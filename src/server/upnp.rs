//! The UPnP lease on the home router that forwards the listen port to this
//! host, renewed the way natwg.py renews it, and the discovery of that router
//! (SSDP) with the one-off mappings `natwg detect` takes for a test.

use crate::config::{Instance, ServerConfig};
use crate::server::error_chain;
use crate::wire::transport::{BoundInterface, bound_tcp_connect, bound_udp_socket};
use crate::{Error, Result, netcfg};
use ipnetwork::Ipv4Network;
use serde::Serialize;
use std::{
    convert::Infallible,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, SystemTime},
};
use tokio::{
    net::UdpSocket,
    sync::watch,
    time::{Instant, MissedTickBehavior},
};
use url::Url;

const SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
const TIMEOUT: Duration = Duration::from_secs(6);

/// The outcome of the last renewal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub ok: bool,
    pub at: SystemTime,
}

/// The SOAP body that asks the router to forward UDP `port` to the same port
/// on `client` for `lease_secs`.
pub fn add_port_mapping(
    port: u16,
    client: Ipv4Addr,
    description: &Instance,
    lease_secs: u32,
) -> String {
    format!(
        concat!(
            r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" "#,
            r#"s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>"#,
            r#"<u:AddPortMapping xmlns:u="{service}">"#,
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort>",
            "<NewProtocol>UDP</NewProtocol><NewInternalPort>{port}</NewInternalPort>",
            "<NewInternalClient>{client}</NewInternalClient><NewEnabled>1</NewEnabled>",
            "<NewPortMappingDescription>{description}</NewPortMappingDescription>",
            "<NewLeaseDuration>{lease_secs}</NewLeaseDuration>",
            "</u:AddPortMapping></s:Body></s:Envelope>",
        ),
        service = SERVICE,
        port = port,
        client = client,
        description = description,
        lease_secs = lease_secs,
    )
}

pub struct Upnp {
    http: reqwest::Client,
    control_url: String,
    iface: String,
    port: u16,
    lease_secs: u32,
    description: Instance,
    refresh: Duration,
}

impl Upnp {
    /// The lease of `server`, or none when its config has no UPnP section.
    /// Requests leave through the server's interface, past any VPN app.
    pub fn new(server: &ServerConfig) -> Result<Option<Self>> {
        let Some(config) = &server.upnp else {
            return Ok(None);
        };
        let http = reqwest::Client::builder()
            .interface(&server.iface)
            .timeout(TIMEOUT)
            .no_proxy()
            .build()
            .map_err(|e| Error::new("HTTP_UNAVAILABLE", error_chain(&e)))?;
        Ok(Some(Self {
            http,
            control_url: config.control_url.clone(),
            iface: server.iface.clone(),
            port: server.listen_port,
            lease_secs: config.lease_secs,
            description: server.instance.clone(),
            refresh: Duration::from_secs(config.refresh_secs.get()),
        }))
    }

    /// Renew the lease now and every `refresh_secs`. Only a change between
    /// success and failure is logged.
    pub async fn run(self, state: watch::Sender<Option<Lease>>) -> Infallible {
        let mut tick = tokio::time::interval(self.refresh);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let renewed = self.renew().await;
            let lease = Lease {
                ok: renewed.is_ok(),
                at: SystemTime::now(),
            };
            let before = state.send_replace(Some(lease));
            if before.map(|before| before.ok) == Some(lease.ok) {
                continue;
            }
            let port = self.port;
            match renewed {
                Ok(client) => tracing::info!("UPnP udp/{port} -> {client}:{port} ok"),
                Err(error) => tracing::warn!("UPnP mapping of udp/{port} failed: {error}"),
            }
        }
    }

    async fn renew(&self) -> Result<Ipv4Addr> {
        let client = ipv4_address(&self.iface).ok_or_else(|| {
            Error::new(
                "UPNP_NO_ADDRESS",
                format!("{} has no IPv4 address", self.iface),
            )
        })?;
        let body = add_port_mapping(self.port, client, &self.description, self.lease_secs);
        let http = |e: reqwest::Error| Error::new("UPNP_HTTP", error_chain(&e));
        let response = self
            .http
            .post(&self.control_url)
            .header(
                reqwest::header::CONTENT_TYPE,
                r#"text/xml; charset="utf-8""#,
            )
            .header("SOAPAction", format!(r#""{SERVICE}#AddPortMapping""#))
            .body(body)
            .send()
            .await
            .map_err(http)?;
        let status = response.status();
        let text = response.text().await.map_err(http)?;
        if !text.contains("AddPortMappingResponse") {
            let reply: String = text.trim().chars().take(200).collect();
            return Err(Error::new(
                "UPNP_REFUSED",
                format!("HTTP {status}: {reply}"),
            ));
        }
        Ok(client)
    }
}

fn ipv4_address(iface: &str) -> Option<Ipv4Addr> {
    let addresses = netcfg::ipv4_addresses().ok()?;
    addresses
        .into_iter()
        .find_map(|(name, address)| (name == iface).then_some(address))
}

const SSDP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
const SEARCH_TARGETS: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
];
/// The WAN connection services that lease ports, the preferred one first.
const WAN_SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    SERVICE,
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];
/// The standard UPnP error for "no such mapping".
const NO_SUCH_ENTRY: u16 = 714;
/// The generic "Action Failed", which TP-Link routers send with "Entry not
/// found !" for a missing mapping. It means that only with such words.
const ACTION_FAILED: u16 = 501;
const ONLY_PERMANENT_LEASES: u16 = 725;
/// The most a device description or a SOAP reply may hold.
pub const BODY_LIMIT: usize = 64 * 1024;
/// How many device descriptions discovery reads at most.
const LOCATIONS: usize = 3;
/// How long discovery may read device descriptions after the SSDP wait.
const DESCRIBE_TIME: Duration = Duration::from_secs(3);

/// An Internet Gateway Device that answered SSDP, and its WAN connection
/// service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Gateway {
    /// The device description the gateway announced.
    pub location: String,
    /// Where the WAN connection service takes SOAP requests: what
    /// `role.server.upnp.control_url` takes.
    pub control_url: String,
    /// The service type of the WAN connection service.
    pub service: String,
}

/// A port mapping the gateway holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PortMapping {
    pub client: Ipv4Addr,
    pub internal_port: u16,
    pub description: String,
    pub lease_secs: u32,
}

/// The LAN of the uplink, which SSDP answers must come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lan {
    /// The uplink's address and prefix.
    pub network: Ipv4Network,
    /// The uplink's default gateway, whose answer discovery prefers.
    pub gateway: Option<Ipv4Addr>,
}

impl Lan {
    /// The LAN of `iface`, whose address is `address`: its prefix, else
    /// the /24 around it, and its default gateway.
    pub fn of(iface: &BoundInterface, address: Ipv4Addr) -> Self {
        let name = iface.to_string();
        let network = netcfg::ipv4_networks()
            .ok()
            .and_then(|networks| {
                networks
                    .into_iter()
                    .find(|(holder, network)| *holder == name && network.ip() == address)
            })
            .map(|(_, network)| network)
            .unwrap_or_else(|| Ipv4Network::new(address, 24).expect("24 is a valid prefix"));
        Self {
            network,
            gateway: netcfg::default_gateway(&name),
        }
    }
}

/// The M-SEARCH request that asks every gateway of the LAN for `target`.
pub fn search_request(target: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {target}\r\n\r\n"
    )
}

/// The LOCATION of an SSDP answer, the URL of the device description.
pub fn ssdp_location(answer: &str) -> Option<&str> {
    let mut lines = answer.lines();
    let status = lines.next()?;
    if !status.starts_with("HTTP/1.") || status.split_whitespace().nth(1) != Some("200") {
        return None;
    }
    lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("location")
            .then(|| value.trim())
            .filter(|value| !value.is_empty())
    })
}

/// The LOCATION of an SSDP answer from `source`, when natwg may follow it:
/// an http URL on `source` itself, a host on the LAN other than this one.
/// Anyone on the LAN can answer SSDP, and a LOCATION elsewhere would send
/// the port mapping requests, and this host's trust, there.
pub fn trusted_location(
    answer: &str,
    source: Ipv4Addr,
    lan: &Lan,
) -> std::result::Result<Url, String> {
    let location = ssdp_location(answer).ok_or("no LOCATION")?;
    let url = Url::parse(location).map_err(|e| format!("LOCATION {location:?}: {e}"))?;
    if url.scheme() != "http" {
        return Err(format!("LOCATION {location} is not http"));
    }
    if url_ip(&url) != Some(source) {
        return Err(format!(
            "LOCATION {location} is not on {source}, which answered"
        ));
    }
    if !lan.network.contains(source) || source == lan.network.ip() {
        return Err(format!("{source} is not another host on {}", lan.network));
    }
    Ok(url)
}

/// Whether a control URL is an http URL on the host of the description
/// that named it, as it must be: a description may not send the port
/// mapping requests elsewhere.
pub fn same_host(control_url: &str, location: &Url) -> bool {
    Url::parse(control_url).is_ok_and(|control| {
        control.scheme() == "http"
            && url_ip(&control).is_some()
            && url_ip(&control) == url_ip(location)
    })
}

fn url_ip(url: &Url) -> Option<Ipv4Addr> {
    match url.host()? {
        url::Host::Ipv4(ip) => Some(ip),
        _ => None,
    }
}

/// The WAN connection service in a device description fetched from
/// `location`: its control URL, made absolute, and its service type.
pub fn wan_service(description: &str, location: &str) -> Option<(String, &'static str)> {
    let base = element(description, "URLBase")
        .map(str::trim)
        .filter(|base| !base.is_empty())
        .unwrap_or(location);
    let base = Url::parse(base).ok()?;
    let services: Vec<(&str, &str)> = description
        .split("<service>")
        .skip(1)
        .filter_map(|block| {
            let block = &block[..block.find("</service>")?];
            Some((
                element(block, "serviceType")?.trim(),
                element(block, "controlURL")?.trim(),
            ))
        })
        .collect();
    WAN_SERVICES.iter().find_map(|&wanted| {
        let (_, control) = services.iter().find(|(kind, _)| *kind == wanted)?;
        Some((base.join(control).ok()?.to_string(), wanted))
    })
}

/// The text of the first `<name>` element in `xml`, as UPnP devices write
/// it: without a namespace prefix and without attributes.
pub fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let len = xml[start..].find(&format!("</{name}>"))?;
    Some(&xml[start..start + len])
}

/// The SOAP envelope that calls `action` of `service` with `arguments`.
pub fn soap_body(service: &str, action: &str, arguments: &[(&str, String)]) -> String {
    let arguments: String = arguments
        .iter()
        .map(|(name, value)| format!("<{name}>{value}</{name}>"))
        .collect();
    format!(
        concat!(
            r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" "#,
            r#"s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>"#,
            r#"<u:{action} xmlns:u="{service}">{arguments}</u:{action}></s:Body></s:Envelope>"#,
        ),
        action = action,
        service = service,
        arguments = arguments,
    )
}

/// The UPnP error code and description in a SOAP fault.
pub fn upnp_error(reply: &str) -> Option<(u16, String)> {
    let code = element(reply, "errorCode")?.trim().parse().ok()?;
    let description = element(reply, "errorDescription").unwrap_or_default();
    Some((code, description.trim().to_owned()))
}

/// Whether a fault answers GetSpecificPortMappingEntry with "no such
/// mapping": 714, or the generic 501 when its description says so.
pub fn no_such_entry(code: u16, description: &str) -> bool {
    let description = description.to_ascii_lowercase();
    code == NO_SUCH_ENTRY
        || (code == ACTION_FAILED
            && (description.contains("not found") || description.contains("no such")))
}

/// Ask the LAN of `iface`, whose IPv4 address is `address`, for an Internet
/// Gateway Device, and read the WAN connection service of one that has one.
///
/// Only answers from a host on the uplink's subnet that point at a device
/// description on that host count, and the control URL must be on it too.
/// SSDP answers are awaited for up to `wait`, or until the default gateway
/// answers; then natwg reads the descriptions, the default gateway's first,
/// at most three, for up to three more seconds.
pub async fn discover(
    iface: &BoundInterface,
    address: Ipv4Addr,
    wait: Duration,
) -> Result<Gateway> {
    discover_on(iface, address, Lan::of(iface, address), wait).await
}

/// [`discover`] on a known LAN.
pub async fn discover_on(
    iface: &BoundInterface,
    address: Ipv4Addr,
    lan: Lan,
    wait: Duration,
) -> Result<Gateway> {
    let failed = |e: std::io::Error| Error::new("UPNP_SSDP", format!("SSDP on {iface}: {e}"));
    let socket = bound_udp_socket(iface, 0).map_err(failed)?;
    socket2::SockRef::from(&socket)
        .set_multicast_if_v4(&address)
        .map_err(failed)?;
    let socket = UdpSocket::from_std(socket).map_err(failed)?;
    for target in SEARCH_TARGETS {
        socket
            .send_to(search_request(target).as_bytes(), SSDP)
            .await
            .map_err(failed)?;
    }
    let started = Instant::now();
    let mut found: Vec<(Ipv4Addr, Url)> = Vec::new();
    let mut ignored = Vec::new();
    let mut answer = [0; 2048];
    while let Ok(received) =
        tokio::time::timeout_at(started + wait, socket.recv_from(&mut answer)).await
    {
        let (len, source) = received.map_err(failed)?;
        let SocketAddr::V4(source) = source else {
            continue;
        };
        let source = *source.ip();
        match trusted_location(&String::from_utf8_lossy(&answer[..len]), source, &lan) {
            Ok(url) if found.iter().all(|(_, known)| *known != url) => found.push((source, url)),
            Ok(_) => {}
            Err(reason) => ignored.push(format!("ignored an SSDP answer from {source}: {reason}")),
        }
        if lan
            .gateway
            .is_some_and(|gateway| found.iter().any(|(from, _)| *from == gateway))
        {
            break;
        }
    }
    // The default gateway first; the sort is stable, so the rest keep their order.
    found.sort_by_key(|(source, _)| Some(*source) != lan.gateway);
    let http = http_client(iface)?;
    let deadline = Instant::now() + DESCRIBE_TIME;
    let mut last_error = None;
    for (_, location) in found.into_iter().take(LOCATIONS) {
        let described = tokio::time::timeout_at(deadline, describe(&http, &location)).await;
        match described {
            Ok(Ok(gateway)) => return Ok(gateway),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(Error::new(
                    "UPNP_TIMEOUT",
                    format!("{location} did not describe a gateway in time"),
                ));
                break;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        let mut message = format!(
            "no UPnP gateway on {} answered SSDP on {iface} within {} ms",
            lan.network,
            wait.as_millis()
        );
        for reason in ignored {
            message.push_str("; ");
            message.push_str(&reason);
        }
        Error::new("UPNP_NO_GATEWAY", message)
    }))
}

async fn describe(http: &reqwest::Client, location: &Url) -> Result<Gateway> {
    let fetch =
        |e: reqwest::Error| Error::new("UPNP_HTTP", format!("{location}: {}", error_chain(&e)));
    let response = http.get(location.clone()).send().await.map_err(fetch)?;
    let description = read_capped(response, location.as_str()).await?;
    let (control_url, service) = wan_service(&description, location.as_str()).ok_or_else(|| {
        Error::new(
            "UPNP_NO_WAN_SERVICE",
            format!("{location} describes no WANIPConnection or WANPPPConnection service"),
        )
    })?;
    if !same_host(&control_url, location) {
        return Err(Error::new(
            "UPNP_UNTRUSTED",
            format!("{location} names a control URL on another host: {control_url}"),
        ));
    }
    Ok(Gateway {
        location: location.to_string(),
        control_url,
        service: service.to_owned(),
    })
}

/// The body of `response`, refused when it holds more than [`BODY_LIMIT`].
async fn read_capped(mut response: reqwest::Response, what: &str) -> Result<String> {
    let too_long = || {
        Error::new(
            "UPNP_TOO_LONG",
            format!("{what} sent more than {BODY_LIMIT} bytes"),
        )
    };
    if response
        .content_length()
        .is_some_and(|len| len > BODY_LIMIT as u64)
    {
        return Err(too_long());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::new("UPNP_HTTP", format!("{what}: {}", error_chain(&e))))?
    {
        if body.len() + chunk.len() > BODY_LIMIT {
            return Err(too_long());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn http_client(iface: &BoundInterface) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .interface(&iface.to_string())
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|e| Error::new("HTTP_UNAVAILABLE", error_chain(&e)))
}

/// SOAP calls to the WAN connection service of a [`Gateway`], sent through
/// one interface.
pub struct Igd {
    http: reqwest::Client,
    iface: BoundInterface,
    gateway: Gateway,
}

impl Igd {
    pub fn new(iface: &BoundInterface, gateway: Gateway) -> Result<Self> {
        Ok(Self {
            http: http_client(iface)?,
            iface: iface.clone(),
            gateway,
        })
    }

    pub fn gateway(&self) -> &Gateway {
        &self.gateway
    }

    /// The address the gateway holds on its WAN side.
    pub async fn external_ip(&self) -> Result<Ipv4Addr> {
        let reply = self.call("GetExternalIPAddress", &[]).await?;
        element(&reply, "NewExternalIPAddress")
            .and_then(|ip| ip.trim().parse().ok())
            .ok_or_else(|| self.refused("GetExternalIPAddress", &reply))
    }

    /// The UDP mapping of external `port`, or none when the gateway says it
    /// holds no such mapping. Any other fault is an error.
    pub async fn mapping(&self, port: u16) -> Result<Option<PortMapping>> {
        let reply = self.call("GetSpecificPortMappingEntry", &key(port)).await?;
        if !reply.contains("GetSpecificPortMappingEntryResponse") {
            return match upnp_error(&reply) {
                Some((code, description)) if no_such_entry(code, &description) => Ok(None),
                _ => Err(self.refused("GetSpecificPortMappingEntry", &reply)),
            };
        }
        let field = |name| element(&reply, name).map(str::trim);
        let parsed = (|| {
            Some(PortMapping {
                client: field("NewInternalClient")?.parse().ok()?,
                internal_port: field("NewInternalPort")?.parse().ok()?,
                description: field("NewPortMappingDescription")
                    .unwrap_or_default()
                    .to_owned(),
                lease_secs: field("NewLeaseDuration")?.parse().unwrap_or(0),
            })
        })();
        parsed
            .map(Some)
            .ok_or_else(|| self.refused("GetSpecificPortMappingEntry", &reply))
    }

    /// Forward UDP `port` to the same port on `client` for `lease_secs`.
    /// A gateway that takes only permanent leases refuses with the error
    /// code `UPNP_PERMANENT_ONLY`, and natwg never falls back to one.
    pub async fn add(
        &self,
        port: u16,
        client: Ipv4Addr,
        description: &str,
        lease_secs: u32,
    ) -> Result<()> {
        let mut arguments = key(port);
        arguments.extend([
            ("NewInternalPort", port.to_string()),
            ("NewInternalClient", client.to_string()),
            ("NewEnabled", "1".to_owned()),
            ("NewPortMappingDescription", description.to_owned()),
            ("NewLeaseDuration", lease_secs.to_string()),
        ]);
        let reply = self.call("AddPortMapping", &arguments).await?;
        if reply.contains("AddPortMappingResponse") {
            return Ok(());
        }
        match upnp_error(&reply) {
            Some((ONLY_PERMANENT_LEASES, _)) => Err(Error::new(
                "UPNP_PERMANENT_ONLY",
                format!("{} takes only permanent leases", self.gateway.control_url),
            )),
            _ => Err(self.refused("AddPortMapping", &reply)),
        }
    }

    /// Remove the UDP mapping of external `port`.
    pub async fn delete(&self, port: u16) -> Result<()> {
        let reply = self.call("DeletePortMapping", &key(port)).await?;
        if reply.contains("DeletePortMappingResponse") {
            return Ok(());
        }
        Err(self.refused("DeletePortMapping", &reply))
    }

    /// [`Igd::delete`] without a runtime, each step limited to `timeout`:
    /// the cleanup of a lease while a panic unwinds.
    pub fn delete_blocking(&self, port: u16, timeout: Duration) -> Result<()> {
        let failed = |reason: String| {
            Error::new(
                "UPNP_HTTP",
                format!("{} DeletePortMapping: {reason}", self.gateway.control_url),
            )
        };
        let url = Url::parse(&self.gateway.control_url).map_err(|e| failed(e.to_string()))?;
        let ip = url_ip(&url).ok_or_else(|| failed("the host is no IPv4 address".to_owned()))?;
        let address = SocketAddrV4::new(ip, url.port_or_known_default().unwrap_or(80));
        let service = &self.gateway.service;
        let body = soap_body(service, "DeletePortMapping", &key(port));
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{service}#DeletePortMapping\"\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            path = url.path(),
            len = body.len(),
        );
        let mut stream =
            bound_tcp_connect(&self.iface, address, timeout).map_err(|e| failed(e.to_string()))?;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| failed(e.to_string()))?;
        let mut reply = Vec::new();
        let _ = stream.take(BODY_LIMIT as u64).read_to_end(&mut reply);
        let reply = String::from_utf8_lossy(&reply);
        if reply.contains("DeletePortMappingResponse") {
            return Ok(());
        }
        Err(self.refused("DeletePortMapping", &reply))
    }

    async fn call(&self, action: &str, arguments: &[(&str, String)]) -> Result<String> {
        let service = &self.gateway.service;
        let what = format!("{} {action}", self.gateway.control_url);
        let response = self
            .http
            .post(&self.gateway.control_url)
            .header(
                reqwest::header::CONTENT_TYPE,
                r#"text/xml; charset="utf-8""#,
            )
            .header("SOAPAction", format!(r#""{service}#{action}""#))
            .body(soap_body(service, action, arguments))
            .send()
            .await
            .map_err(|e| Error::new("UPNP_HTTP", format!("{what}: {}", error_chain(&e))))?;
        read_capped(response, &what).await
    }

    fn refused(&self, action: &str, reply: &str) -> Error {
        let reason = match upnp_error(reply) {
            Some((code, description)) => format!("UPnP error {code} {description}"),
            None => reply.trim().chars().take(200).collect(),
        };
        Error::new(
            "UPNP_REFUSED",
            format!("{} {action}: {reason}", self.gateway.control_url),
        )
    }
}

fn key(port: u16) -> Vec<(&'static str, String)> {
    vec![
        ("NewRemoteHost", String::new()),
        ("NewExternalPort", port.to_string()),
        ("NewProtocol", "UDP".to_owned()),
    ]
}
