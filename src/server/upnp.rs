//! The UPnP lease on the home router that forwards the listen port to this
//! host, renewed the way natwg.py renews it, and the discovery of that router
//! (SSDP) with the one-off mappings `natwg detect` takes for a test.

use crate::config::{Instance, ServerConfig};
use crate::server::error_chain;
use crate::wire::transport::{BoundInterface, bound_udp_socket};
use crate::{Error, Result, netcfg};
use serde::Serialize;
use std::{
    convert::Infallible,
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, SystemTime},
};
use tokio::{net::UdpSocket, sync::watch, time::MissedTickBehavior};

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
// UPnP errors that mean "no such mapping": 714 NoSuchEntryInArray, and the
// 501 that TP-Link routers send with "Entry not found !".
const NO_SUCH_ENTRY: [u16; 2] = [714, 501];
const ONLY_PERMANENT_LEASES: u16 = 725;

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

/// The WAN connection service in a device description fetched from
/// `location`: its control URL, made absolute, and its service type.
pub fn wan_service(description: &str, location: &str) -> Option<(String, &'static str)> {
    let base = element(description, "URLBase")
        .map(str::trim)
        .filter(|base| !base.is_empty())
        .unwrap_or(location);
    let base = url::Url::parse(base).ok()?;
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

/// Ask the LAN of `iface`, whose IPv4 address is `address`, for an Internet
/// Gateway Device, and read the WAN connection service of the first one that
/// has one. SSDP answers are awaited for up to `wait`.
pub async fn discover(
    iface: &BoundInterface,
    address: Ipv4Addr,
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
    let http = http_client(&iface.to_string())?;
    let mut tried = Vec::new();
    let mut last_error = None;
    let deadline = tokio::time::Instant::now() + wait;
    let mut answer = [0; 2048];
    while let Ok(received) = tokio::time::timeout_at(deadline, socket.recv_from(&mut answer)).await
    {
        let (len, _) = received.map_err(failed)?;
        let text = String::from_utf8_lossy(&answer[..len]);
        let Some(location) = ssdp_location(&text).map(str::to_owned) else {
            continue;
        };
        if tried.contains(&location) {
            continue;
        }
        tried.push(location.clone());
        match describe(&http, &location).await {
            Ok(gateway) => return Ok(gateway),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        Error::new(
            "UPNP_NO_GATEWAY",
            format!(
                "no UPnP gateway answered SSDP on {iface} within {} ms",
                wait.as_millis()
            ),
        )
    }))
}

async fn describe(http: &reqwest::Client, location: &str) -> Result<Gateway> {
    let fetch =
        |e: reqwest::Error| Error::new("UPNP_HTTP", format!("{location}: {}", error_chain(&e)));
    let description = http
        .get(location)
        .send()
        .await
        .map_err(fetch)?
        .text()
        .await
        .map_err(fetch)?;
    let (control_url, service) = wan_service(&description, location).ok_or_else(|| {
        Error::new(
            "UPNP_NO_WAN_SERVICE",
            format!("{location} describes no WANIPConnection or WANPPPConnection service"),
        )
    })?;
    Ok(Gateway {
        location: location.to_owned(),
        control_url,
        service: service.to_owned(),
    })
}

fn http_client(iface: &str) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .interface(iface)
        .timeout(TIMEOUT)
        .no_proxy()
        .build()
        .map_err(|e| Error::new("HTTP_UNAVAILABLE", error_chain(&e)))
}

/// SOAP calls to the WAN connection service of a [`Gateway`], sent through
/// one interface.
pub struct Igd {
    http: reqwest::Client,
    gateway: Gateway,
}

impl Igd {
    pub fn new(iface: &str, gateway: Gateway) -> Result<Self> {
        Ok(Self {
            http: http_client(iface)?,
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

    /// The UDP mapping of external `port`, or none when the gateway holds
    /// no such mapping.
    pub async fn mapping(&self, port: u16) -> Result<Option<PortMapping>> {
        let reply = self.call("GetSpecificPortMappingEntry", &key(port)).await?;
        if !reply.contains("GetSpecificPortMappingEntryResponse") {
            return match upnp_error(&reply) {
                Some((code, _)) if NO_SUCH_ENTRY.contains(&code) => Ok(None),
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

    /// Forward UDP `port` to the same port on `client` for `lease_secs`. A
    /// gateway that takes only permanent leases gets one, and returns 0.
    pub async fn add(
        &self,
        port: u16,
        client: Ipv4Addr,
        description: &str,
        lease_secs: u32,
    ) -> Result<u32> {
        let mut lease = lease_secs;
        loop {
            let mut arguments = key(port);
            arguments.extend([
                ("NewInternalPort", port.to_string()),
                ("NewInternalClient", client.to_string()),
                ("NewEnabled", "1".to_owned()),
                ("NewPortMappingDescription", description.to_owned()),
                ("NewLeaseDuration", lease.to_string()),
            ]);
            let reply = self.call("AddPortMapping", &arguments).await?;
            if reply.contains("AddPortMappingResponse") {
                return Ok(lease);
            }
            match upnp_error(&reply) {
                Some((ONLY_PERMANENT_LEASES, _)) if lease != 0 => lease = 0,
                _ => return Err(self.refused("AddPortMapping", &reply)),
            }
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

    async fn call(&self, action: &str, arguments: &[(&str, String)]) -> Result<String> {
        let service = &self.gateway.service;
        let http = |e: reqwest::Error| {
            Error::new(
                "UPNP_HTTP",
                format!("{} {action}: {}", self.gateway.control_url, error_chain(&e)),
            )
        };
        self.http
            .post(&self.gateway.control_url)
            .header(
                reqwest::header::CONTENT_TYPE,
                r#"text/xml; charset="utf-8""#,
            )
            .header("SOAPAction", format!(r#""{service}#{action}""#))
            .body(soap_body(service, action, arguments))
            .send()
            .await
            .map_err(http)?
            .text()
            .await
            .map_err(http)
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
