//! The UPnP lease on the home router that forwards the listen port to this
//! host, renewed the way natwg.py renews it.

use crate::config::{Instance, ServerConfig};
use crate::server::error_chain;
use crate::{Error, Result};
use std::{
    convert::Infallible,
    ffi::CStr,
    net::Ipv4Addr,
    time::{Duration, SystemTime},
};
use tokio::{sync::watch, time::MissedTickBehavior};

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

/// The first IPv4 address of the interface named `iface`.
fn ipv4_address(iface: &str) -> Option<Ipv4Addr> {
    let mut list = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut entry = list;
    while let Some(current) = unsafe { entry.as_ref() } {
        entry = current.ifa_next;
        let address = current.ifa_addr;
        if address.is_null() || i32::from(unsafe { (*address).sa_family }) != libc::AF_INET {
            continue;
        }
        if unsafe { CStr::from_ptr(current.ifa_name) }.to_bytes() != iface.as_bytes() {
            continue;
        }
        let address = unsafe { &*address.cast::<libc::sockaddr_in>() };
        found = Some(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)));
        break;
    }
    unsafe { libc::freeifaddrs(list) };
    found
}
