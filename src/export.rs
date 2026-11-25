//! Export a device's own WireGuard identity and its split routes.
mod hooks;

use crate::client::{Options, resolve, uplink};
use crate::config::{ClientConfig, Config, PeerConfig, PublishMode, Role, ServerConfig};
use crate::{Error, Result, tunnel};
use clap::ValueEnum;
use std::{fmt::Write as _, net::SocketAddrV4, time::SystemTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Natwg,
    WgQuick,
    Surge,
    Clash,
}

/// `origin` is the server when issuing a new device. Use that uplink and
/// resolver for a TXT snapshot taken there, without changing the client JSON.
pub async fn render(
    config: &Config,
    format: Format,
    name: &str,
    origin: Option<&ServerConfig>,
) -> Result<String> {
    if let Role::Server(server) = &config.role {
        if format != Format::WgQuick || server.publish != PublishMode::A {
            return Err(Error::new(
                "EXPORT_ROLE",
                "a server can export wg-quick in public mode (publish a); export a device from its client config or with peer add",
            ));
        }
        return Ok(server_config(config, server));
    }
    if format == Format::Natwg {
        return Ok(format!("{}\n", config.exposed()));
    }
    crate::peer::validate_name(name)?;
    if format == Format::Surge && config.interface.mtu > 1420 {
        return Err(Error::new(
            "SURGE_MTU",
            "Surge accepts an MTU of 576 to 1420; lower interface.mtu before exporting",
        ));
    }
    let (client, peer) = config.client()?;
    let mut text = String::new();
    let (host, port) = match resolve::Lookup::of(client) {
        Some(resolve::Lookup::A(host)) => (host.host.clone(), host.port),
        Some(lookup @ resolve::Lookup::Txt(record)) => {
            let address = snapshot(lookup, client, origin).await?;
            let at = humantime::format_rfc3339_seconds(SystemTime::now());
            writeln!(
                text,
                "# TXT record {record}\n# Snapshot at {at}. Export again when the mapping changes."
            )
            .unwrap();
            (address.ip().to_string(), address.port())
        }
        None => {
            let address = peer
                .endpoint
                .ok_or_else(|| Error::new("EXPORT_ENDPOINT", "the client has no endpoint"))?;
            (address.ip().to_string(), address.port())
        }
    };
    let endpoint = format!("{host}:{port}");
    let keepalive = tunnel::client_keepalive(peer);
    let allowed = prefixes(peer);
    let private = config.private_key.to_base64();
    let public = peer.public_key;
    let address = config.interface.address.ip();
    let mtu = config.interface.mtu;
    // These policy names already select built-in actions in Surge or mihomo.
    let policy = match name.to_ascii_uppercase().as_str() {
        "DIRECT" | "CELLULAR" | "CELLULAR-ONLY" | "HYBRID" | "NO-HYBRID" | "REJECT"
        | "REJECT-DROP" | "REJECT-NO-DROP" | "REJECT-TINYGIF" | "PASS" | "PASS-RULE"
        | "COMPATIBLE" | "GLOBAL" | "DNS" => format!("natwg-{name}"),
        _ => name.to_owned(),
    };
    match format {
        Format::Natwg => unreachable!(),
        Format::WgQuick => {
            text += &wg_interface(config);
            wg_peer(&mut text, peer, Some(&endpoint), Some(keepalive));
        }
        Format::Surge => {
            let psk = peer
                .preshared_key
                .as_ref()
                .map(|k| format!(", preshared-key = {}", k.to_base64()))
                .unwrap_or_default();
            let networks = allowed.join(", ");
            writeln!(text, r#"[Proxy]
{policy} = wireguard, section-name = {policy}

[WireGuard {policy}]
private-key = {private}
self-ip = {address}
mtu = {mtu}
peer = (public-key = {public}{psk}, allowed-ips = "{networks}", endpoint = {endpoint}, keepalive = {keepalive})

[Rule]"#).unwrap();
            for net in allowed {
                writeln!(text, "IP-CIDR,{net},{policy},no-resolve").unwrap();
            }
            text += "FINAL,DIRECT\n";
        }
        Format::Clash => {
            let networks = serde_json::to_string(&allowed).unwrap();
            writeln!(
                text,
                r#"proxies:
  - name: "{policy}"
    type: wireguard
    server: "{host}"
    port: {port}
    ip: {address}
    private-key: "{private}"
    public-key: "{public}""#
            )
            .unwrap();
            if let Some(psk) = &peer.preshared_key {
                writeln!(text, "    pre-shared-key: \"{}\"", psk.to_base64()).unwrap();
            }
            writeln!(
                text,
                "    allowed-ips: {networks}
    mtu: {mtu}
    udp: true
    persistent-keepalive: {keepalive}
rules:"
            )
            .unwrap();
            for net in allowed {
                writeln!(text, "  - IP-CIDR,{net},{policy},no-resolve").unwrap();
            }
            text += "  - MATCH,DIRECT\n";
        }
    }
    Ok(text)
}

async fn snapshot(
    lookup: resolve::Lookup<'_>,
    client: &ClientConfig,
    origin: Option<&ServerConfig>,
) -> Result<SocketAddrV4> {
    let options = Options::default();
    let iface = origin.map(|s| s.iface.as_str()).or(client.iface.as_deref());
    let link = uplink::find(iface)?;
    let mut resolvers = resolve::resolvers(client, options.dns_port);
    if let Some(stun) = origin.and_then(|s| s.stun.as_ref()) {
        let server_dns = SocketAddrV4::new(stun.dns_server, options.dns_port);
        resolvers.retain(|ip| *ip != server_dns);
        resolvers.insert(0, server_dns);
    }
    let (endpoint, _) = lookup
        .endpoint(&link.iface, &resolvers, options.dns_timeout)
        .await?;
    Ok(endpoint)
}

fn prefixes(peer: &PeerConfig) -> Vec<String> {
    peer.allowed_ips
        .iter()
        .map(|net| format!("{}/{}", net.network(), net.prefix()))
        .collect()
}

fn wg_interface(config: &Config) -> String {
    format!(
        "[Interface]\nAddress = {}\nMTU = {}\nPrivateKey = {}\n",
        config.interface.address,
        config.interface.mtu,
        config.private_key.to_base64()
    )
}

fn wg_peer(text: &mut String, peer: &PeerConfig, endpoint: Option<&str>, keepalive: Option<u16>) {
    writeln!(text, "\n[Peer]\nPublicKey = {}", peer.public_key).unwrap();
    if let Some(psk) = &peer.preshared_key {
        writeln!(text, "PresharedKey = {}", psk.to_base64()).unwrap();
    }
    if !peer.allowed_ips.is_empty() {
        writeln!(text, "AllowedIPs = {}", prefixes(peer).join(", ")).unwrap();
    }
    if let Some(endpoint) = endpoint {
        writeln!(text, "Endpoint = {endpoint}").unwrap();
    }
    if let Some(keepalive) = keepalive {
        writeln!(text, "PersistentKeepalive = {keepalive}").unwrap();
    }
}

fn server_config(config: &Config, server: &ServerConfig) -> String {
    let mut text = wg_interface(config);
    writeln!(text, "ListenPort = {}", server.listen_port).unwrap();
    text += &hooks::firewall(server, config.interface.subnet());
    for peer in &config.peers {
        wg_peer(
            &mut text,
            peer,
            peer.endpoint.map(|ep| ep.to_string()).as_deref(),
            peer.keepalive,
        );
    }
    if let Some(doctor) = &server.doctor {
        writeln!(
            text,
            "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32",
            doctor.private_key.public_key(),
            doctor.address
        )
        .unwrap();
    }
    text
}
