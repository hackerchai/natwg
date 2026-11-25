//! First-time setup. Use the same network evidence, enrollment and exporters
//! as the standalone commands. A probe on a spare port cannot authorize the
//! configured port, even when both ports happen to preserve their number.
mod files;
mod prompt;

use super::{ExportOutput, Stop, runtime};
use clap::ValueEnum;
use ipnetwork::Ipv4Network;
use natwg::client::uplink;
use natwg::config::{
    self, CloudflareConfig, Config, Interface, PublishMode, Role, ServerConfig, StunConfig,
    UpnpConfig, Version1,
};
use natwg::detect::{self, Detection, PublicBy, UpnpMode, UpnpState, Verdict};
use natwg::export::{self, Format};
use natwg::keys::{Key, Secret};
use natwg::{Error, Result, netcfg, peer, service, wire::stun};
use prompt::Prompt;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    Natwg,
    Wireguard,
}

#[derive(clap::Args)]
pub(super) struct Args {
    /// Server implementation (default: natwg). Wireguard needs confirmed public reachability.
    #[arg(long, value_enum)]
    mode: Option<Mode>,
    /// Uplink to test (default: the physical default route).
    #[arg(long)]
    iface: Option<String>,
    /// UDP listen port to test and configure (default: 51830).
    #[arg(long)]
    port: Option<NonZeroU16>,
    /// Server tunnel address with prefix (default: 10.66.66.1/24).
    #[arg(long)]
    subnet: Option<Ipv4Network>,
    /// LAN to route, repeatable (default: the uplink subnet if it excludes the public endpoint).
    #[arg(long)]
    lan: Vec<Ipv4Network>,
    /// Host the tunnel alone, without a LAN route.
    #[arg(long, conflicts_with = "lan")]
    no_lan: bool,
    /// Cloudflare zone name.
    #[arg(long)]
    zone: Option<String>,
    /// Full DNS name to publish in this zone.
    #[arg(long)]
    record: Option<String>,
    /// Owner-only file containing the Cloudflare API token on one line.
    #[arg(long, value_name = "PATH")]
    token_file: Option<PathBuf>,
    /// Try the UPnP gateway on a private uplink (default: auto).
    #[arg(long, value_enum)]
    upnp: Option<super::UpnpArg>,
    /// STUN server to use for detection and keepalive; repeat to replace the built-in list.
    #[arg(long = "server", value_name = "HOST:PORT", value_parser = parse_server)]
    servers: Vec<(String, u16)>,
    /// Resolver for STUN and for the first peer's DNS lookups.
    #[arg(long)]
    dns: Option<Ipv4Addr>,
    /// Enroll the first peer and export its private profile.
    #[arg(long, value_name = "NAME")]
    peer: Option<String>,
    /// First peer's output format (default: natwg, or wg-quick in wireguard mode).
    #[arg(long, value_enum)]
    format: Option<Format>,
    /// Write the first peer here with mode 0600 (default: stdout).
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
    /// Directory for native wg-quick profiles (default: platform WireGuard directory).
    #[arg(long, value_name = "DIR")]
    wg_dir: Option<PathBuf>,
    /// Install and start the natwg service after saving the server.
    #[arg(long)]
    install_service: bool,
    /// Accept defaults without prompting. Service installation requires --install-service.
    #[arg(long)]
    yes: bool,
    /// Replace existing configs and profiles with newly generated keys.
    #[arg(long)]
    force: bool,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new("INIT_INPUT", message)
}

// Render a path as a single shell argument in the commands printed to the operator.
fn shell_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        return s.into_owned();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn parse_server(text: &str) -> std::result::Result<(String, u16), String> {
    let (host, port) = stun::host_port(text)?;
    if host.is_empty()
        || port == 0
        || !(config::is_dns_name(&host) || host.parse::<Ipv4Addr>().is_ok())
    {
        return Err("expected a STUN host or IPv4 address with a nonzero port".into());
    }
    Ok((host, port))
}

fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
}

impl Args {
    fn request(&mut self, prompt: &Prompt) -> Result<detect::Request> {
        let mut iface = self.iface.take();
        if iface.is_none() && prompt.interactive {
            let default = uplink::find(None)
                .map(|u| u.iface.to_string())
                .unwrap_or_default();
            let answer = prompt.ask("Uplink interface", &default)?;
            if answer.is_empty() {
                return Err(invalid("missing --iface (uplink interface)"));
            }
            iface = Some(answer);
        }
        let port = match self.port {
            Some(port) => port,
            None => prompt
                .ask("UDP listen port", &detect::DEFAULT_PORT.to_string())?
                .parse()
                .map_err(|_| invalid("--port must be 1 to 65535"))?,
        };
        let mut servers = std::mem::take(&mut self.servers);
        if servers.is_empty() && prompt.interactive {
            let answer = prompt.ask("STUN servers (space-separated host:port)", "built-in")?;
            if answer != "built-in" {
                servers = words(&answer)
                    .map(parse_server)
                    .collect::<std::result::Result<_, _>>()
                    .map_err(invalid)?;
                if servers.is_empty() {
                    return Err(invalid("enter at least one --server"));
                }
            }
        }
        Ok(detect::Request {
            iface,
            port: Some(port.get()),
            servers,
            upnp: if matches!(self.upnp, Some(super::UpnpArg::Off)) {
                UpnpMode::Off
            } else {
                UpnpMode::Auto
            },
            dns: self.dns.unwrap_or(detect::DEFAULT_DNS),
            ..Default::default()
        })
    }

    fn lans(&mut self, found: &Detection, prompt: &Prompt) -> Result<Vec<Ipv4Network>> {
        let mut lans = std::mem::take(&mut self.lan);
        if !self.no_lan && lans.is_empty() {
            let default = netcfg::ipv4_networks()
                .map_err(|e| invalid(e.to_string()))?
                .into_iter()
                .find(|(name, net)| *name == found.uplink.iface && net.ip() == found.uplink.address)
                .ok_or_else(|| invalid("uplink address changed; run init again"))?
                .1;
            let public = found.mapping.endpoint.map(|endpoint| *endpoint.ip());
            let default = if public.is_some_and(|ip| default.contains(ip)) {
                warn!(
                    "The uplink subnet contains the public WireGuard endpoint. Use --lan for a separate LAN; the default routes only the tunnel."
                );
                "none".to_owned()
            } else {
                format!("{}/{}", default.network(), default.prefix())
            };
            let answer = prompt.ask("LANs (space-separated CIDRs, or none)", &default)?;
            if answer != "none" {
                lans = words(&answer)
                    .map(str::parse)
                    .collect::<std::result::Result<_, _>>()
                    .map_err(|_| invalid("expected IPv4 CIDRs for --lan"))?;
            }
        }
        Ok(lans
            .into_iter()
            .map(|lan| Ipv4Network::new(lan.network(), lan.prefix()).unwrap())
            .collect())
    }

    fn cloudflare(&mut self, prompt: &Prompt) -> Result<CloudflareConfig> {
        let zone = prompt
            .required(self.zone.take(), "Cloudflare zone", "--zone")?
            .to_ascii_lowercase();
        config::host_name(&zone).map_err(|e| invalid(format!("--zone: {e}")))?;
        let record = prompt
            .required(self.record.take(), "Full DNS record name", "--record")?
            .to_ascii_lowercase();
        if !config::is_dns_name(&record)
            || !(record == zone || record.ends_with(&format!(".{zone}")))
        {
            return Err(invalid(format!(
                "--record must name a DNS record in {zone}"
            )));
        }
        let token = match &self.token_file {
            Some(path) => {
                let caller = std::env::var("SUDO_UID")
                    .ok()
                    .and_then(|uid| uid.parse().ok());
                config::read_private(path, caller)?
            }
            None => prompt.token()?,
        };
        let token = token.trim_end_matches(['\r', '\n']);
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid(
                "the Cloudflare API token must be a single nonempty value",
            ));
        }
        Ok(CloudflareConfig {
            zone,
            record,
            token: token.parse::<Secret>().map_err(invalid)?,
        })
    }
}

fn accept_probe(found: Detection) -> Result<Detection> {
    warn!("{}", found.render().trim_end());
    if found.port.held || found.port.wanted != found.port.tested {
        return Err(Error::new(
            "INIT_PORT_IN_USE",
            format!(
                "udp/{} is in use; stop its listener or choose another --port and run init again",
                found.port.wanted
            ),
        ));
    }
    match found.verdict {
        Verdict::Inconclusive | Verdict::Unsupported => Err(Error::new(
            "INIT_NETWORK",
            format!("setup stopped: {}", found.summary),
        )),
        Verdict::Likely | Verdict::Supported => Ok(found),
    }
}

fn detect_network(
    request: &mut detect::Request,
    prompt: &Prompt,
    choose_gateway: bool,
) -> Result<Detection> {
    // Tokio keeps its signal handlers after a receiver drops. While a
    // probe owns a temporary router lease it must finish cleanup on a
    // signal. At the prompts and during delivery, restore normal Ctrl-C.
    let rt = runtime(tokio::runtime::Builder::new_current_thread())?;
    let mut stop = {
        let _enter = rt.enter();
        Stop::listen()?
    };
    let terminate = Arc::new(AtomicBool::new(true));
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        signal_hook::flag::register_conditional_default(sig, Arc::clone(&terminate))
            .map_err(|e| Error::new("SIGNAL_UNAVAILABLE", e.to_string()))?;
    }
    let mut probe = |request: &detect::Request| {
        terminate.store(false, Ordering::SeqCst);
        let result = rt.block_on(detect::run_until(request, async {
            stop.requested().await;
            "a termination signal".into()
        }));
        terminate.store(true, Ordering::SeqCst);
        let found = result.map_err(|e| {
            if e.code == "UPLINK_NOT_FOUND" && request.iface.is_none() {
                invalid("could not select an uplink; specify --iface")
            } else {
                e
            }
        })?;
        accept_probe(found)
    };
    let found = probe(request)?;
    if choose_gateway
        && let Some(url) = gateway(&found)
        && !prompt.confirm(&format!("Use the discovered UPnP gateway {url}?"), true)?
    {
        request.upnp = UpnpMode::Off;
        return probe(request);
    }
    Ok(found)
}

fn gateway(found: &Detection) -> Option<&str> {
    if matches!(
        found.upnp.state,
        UpnpState::Leased | UpnpState::Existing | UpnpState::LeaseLeft
    ) {
        found.upnp.gateway.as_ref().map(|g| g.control_url.as_str())
    } else {
        None
    }
}

fn publish(verdict: Verdict, public_by: Option<PublicBy>) -> PublishMode {
    if verdict == Verdict::Supported
        && matches!(public_by, Some(PublicBy::Address | PublicBy::Upnp))
    {
        PublishMode::A
    } else {
        PublishMode::Txt
    }
}

fn stun_config(request: &detect::Request) -> StunConfig {
    let mut servers = Vec::new();
    let mut fallback = Vec::new();
    for (host, port) in &request.servers {
        match host.parse::<Ipv4Addr>() {
            Ok(ip) => fallback.push(SocketAddrV4::new(ip, *port)),
            Err(_) => servers.push(format!("{host}:{port}")),
        }
    }
    // The daemon uses its built-in targets when both lists are empty.
    StunConfig {
        servers,
        fallback,
        interval_secs: 25.try_into().unwrap(),
        dns_server: request.dns,
    }
}

impl Args {
    fn server(
        &mut self,
        request: &detect::Request,
        found: &Detection,
        publish: PublishMode,
        prompt: &Prompt,
    ) -> Result<Config> {
        let address: Ipv4Network = match self.subnet {
            Some(address) => address,
            None => prompt
                .ask("Server tunnel address/prefix", "10.66.66.1/24")?
                .parse()
                .map_err(|_| invalid("--subnet needs an IPv4 address/prefix"))?,
        };
        if address.prefix() > 30
            || address.ip() == address.network()
            || address.ip() == address.broadcast()
        {
            return Err(invalid(
                "--subnet needs a usable server address and room for the doctor peer",
            ));
        }
        let lan = self.lans(found, prompt)?;
        if let Some(endpoint) = found.mapping.endpoint
            && let Some(net) = std::iter::once(&address)
                .chain(&lan)
                .find(|net| net.contains(*endpoint.ip()))
        {
            return Err(invalid(format!(
                "route {net} contains the public WireGuard endpoint {}; choose --subnet and --lan networks that leave the endpoint reachable through the uplink",
                endpoint.ip()
            )));
        }
        let cloudflare = self.cloudflare(prompt)?;
        let upnp = gateway(found).map(|url| UpnpConfig {
            control_url: url.to_owned(),
            lease_secs: 3600,
            refresh_secs: 300.try_into().unwrap(),
        });
        let mut config = Config {
            version: Version1,
            private_key: Key::generate()?,
            interface: Interface {
                address,
                mtu: config::DEFAULT_MTU,
            },
            peers: Vec::new(),
            role: Role::Server(ServerConfig {
                instance: Default::default(),
                iface: found.uplink.iface.clone(),
                listen_port: found.port.tested,
                lan,
                publish,
                cloudflare,
                upnp,
                stun: (publish == PublishMode::Txt || found.public_by == Some(PublicBy::Upnp))
                    .then(|| stun_config(request)),
                status_file: None,
                doctor: None,
            }),
            update: None,
        };
        config.add_doctor(false)?;
        config.validate().map_err(invalid)?;
        Ok(config)
    }

    fn enroll(
        &mut self,
        config: &mut Config,
        mode: Mode,
        prompt: &Prompt,
    ) -> Result<Option<Enrollment>> {
        let name = match self.peer.take() {
            Some(name) => Some(name),
            None => {
                Some(prompt.ask("First peer name (Enter to skip)", "")?).filter(|s| !s.is_empty())
            }
        };
        if name.is_none() && (self.format.is_some() || self.out.is_some()) {
            return Err(invalid(
                "--format and --out need a first peer; give --peer NAME",
            ));
        }
        let default_format = if mode == Mode::Wireguard {
            "wg-quick"
        } else {
            "natwg"
        };
        let Some(name) = name else { return Ok(None) };

        let mut client = peer::add(config, &name)?;
        if let (Some(dns), Role::Client(role)) = (self.dns, &mut client.role) {
            role.resolvers = vec![dns];
        }
        let format = match self.format {
            Some(format) => format,
            None => Format::from_str(
                &prompt.ask("Peer format (natwg/wg-quick/surge/clash)", default_format)?,
                true,
            )
            .map_err(invalid)?,
        };
        let replace_output = self.force && self.out.as_ref().is_some_and(|p| p.exists());
        Ok(Some(Enrollment {
            name,
            client,
            format,
            output: ExportOutput {
                out: self.out.take(),
                force: replace_output,
            },
        }))
    }
}

pub(super) fn run(mut args: Args, path: &Path) -> Result<()> {
    let prompt = Prompt::new(args.yes);
    let mut request = args.request(&prompt)?;
    let found = detect_network(
        &mut request,
        &prompt,
        prompt.interactive && args.upnp.is_none(),
    )?;
    let publish = publish(found.verdict, found.public_by);
    if found.verdict == Verdict::Likely {
        warn!("Reachability is likely. Connect a first client to confirm it.");
    }
    let mode = match args.mode {
        Some(mode) => mode,
        None if publish == PublishMode::A => {
            Mode::from_str(&prompt.ask("Server mode (natwg/wireguard)", "natwg")?, true)
                .map_err(invalid)?
        }
        None => Mode::Natwg,
    };
    if mode == Mode::Wireguard && publish != PublishMode::A {
        return Err(invalid(
            "--mode wireguard needs a confirmed public IP on the uplink or its UPnP router; use --mode natwg with TXT",
        ));
    }
    if mode == Mode::Wireguard && args.install_service
        || mode != Mode::Wireguard && args.wg_dir.is_some()
    {
        return Err(invalid(
            "--install-service requires natwg mode; --wg-dir requires wireguard mode",
        ));
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::new(
            "NOT_ROOT",
            "run sudo natwg init to create root-owned profiles",
        ));
    }
    files::check_target(path, args.force)?;
    let mut config = args.server(&request, &found, publish, &prompt)?;
    let enrollment = args.enroll(&mut config, mode, &prompt)?;
    let native = if mode == Mode::Wireguard {
        let ip = found
            .mapping
            .endpoint
            .ok_or_else(|| invalid("missing confirmed public endpoint"))?;
        warn!(
            "Plain WireGuard needs a DNS-only A record for {} pointing at {}. Maintain it when the address changes.",
            config.server()?.cloudflare.record,
            ip.ip()
        );
        if found.public_by == Some(PublicBy::Upnp) {
            warn!(
                "Maintain a UDP forward for port {} to {}:{} with a static router rule or an independent UPnP lease renewer. The detection lease is temporary.",
                ip.port(),
                found.uplink.address,
                ip.port()
            );
        }
        Some(args.wg_dir.unwrap_or_else(files::wireguard_dir))
    } else {
        None
    };
    let install = mode == Mode::Natwg
        && (args.install_service
            || prompt.confirm("Install and start the natwg system service?", false)?);
    let rt = runtime(tokio::runtime::Builder::new_current_thread())?;
    if mode == Mode::Natwg {
        warn!(
            "Configuring the natwg server with {publish} publication for {}.",
            config.server()?.cloudflare.record
        );
    }
    let saved = files::save(
        &rt,
        path,
        &config,
        enrollment.as_ref(),
        native.as_deref(),
        args.token_file.as_deref(),
        args.force,
    )?;
    if let Some(dir) = native {
        warn!(
            "Start the server with sudo wg-quick up {}",
            shell_path(&dir.join("natwg.conf"))
        );
    } else if !install {
        warn!(
            "Start the server with sudo natwg --config {} service install{}",
            shell_path(path),
            if args.force { " --reload-config" } else { "" }
        );
    }
    let mut detect = format!(
        "sudo natwg detect --config {} --dns {}",
        shell_path(path),
        request.dns
    );
    if matches!(request.upnp, UpnpMode::Off) {
        detect.push_str(" --upnp off");
    }
    for (host, port) in &request.servers {
        use std::fmt::Write;
        write!(detect, " --server={host}:{port}").unwrap();
    }
    warn!("Check the network with {detect}");
    warn!(
        "Check the tunnel with sudo natwg doctor loopback --config {}{}",
        shell_path(path),
        if mode == Mode::Wireguard {
            format!(" --endpoint {}", found.mapping.endpoint.unwrap())
        } else {
            String::new()
        }
    );
    let deliver = || -> Result<()> {
        if install {
            let report = service::install_new_config(path)?;
            warn!("{report}");
        }
        if let Some(peer) = &enrollment {
            rt.block_on(peer.deliver(config.server()?, install, found.mapping.endpoint))?;
        }
        Ok(())
    };
    saved.finish(deliver())
}

struct Enrollment {
    name: String,
    client: Config,
    format: Format,
    output: ExportOutput,
}

impl Enrollment {
    async fn deliver(
        &self,
        server: &ServerConfig,
        install: bool,
        detected: Option<SocketAddrV4>,
    ) -> Result<()> {
        // Service installation waits for the tunnel. The first TXT record
        // may still be propagating when a native profile needs a snapshot.
        if server.publish != PublishMode::Txt || self.format == Format::Natwg {
            let profile =
                export::render(&self.client, self.format, &self.name, Some(server)).await?;
            return self.output.write(&profile);
        }
        if !install {
            let endpoint = detected.ok_or_else(|| {
                Error::new(
                    "INIT_DNS_PENDING",
                    "no mapping was confirmed on the configured port",
                )
            })?;
            let profile = export::render_confirmed(
                &self.client,
                self.format,
                &self.name,
                Some(server),
                Some(endpoint),
            )
            .await?;
            return self.output.write(&profile);
        }
        let status = natwg::status::path(server);
        let snapshot = async {
            loop {
                if let Ok(seen) = natwg::status::Status::read(&status)
                    && let Some(endpoint) = seen.mapping
                    && seen.published == Some(endpoint)
                    && seen.record.as_deref() == Some(&server.cloudflare.record)
                {
                    match export::render_confirmed(
                        &self.client,
                        self.format,
                        &self.name,
                        Some(server),
                        Some(endpoint),
                    )
                    .await
                    {
                        Err(e) if matches!(e.code, "TXT_NO_ENDPOINT" | "TXT_NOT_CURRENT") => {}
                        result => return result,
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        };
        let profile = tokio::time::timeout(Duration::from_secs(30), snapshot).await
            .map_err(|_| Error::new("INIT_DNS_PENDING", format!("the new server's mapping and TXT record {} did not agree within 30 seconds", server.cloudflare.record)))??;
        self.output.write(&profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_supported_address_or_router_forward_qualifies_for_fixed_port_clients() {
        for source in [
            None,
            Some(PublicBy::Address),
            Some(PublicBy::Upnp),
            Some(PublicBy::PortKept),
        ] {
            for verdict in [Verdict::Likely, Verdict::Inconclusive, Verdict::Unsupported] {
                assert_eq!(publish(verdict, source), PublishMode::Txt);
            }
        }
        assert_eq!(publish(Verdict::Supported, None), PublishMode::Txt);
        assert_eq!(
            publish(Verdict::Supported, Some(PublicBy::PortKept)),
            PublishMode::Txt
        );
        assert_eq!(
            publish(Verdict::Supported, Some(PublicBy::Address)),
            PublishMode::A
        );
        assert_eq!(
            publish(Verdict::Supported, Some(PublicBy::Upnp)),
            PublishMode::A
        );
    }
}
