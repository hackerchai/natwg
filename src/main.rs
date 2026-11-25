// `println!` and `eprintln!` panic when the pipe they write to is closed, and
// the server outlives the reader of its output. Every line goes through
// `say!` or `warn!`, which drop a line that cannot be written.
#![deny(clippy::print_stdout, clippy::print_stderr)]

use clap::{Args, Parser, Subcommand, ValueEnum};
use ipnetwork::Ipv4Network;
use natwg::client::{self, uplink};
use natwg::config::set::{self, Setting};
use natwg::config::{Config, Instance, Role};
use natwg::server::{self, cloudflare};
use natwg::status::{self, Report, Status};
use natwg::tunnel::{self, Tunnel};
use natwg::wire::dns::{self, Record, RecordKind};
use natwg::wire::stun;
use natwg::wire::transport::{BoundInterface, StunPort};
use natwg::{Error, Result, detect, doctor, keys::Key, peer, service, update};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tokio::signal::unix::{Signal, SignalKind, signal};

macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

macro_rules! warn {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

#[derive(Parser)]
#[command(
    version,
    about = "Reach a home LAN over WireGuard from behind carrier-grade NAT"
)]
struct Cli {
    /// The natwg configuration file.
    #[arg(long, global = true, env = "NATWG_CONFIG", default_value = natwg::config::DEFAULT_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Generate WireGuard keys.
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Show or change the configuration, or import a wg-quick client config.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Tell whether this network can host a natwg server.
    ///
    /// A client whose address is unknown in advance must reach the server's
    /// UDP port: natwg needs a public IPv4 address that keeps the listen
    /// port, or a full-cone NAT (NAT1). natwg tests the uplink with STUN
    /// through one socket: the filtering with an RFC 5780 server's
    /// CHANGE-REQUEST, the mapping across servers with different IPs, and a
    /// datagram from a second socket through the mapping. On a private
    /// uplink, --upnp auto has the UPnP gateway forward the test port for
    /// the test, as it would for the server, and deletes the lease after.
    ///
    /// Exit status: 0 supported (public or NAT1), 2 likely (one test could
    /// not run), 1 unsupported or an error. Needs no root.
    Detect {
        /// The uplink (default: role.server.iface of --config when natwg can
        /// read it, else the physical interface of the default route).
        #[arg(long)]
        iface: Option<String>,
        /// The UDP port to test (default: role.server.listen_port of
        /// --config, else 51830). A port in use, as by a running natwg,
        /// gives way to a free one.
        #[arg(long)]
        port: Option<u16>,
        /// A STUN server, asked in order; repeat it for more. An RFC 5780
        /// server runs the filtering test, and every server reports the
        /// mapping. With none, natwg uses its built-in lists.
        #[arg(long = "server", value_name = "HOST:PORT", value_parser = stun::host_port)]
        servers: Vec<(String, u16)>,
        /// Lease the test port on the UPnP gateway while the uplink's
        /// address is private.
        #[arg(long, value_enum, default_value_t = UpnpArg::Auto)]
        upnp: UpnpArg,
        /// The DNS server for STUN host names, asked through the uplink
        /// (default: stun.dns_server of --config, else 223.5.5.5).
        #[arg(long)]
        dns: Option<Ipv4Addr>,
        /// How long each STUN request waits before it is sent again, in
        /// milliseconds.
        #[arg(long = "timeout-ms", value_name = "MS", default_value = "1000", value_parser = millis)]
        timeout: Duration,
        /// Print the whole result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Ask STUN and DNS servers through one interface, without the daemon.
    Probe {
        #[command(subcommand)]
        action: ProbeAction,
    },
    /// Run the WireGuard server: the tunnel with its route and LAN NAT, the
    /// STUN keepalive, the TXT record, the UPnP lease and the status file.
    Server {
        /// Stay in the foreground until SIGINT, SIGTERM or SIGHUP. `natwg
        /// service install` runs the server in the background.
        #[arg(long, required = true)]
        foreground: bool,
    },
    /// Run the WireGuard client: the tunnel to the server with a route for
    /// each of its allowed IPs, the TXT lookup that follows the server's
    /// endpoint, and the status file.
    Client {
        /// Stay in the foreground until SIGINT, SIGTERM or SIGHUP. `natwg
        /// service install` runs the client in the background.
        #[arg(long, required = true)]
        foreground: bool,
    },
    /// Add, list or remove the clients of the server config.
    ///
    /// natwg replaces --config in one step. Restart the server to load the
    /// change: sudo natwg service restart.
    Peer {
        #[command(subcommand)]
        action: PeerAction,
    },
    /// Show what the running server or client reported last. Needs no root.
    ///
    /// natwg exits 1 when the status is older than 60 s or shows a problem:
    /// for a server no tunnel, no public mapping, a failed TXT publish, or
    /// failed NAT or UPnP; for a client no tunnel, no endpoint, a failed TXT
    /// lookup, or, with a keepalive, no handshake yet or none for 210 s plus
    /// the keepalive.
    Status {
        /// Print the status file as JSON.
        #[arg(long)]
        json: bool,
        /// The status file (default: the server's, else the client's when
        /// only that exists). A server of another instance than natwg writes
        /// <instance>.status.json beside the default, the client writes
        /// client.status.json there, and a config can name its own in
        /// status_file.
        #[arg(long, value_name = "PATH")]
        status_file: Option<PathBuf>,
    },
    /// Test a running server from this host.
    Doctor {
        #[command(subcommand)]
        action: DoctorAction,
    },
    /// Run the server or the client as a system service: a LaunchDaemon on
    /// macOS, a systemd unit on Linux.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Install the newest natwg release and restart the natwg services.
    ///
    /// natwg downloads the release archive of this platform from the
    /// download site, or from the GitHub Releases of hackerchai/natwg when
    /// the site fails, and checks it against the release's manifest. It
    /// replaces the service binary /usr/local/libexec/natwg/natwg and this
    /// natwg, each with its owner and mode, and keeps the file it replaced
    /// beside it as .natwg.previous. Then it restarts each natwg service
    /// that runs, and waits until it serves again; when one does not, natwg
    /// puts the previous binaries back and restarts the services again. A
    /// stopped service stays stopped. An older service binary is brought to
    /// the latest release even when this natwg is up to date. Nothing is
    /// downgraded.
    ///
    /// The GitHub repository is private, so its releases need GH_TOKEN or
    /// `gh auth login`. The `update` object of --config, when natwg can
    /// read it, sets `url` and `repository`.
    Update {
        /// Only print the installed and the latest versions. Needs no root.
        #[arg(long)]
        check: bool,
        /// The download site, an exact https:// origin with the same layout
        /// (default: https://natwg-dl.hackerchai.com).
        #[arg(long, value_name = "ORIGIN", env = "NATWG_UPDATE_URL")]
        download_url: Option<String>,
        /// Use the GitHub Releases of this repository alone.
        #[arg(long, value_name = "OWNER/REPO", env = "NATWG_UPDATE_REPOSITORY")]
        repository: Option<String>,
    },
    /// Run the server or the client of --config for a service manager, as
    /// `server --foreground` and `client --foreground` do.
    #[command(hide = true)]
    Daemon,
}

#[derive(Clone, Copy, ValueEnum)]
enum UpnpArg {
    Auto,
    Off,
}

#[derive(Subcommand)]
enum PeerAction {
    /// Give a new client fresh keys and the next free tunnel address, add it
    /// to the server config, and print the client's config.json.
    ///
    /// The client config holds the client's private key. Copy it to the
    /// client privately, as /usr/local/etc/natwg/config.json (macOS) or
    /// /etc/natwg/config.json (Linux), owned by root with mode 0600.
    Add {
        /// The name of the peer: 1 to 32 characters from A-Z, a-z, 0-9, '.',
        /// '_' and '-'.
        name: String,
        /// Write the client config here, readable only by its owner, instead
        /// of printing it.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
        /// Replace a file at --out.
        #[arg(long, requires = "out")]
        force: bool,
    },
    /// Print each peer: its name, allowed IPs and public key.
    List,
    /// Remove a peer from the server config.
    Remove { name: String },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install the server or the client of --config as a service and start
    /// it. The client's service is com.hackerchai.natwg.client on macOS and
    /// natwg-client.service on Linux.
    ///
    /// natwg copies itself to /usr/local/libexec/natwg/natwg, and the service
    /// runs that copy. A part that is in place already stays, so a second
    /// run with nothing changed keeps the running server.
    Install,
    /// Stop the service of --config, or of --instance, and remove it.
    ///
    /// The definition and the status file go. The binary and the config
    /// stay unless --purge is given.
    Uninstall {
        /// Also delete the config and, once no natwg service is left, the
        /// binary.
        #[arg(long)]
        purge: bool,
        /// Remove the service of this instance, or of the client with
        /// `client`, without reading --config, as when the config is broken
        /// or gone. Its status file stays.
        #[arg(long, value_name = "NAME", conflicts_with = "purge", value_parser = service_instance)]
        instance: Option<Instance>,
    },
    /// Restart the service of --config, which then reads the config again.
    Restart,
    /// Show every natwg service on this host. Needs no root.
    Status,
}

#[derive(Subcommand)]
enum DoctorAction {
    /// Ping the server's tunnel address and the first host of its first LAN,
    /// if it has one, through a WireGuard client inside this process. The client uses the doctor key
    /// of the server config. A reply time is that of the first echo that got
    /// an answer, so it includes the WireGuard handshake.
    Loopback {
        /// Where the client dials the server (default: the mapping in the
        /// status file of the server).
        #[arg(long, value_name = "IP:PORT")]
        endpoint: Option<SocketAddrV4>,
        /// The interface the client sends through (default: the server's interface).
        #[arg(long)]
        iface: Option<String>,
        /// How many echo requests a silent target gets, one per second. At
        /// least 1.
        #[arg(long, default_value_t = doctor::ATTEMPTS)]
        attempts: NonZeroU16,
    },
}

#[derive(Subcommand)]
enum KeysAction {
    /// Print a new private key and its public key.
    Gen,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the configuration with secrets redacted and the public key added.
    Show,
    /// Turn the wg-quick config of a client into a natwg client config that
    /// keeps its keys and its tunnel address.
    ///
    /// The config must have one [Peer], the server. wg-quick's placeholder
    /// `Endpoint = 0.0.0.0:0` counts as no endpoint.
    ImportWgQuick {
        /// The wg-quick config, such as /etc/wireguard/wg-home.conf.
        wg_conf: PathBuf,
        /// The TXT record that holds the server's endpoint as "ip:port".
        /// Without it, the client dials the Endpoint of the [Peer].
        #[arg(long, value_name = "NAME")]
        record: Option<String>,
        /// A DNS server to ask for --record, in order; repeat it for more
        /// (default: 223.5.5.5, 119.29.29.29, 1.1.1.1 and 8.8.8.8).
        #[arg(long = "resolver", value_name = "IP")]
        resolvers: Vec<Ipv4Addr>,
        /// Where to write the configuration (default: --config).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Print the redacted configuration without writing it.
        #[arg(long)]
        dry_run: bool,
        /// Replace a configuration that exists already.
        #[arg(long)]
        force: bool,
    },
    /// Give the server config of --config a doctor, the client identity that
    /// natwg doctor uses.
    ///
    /// The doctor gets a fresh key and the highest host of the tunnel subnet
    /// that neither the server nor a peer uses. natwg replaces --config in
    /// one step. Restart the server to load the doctor.
    Doctor {
        /// Replace a doctor that the config has already.
        #[arg(long)]
        force: bool,
    },
    /// Change one setting of --config in place.
    ///
    /// natwg validates the result, then replaces --config in one step,
    /// readable only by its owner. Restart the service to load the change:
    /// sudo natwg service restart.
    Set {
        #[command(subcommand)]
        setting: SetAction,
        /// Print the redacted result without writing it.
        #[arg(long, global = true)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum SetAction {
    /// The tunnel address of this host, whose prefix sets the tunnel subnet
    /// (interface.address): 10.66.66.1/24 on a server, 10.66.66.2/32 on a
    /// client.
    ///
    /// A server that moves to another subnet moves its peers and its doctor
    /// along, each at the same host offset. It refuses when one of them does
    /// not fit in the new subnet or would land on the new server address.
    /// Each moved client must then take its new address and route the new
    /// subnet.
    Address {
        #[arg(value_name = "ADDR/PREFIX")]
        address: Ipv4Network,
    },
    /// The LAN networks of a server (role.server.lan). The server NATs its
    /// clients into each of them out of role.server.iface. With none, it
    /// serves the tunnel only.
    ///
    /// Clients route only their own allowed_ips, so give each the new set.
    Lan {
        #[arg(value_name = "CIDR")]
        lans: Vec<Ipv4Network>,
    },
    /// The networks a client routes into the tunnel (peers[0].allowed_ips),
    /// such as the tunnel subnet and the LANs of the server.
    AllowedIps {
        #[arg(value_name = "CIDR", required = true)]
        networks: Vec<Ipv4Network>,
    },
}

#[derive(Subcommand)]
enum ProbeAction {
    /// Print the public mapping of a UDP port as a STUN server sees it.
    Stun {
        #[command(flatten)]
        uplink: Uplink,
        /// The local UDP port; 0 picks a free one.
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// A STUN server, resolved through --dns. Servers are tried in order. With
        /// no --server and no --fallback, natwg uses its built-in list.
        #[arg(long = "server", value_name = "HOST:PORT", value_parser = stun::host_port)]
        servers: Vec<(String, u16)>,
        /// A STUN server address, tried after every --server.
        #[arg(long = "fallback", value_name = "IP:PORT")]
        fallbacks: Vec<SocketAddrV4>,
    },
    /// Print the A records of a name, one per line.
    Dns(Lookup),
    /// Print the TXT records of a name, one per line.
    Txt(Lookup),
    /// Print the uplink natwg client picks: the physical interface of the
    /// default route that has an IPv4 address, skipping VPN tunnels.
    Uplink,
}

#[derive(Args)]
struct Lookup {
    name: String,
    #[command(flatten)]
    uplink: Uplink,
}

#[derive(Args)]
struct Uplink {
    /// The uplink interface, such as en6 or eth0.
    #[arg(long)]
    iface: String,
    /// The DNS server, asked through --iface.
    #[arg(long, default_value = "223.5.5.5")]
    dns: Ipv4Addr,
    /// How long to wait for each answer, in milliseconds.
    #[arg(long = "timeout-ms", value_name = "MS", default_value = "3000", value_parser = millis)]
    timeout: Duration,
}

const DNS_PORT: u16 = 53;

fn millis(text: &str) -> std::result::Result<Duration, std::num::ParseIntError> {
    text.parse().map(Duration::from_millis)
}

/// An instance name, or `client` for the client's service.
fn service_instance(name: &str) -> std::result::Result<Instance, &'static str> {
    match name {
        "client" => Ok(Instance::client()),
        name => name.parse(),
    }
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        warn!("{error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Action::Keys {
            action: KeysAction::Gen,
        } => {
            let key = Key::generate()?;
            let keys = serde_json::json!({
                "private_key": key.to_base64(),
                "public_key": key.public_key(),
            });
            say!("{keys:#}");
        }
        Action::Config {
            action: ConfigAction::Show,
        } => say!("{}", Config::load(&cli.config)?.redacted()),
        Action::Config {
            action:
                ConfigAction::ImportWgQuick {
                    wg_conf,
                    record,
                    resolvers,
                    out,
                    dry_run,
                    force,
                },
        } => {
            let config = client::wg_quick::import(&wg_conf, record, resolvers)?;
            say!("{}", config.redacted());
            if !dry_run {
                let out = out.unwrap_or(cli.config);
                if force {
                    config.save(&out)?;
                } else {
                    config.create(&out)?;
                }
                warn!("Wrote {}", out.display());
            }
        }
        Action::Config {
            action: ConfigAction::Doctor { force },
        } => {
            let mut config = Config::load(&cli.config)?;
            let doctor = config.add_doctor(force)?;
            config.save(&cli.config)?;
            say!(
                "doctor {} public key {}",
                doctor.address,
                doctor.private_key.public_key()
            );
            warn!(
                "Wrote {}; natwg service restart loads the doctor",
                cli.config.display()
            );
        }
        Action::Config {
            action: ConfigAction::Set { setting, dry_run },
        } => config_set(&cli.config, setting, dry_run)?,
        Action::Probe { action } => probe(action)?,
        Action::Detect {
            iface,
            port,
            servers,
            upnp,
            dns,
            timeout,
            json,
        } => {
            // Root reads a root config; without root, natwg goes without.
            let config = Config::load(&cli.config).ok();
            let server = config.as_ref().and_then(|config| config.server().ok());
            let request = detect::Request {
                iface: iface.or_else(|| server.map(|server| server.iface.clone())),
                port: port.or(server.map(|server| server.listen_port)),
                servers,
                upnp: match upnp {
                    UpnpArg::Auto => detect::UpnpMode::Auto,
                    UpnpArg::Off => detect::UpnpMode::Off,
                },
                dns: dns
                    .or(server.map(|server| server.stun.dns_server))
                    .unwrap_or(detect::DEFAULT_DNS),
                timeout,
            };
            let detection = runtime(tokio::runtime::Builder::new_current_thread())?
                .block_on(detect::run(&request))?;
            if json {
                say!(
                    "{}",
                    serde_json::to_string_pretty(&detection)
                        .expect("a detection always serializes")
                );
            } else {
                say!("{}", detection.render().trim_end());
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
            std::process::exit(detection.exit_code());
        }
        Action::Server { foreground: _ } => daemon(&cli.config, Some(Want::Server))?,
        Action::Client { foreground: _ } => daemon(&cli.config, Some(Want::Client))?,
        Action::Daemon => daemon(&cli.config, None)?,
        Action::Peer { action } => peer_action(&cli.config, action)?,
        Action::Status { json, status_file } => {
            let status = Report::read(&status_file.unwrap_or_else(status::default_path))?;
            let now = status::unix(SystemTime::now());
            if json {
                say!(
                    "{}",
                    serde_json::to_string_pretty(&status).expect("a status always serializes")
                );
            } else {
                say!("{}", status.render(now).trim_end());
                if let Some(notice) = status.update_notice() {
                    say!("{notice}");
                }
            }
            let problems = status.problems(now);
            if !problems.is_empty() {
                return Err(Error::new(status.unhealthy(), problems.join(", ")));
            }
        }
        Action::Doctor {
            action:
                DoctorAction::Loopback {
                    endpoint,
                    iface,
                    attempts,
                },
        } => doctor_loopback(&cli.config, iface.as_deref(), endpoint, attempts)?,
        Action::Service { action } => service_action(&cli.config, action)?,
        Action::Update {
            check,
            download_url,
            repository,
        } => {
            // Root reads a root config; a check without root goes without.
            let config = Config::load(&cli.config).ok().and_then(|c| c.update);
            let config = config.unwrap_or_default();
            update::run(&update::Request {
                check,
                site: download_url.or(config.url).as_deref(),
                repository: repository.or(config.repository).as_deref(),
            })?;
        }
    }
    Ok(())
}

fn config_set(path: &Path, action: SetAction, dry_run: bool) -> Result<()> {
    let setting = match action {
        SetAction::Address { address } => Setting::Address(address),
        SetAction::Lan { lans } => Setting::Lan(lans),
        SetAction::AllowedIps { networks } => Setting::AllowedIps(networks),
    };
    let mut config = Config::load(path)?;
    let change = set::apply(&mut config, &setting)?;
    if dry_run {
        say!("{}", config.redacted());
    }
    if change.changed.is_empty() {
        warn!(
            "{} has this {} already; nothing to write",
            path.display(),
            setting.key()
        );
        return Ok(());
    }
    if !dry_run {
        config.save(path)?;
    }
    for line in &change.changed {
        // Under --dry-run, stdout holds only the redacted config.
        if dry_run {
            warn!("{line}");
        } else {
            say!("{line}");
        }
    }
    for note in &change.notes {
        warn!("{note}");
    }
    if dry_run {
        warn!("Dry run: {} stays as it was", path.display());
    } else {
        warn!(
            "Wrote {}; run sudo natwg service restart to load it",
            path.display()
        );
    }
    Ok(())
}

fn peer_action(path: &Path, action: PeerAction) -> Result<()> {
    let mut config = Config::load(path)?;
    match action {
        PeerAction::List => {
            match peer::list(&config)?.trim_end() {
                "" => warn!("{} has no peers", path.display()),
                listed => say!("{listed}"),
            }
            return Ok(());
        }
        PeerAction::Add { name, out, force } => {
            let client = peer::add(&mut config, &name)?;
            // The client's file comes first, so a refused --out leaves the
            // server config as it was.
            if let Some(out) = &out {
                if force {
                    client.save(out)?;
                } else {
                    client.create(out)?;
                }
            }
            config.save(path)?;
            let address = client.interface.address;
            match &out {
                Some(out) => warn!("Wrote the config of {name} to {}", out.display()),
                None => say!("{}", client.exposed()),
            }
            warn!(
                "Added peer {name} at {address} to {}; sudo natwg service restart loads it",
                path.display()
            );
        }
        PeerAction::Remove { name } => {
            let removed = peer::remove(&mut config, &name)?;
            config.save(path)?;
            warn!(
                "Removed peer {name} ({}) from {}; sudo natwg service restart drops it",
                removed.public_key,
                path.display()
            );
        }
    }
    Ok(())
}

fn service_action(config: &Path, action: ServiceAction) -> Result<()> {
    let report = match action {
        ServiceAction::Install => service::install(config)?,
        ServiceAction::Uninstall {
            instance: Some(instance),
            ..
        } => service::uninstall_instance(&instance)?,
        ServiceAction::Uninstall {
            purge,
            instance: None,
        } => service::uninstall(config, purge)?,
        ServiceAction::Restart => service::restart(config)?,
        ServiceAction::Status => {
            let services = service::status()?;
            if services.is_empty() {
                return Err(Error::new(
                    "SERVICE_NOT_INSTALLED",
                    "no natwg service is installed; run natwg service install",
                ));
            }
            for (name, state) in &services {
                say!("{name} {state}");
            }
            let stopped: Vec<&str> = services
                .iter()
                .filter(|(_, state)| !matches!(state, service::State::Running { .. }))
                .map(|(name, _)| name.as_str())
                .collect();
            if stopped.is_empty() {
                return Ok(());
            }
            return Err(Error::new(
                "SERVICE_STOPPED",
                format!("{} does not run", stopped.join(" and ")),
            ));
        }
    };
    say!("{report}");
    Ok(())
}

fn doctor_loopback(
    config: &Path,
    iface: Option<&str>,
    endpoint: Option<SocketAddrV4>,
    attempts: NonZeroU16,
) -> Result<()> {
    let config = Config::load(config)?;
    let endpoint = match endpoint {
        Some(endpoint) => endpoint,
        None => {
            let path = status::path(config.server()?);
            Status::read(&path)?.mapping.ok_or_else(|| {
                Error::new(
                    "DOCTOR_NO_ENDPOINT",
                    format!("{} holds no mapping yet; pass --endpoint", path.display()),
                )
            })?
        }
    };
    let probes = runtime(tokio::runtime::Builder::new_current_thread())?
        .block_on(doctor::loopback(&config, iface, endpoint, attempts))?;
    let mut silent = Vec::new();
    for probe in probes {
        match probe.reply {
            Some(reply) => {
                let ms = reply.as_secs_f64() * 1000.0;
                say!("{} reply {ms:.1} ms", probe.target);
            }
            None => {
                say!("{} no reply", probe.target);
                silent.push(probe.target.to_string());
            }
        }
    }
    if silent.is_empty() {
        return Ok(());
    }
    Err(Error::new(
        "DOCTOR_NO_REPLY",
        format!("{} did not answer through {endpoint}", silent.join(" and ")),
    ))
}

fn runtime(mut builder: tokio::runtime::Builder) -> Result<tokio::runtime::Runtime> {
    builder
        .enable_all()
        .build()
        .map_err(|e| Error::new("RUNTIME_UNAVAILABLE", e.to_string()))
}

/// The role a command needs of the config.
#[derive(Clone, Copy)]
enum Want {
    Server,
    Client,
}

/// Run the server or the client of `config` until a signal stops it. With
/// `want`, the config must have that role.
fn daemon(config: &Path, want: Option<Want>) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        let what = match want {
            Some(Want::Server) => "natwg server opens a TUN and loads NAT rules",
            Some(Want::Client) => "natwg client opens a TUN and adds routes",
            None => "natwg daemon opens a TUN",
        };
        return Err(Error::new("NOT_ROOT", format!("{what}; run it as root")));
    }
    let config = Config::load(config)?;
    match want {
        Some(Want::Server) => {
            config.server()?;
        }
        Some(Want::Client) => {
            config.client()?;
        }
        None => {}
    }
    // A write error must not panic, because the daemon outlives the reader
    // of its output.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .log_internal_errors(false)
        .init();
    runtime(tokio::runtime::Builder::new_multi_thread())?.block_on(async {
        // In the background, and never in the way of the tunnel.
        update::spawn_checks(config.update.as_ref());
        let mut stop = Stop::listen()?;
        let stop = async move { stop.requested().await };
        match &config.role {
            Role::Server(_) => server::run(&config, cloudflare::API, Tunnel::start, stop).await,
            Role::Client(_) => {
                let build = async |config: &Config, uplink: &uplink::Uplink, endpoint| {
                    tunnel::Client::start(config, &uplink.iface, endpoint).await
                };
                let options = client::Options::default();
                client::run(&config, &options, uplink::find, build, stop).await
            }
        }
    })
}

/// The signals that stop the server or the client. SIGHUP is one of them, because a
/// terminal that closes sends it, and its default action ends the process
/// with the NAT rule still loaded.
struct Stop {
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
}

impl Stop {
    fn listen() -> Result<Self> {
        let listen =
            |kind| signal(kind).map_err(|e| Error::new("SIGNAL_UNAVAILABLE", e.to_string()));
        Ok(Self {
            interrupt: listen(SignalKind::interrupt())?,
            terminate: listen(SignalKind::terminate())?,
            hangup: listen(SignalKind::hangup())?,
        })
    }

    async fn requested(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
            _ = self.hangup.recv() => {}
        }
    }
}

fn built_in_stun() -> (Vec<(String, u16)>, Vec<SocketAddrV4>) {
    let servers = stun::DEFAULT_SERVERS.map(|(host, port)| (host.to_owned(), port));
    (servers.to_vec(), stun::DEFAULT_FALLBACKS.to_vec())
}

fn probe(action: ProbeAction) -> Result<()> {
    runtime(tokio::runtime::Builder::new_current_thread())?.block_on(async {
        match action {
            ProbeAction::Stun {
                uplink,
                port,
                servers,
                fallbacks,
            } => probe_stun(uplink, port, servers, fallbacks).await,
            ProbeAction::Dns(lookup) => probe_records(lookup, RecordKind::A).await,
            ProbeAction::Txt(lookup) => probe_records(lookup, RecordKind::Txt).await,
            ProbeAction::Uplink => {
                say!("{}", uplink::find(None)?);
                Ok(())
            }
        }
    })
}

async fn probe_records(lookup: Lookup, kind: RecordKind) -> Result<()> {
    let Uplink {
        iface,
        dns,
        timeout,
    } = lookup.uplink;
    let iface = BoundInterface::lookup(&iface)?;
    let server = SocketAddrV4::new(dns, DNS_PORT);
    for record in dns::resolve(&iface, server, &lookup.name, kind, timeout).await? {
        say!("{record}");
    }
    Ok(())
}

async fn probe_stun(
    uplink: Uplink,
    port: u16,
    servers: Vec<(String, u16)>,
    fallbacks: Vec<SocketAddrV4>,
) -> Result<()> {
    let iface = BoundInterface::lookup(&uplink.iface)?;
    let (servers, fallbacks) = if servers.is_empty() && fallbacks.is_empty() {
        built_in_stun()
    } else {
        (servers, fallbacks)
    };
    let mut stun = StunPort::bind(iface.clone(), port).await?;
    let (dns, timeout) = (uplink.dns, uplink.timeout);
    let (mapping, target) =
        first_mapping(&mut stun, &iface, dns, timeout, servers, fallbacks).await?;
    say!("{mapping} via {target}");
    Ok(())
}

/// The first mapping a STUN server reports, and that server. Each of
/// `servers` is resolved through `dns` and asked in order, then `fallbacks`.
async fn first_mapping(
    stun: &mut StunPort,
    iface: &BoundInterface,
    dns: Ipv4Addr,
    timeout: Duration,
    servers: Vec<(String, u16)>,
    fallbacks: Vec<SocketAddrV4>,
) -> Result<(SocketAddrV4, SocketAddrV4)> {
    let mut targets = Vec::new();
    for (host, server_port) in servers {
        let server = SocketAddrV4::new(dns, DNS_PORT);
        match dns::resolve(iface, server, &host, RecordKind::A, timeout).await {
            Ok(records) => targets.extend(records.into_iter().filter_map(|record| match record {
                Record::A(ip) => Some(SocketAddrV4::new(ip, server_port)),
                Record::Txt(_) => None,
            })),
            Err(error) => warn!("{error}; skipping {host}:{server_port}"),
        }
    }
    targets.extend(fallbacks);
    let mut failure = None;
    for target in targets {
        match stun.binding(target, timeout).await {
            Ok(mapping) => return Ok((mapping, target)),
            Err(error) => {
                warn!("{error}");
                failure = Some(error.code);
            }
        }
    }
    Err(match failure {
        Some(code) => Error::new(code, "no STUN server answered"),
        None => Error::new("STUN_NO_SERVER", "no STUN server address to try"),
    })
}

#[cfg(test)]
mod tests {
    use super::Stop;
    use std::time::Duration;

    #[tokio::test]
    async fn sigint_sigterm_and_sighup_each_stop_the_server() {
        let signals = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
        // A signal that nothing listens for is ignored from here on, so a
        // missing listener fails this test and does not kill the test run.
        for signal in signals {
            unsafe { libc::signal(signal, libc::SIG_IGN) };
        }
        let mut stop = Stop::listen().unwrap();
        for signal in signals {
            unsafe { libc::kill(libc::getpid(), signal) };
            tokio::time::timeout(Duration::from_secs(5), stop.requested())
                .await
                .unwrap_or_else(|_| panic!("signal {signal} did not stop the server"));
        }
    }
}
