// `println!` and `eprintln!` panic when the pipe they write to is closed, and
// the server outlives the reader of its output. Every line goes through
// `say!` or `warn!`, which drop a line that cannot be written.
#![deny(clippy::print_stdout, clippy::print_stderr)]

use clap::{Args, Parser, Subcommand};
use natwg::client::{self, uplink};
use natwg::config::{Config, Instance, Role};
use natwg::server::{self, cloudflare};
use natwg::status::{self, Report, Status};
use natwg::tunnel::{self, Tunnel};
use natwg::wire::dns::{self, Record, RecordKind};
use natwg::wire::stun;
use natwg::wire::transport::{BoundInterface, StunPort};
use natwg::{Error, Result, doctor, keys::Key, service};
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
    /// Show the configuration, or give a server config a doctor.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
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
        /// Stay in the foreground until SIGINT, SIGTERM or SIGHUP.
        #[arg(long, required = true)]
        foreground: bool,
    },
    /// Show what the running server or client reported last. Needs no root.
    ///
    /// natwg exits 1 when the status is older than 60 s or shows a problem:
    /// for a server no tunnel, no public mapping, a failed TXT publish, or
    /// failed NAT or UPnP; for a client no tunnel, no endpoint, a failed TXT
    /// lookup, or no handshake within 180 s.
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
    /// Run the server as a system service: a LaunchDaemon on macOS, a
    /// systemd unit on Linux.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Run the server or the client of --config for a service manager, as
    /// `server --foreground` and `client --foreground` do.
    #[command(hide = true)]
    Daemon,
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install the server of --config as a service and start it.
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
        /// Remove the service of this instance without reading --config, as
        /// when the config is broken or gone. Its status file stays.
        #[arg(long, value_name = "NAME", conflicts_with = "purge")]
        instance: Option<Instance>,
    },
    /// Restart the service of --config, which then reads the config again.
    Restart,
    /// Show every natwg service on this host. Needs no root.
    Status,
}

#[derive(Subcommand)]
enum DoctorAction {
    /// Ping the server's tunnel address and the first host of its LAN through
    /// a WireGuard client inside this process. The client uses the doctor key
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
        Action::Probe { action } => probe(action)?,
        Action::Server { foreground: _ } => daemon(&cli.config, Some(Want::Server))?,
        Action::Client { foreground: _ } => daemon(&cli.config, Some(Want::Client))?,
        Action::Daemon => daemon(&cli.config, None)?,
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
