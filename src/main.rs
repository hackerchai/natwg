use clap::{Args, Parser, Subcommand};
use natwg::config::{Config, ServerConfig};
use natwg::tunnel::Tunnel;
use natwg::wire::dns::{self, Record, RecordKind};
use natwg::wire::stun;
use natwg::wire::transport::{BoundInterface, StunPort};
use natwg::{Error, Result, doctor, keys::Key};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::signal::unix::{Signal, SignalKind, signal};

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
    /// Show the configuration or import it from the Python natwg install.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Ask STUN and DNS servers through one interface, without the daemon.
    Probe {
        #[command(subcommand)]
        action: ProbeAction,
    },
    /// Run the WireGuard server: the tunnel interface, its route and LAN NAT.
    Server {
        /// Stay in the foreground until SIGINT, SIGTERM or SIGHUP. natwg has no
        /// other way to run the server yet.
        #[arg(long, required = true)]
        foreground: bool,
    },
    /// Test a running server from this host.
    Doctor {
        #[command(subcommand)]
        action: DoctorAction,
    },
}

#[derive(Subcommand)]
enum DoctorAction {
    /// Ping the server's tunnel address and the first host of its LAN through
    /// a WireGuard client inside this process. The client uses the doctor key
    /// of the server config. A reply time is that of the first echo that got
    /// an answer, so it includes the WireGuard handshake.
    Loopback {
        /// Where the client dials the server, such as the mapping that natwg
        /// server prints. Required, because natwg cannot look the mapping up yet.
        #[arg(long, value_name = "IP:PORT")]
        endpoint: SocketAddrV4,
        /// The interface the client sends through (default: the server's interface).
        #[arg(long)]
        iface: Option<String>,
        /// How many echo requests a silent target gets, one per second.
        #[arg(long, default_value_t = doctor::ATTEMPTS)]
        attempts: u16,
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
    /// Convert the Python natwg install into a configuration file.
    ImportLegacy {
        #[arg(long, default_value = natwg::legacy::DEFAULT_NATWG_JSON)]
        natwg_json: PathBuf,
        /// The WireGuard server config (default: wg_conf in natwg.json).
        #[arg(long)]
        wg_conf: Option<PathBuf>,
        /// The Cloudflare token file (default: cf_token_file in natwg.json).
        #[arg(long)]
        cf_token: Option<PathBuf>,
        /// Where to write the configuration (default: --config).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Print the redacted configuration without writing it.
        #[arg(long)]
        dry_run: bool,
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
        #[arg(long = "server", value_name = "HOST:PORT", value_parser = host_port)]
        servers: Vec<(String, u16)>,
        /// A STUN server address, tried after every --server.
        #[arg(long = "fallback", value_name = "IP:PORT")]
        fallbacks: Vec<SocketAddrV4>,
    },
    /// Print the A records of a name, one per line.
    Dns(Lookup),
    /// Print the TXT records of a name, one per line.
    Txt(Lookup),
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
const STUN_TIMEOUT: Duration = Duration::from_secs(3);

fn host_port(text: &str) -> std::result::Result<(String, u16), String> {
    let (host, port) = text.rsplit_once(':').ok_or("expected HOST:PORT")?;
    let port = port
        .parse()
        .map_err(|_| format!("{port:?} is not a port number"))?;
    Ok((host.to_owned(), port))
}

fn millis(text: &str) -> std::result::Result<Duration, std::num::ParseIntError> {
    text.parse().map(Duration::from_millis)
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("{error}");
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
            println!("{keys:#}");
        }
        Action::Config {
            action: ConfigAction::Show,
        } => println!("{}", Config::load(&cli.config)?.redacted()),
        Action::Config {
            action:
                ConfigAction::ImportLegacy {
                    natwg_json,
                    wg_conf,
                    cf_token,
                    out,
                    dry_run,
                },
        } => {
            let config =
                natwg::legacy::import(&natwg_json, wg_conf.as_deref(), cf_token.as_deref())?;
            println!("{}", config.redacted());
            if !dry_run {
                let out = out.unwrap_or(cli.config);
                config.save(&out)?;
                eprintln!("Wrote {}", out.display());
            }
        }
        Action::Probe { action } => probe(action)?,
        Action::Server { foreground: _ } => server(&cli.config)?,
        Action::Doctor {
            action:
                DoctorAction::Loopback {
                    endpoint,
                    iface,
                    attempts,
                },
        } => doctor_loopback(&cli.config, iface.as_deref(), endpoint, attempts)?,
    }
    Ok(())
}

fn doctor_loopback(
    config: &Path,
    iface: Option<&str>,
    endpoint: SocketAddrV4,
    attempts: u16,
) -> Result<()> {
    let config = Config::load(config)?;
    let probes = runtime(tokio::runtime::Builder::new_current_thread())?
        .block_on(doctor::loopback(&config, iface, endpoint, attempts))?;
    let mut silent = Vec::new();
    for probe in probes {
        match probe.reply {
            Some(reply) => {
                let ms = reply.as_secs_f64() * 1000.0;
                println!("{} reply {ms:.1} ms", probe.target);
            }
            None => {
                println!("{} no reply", probe.target);
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

fn server(config: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::new(
            "NOT_ROOT",
            "natwg server opens a TUN and loads NAT rules; run it as root",
        ));
    }
    let config = Config::load(config)?;
    runtime(tokio::runtime::Builder::new_multi_thread())?.block_on(serve(&config))
}

async fn serve(config: &Config) -> Result<()> {
    let server = config.server()?;
    let mut stop = Stop::listen()?;
    let mut tunnel = Tunnel::start(config).await?;
    println!("tun {}", tunnel.tun_name());
    let served = tokio::select! {
        failure = until_failure(&mut tunnel, server) => Err(failure),
        () = stop.requested() => Ok(()),
    };
    let stopped = tunnel.stop().await;
    served.and(stopped)
}

/// The signals that stop the server. SIGHUP is one of them, because a
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

/// Print the public mapping of the server's socket, then wait for the device
/// to fail. A server that learns no mapping keeps its tunnel up.
async fn until_failure(tunnel: &mut Tunnel, server: &ServerConfig) -> Error {
    match public_mapping(tunnel.stun(), server).await {
        Ok(mapping) => println!("mapping {mapping}"),
        Err(error) => eprintln!("{error}"),
    }
    tunnel.failed().await;
    Error::new(
        "TUNNEL_FAILED",
        "the WireGuard device stopped, because its TUN or its UDP socket failed",
    )
}

/// Ask the configured STUN servers, then the built-in ones.
async fn public_mapping(stun: &mut StunPort, server: &ServerConfig) -> Result<SocketAddrV4> {
    let iface = BoundInterface::lookup(&server.iface)?;
    let dns = server.stun.dns_server;
    let mut servers = Vec::new();
    for entry in &server.stun.servers {
        match host_port(entry) {
            Ok(server) => servers.push(server),
            Err(error) => eprintln!("STUN_SERVER_INVALID: {entry:?}: {error}"),
        }
    }
    let fallbacks = server.stun.fallback.clone();
    let configured = first_mapping(stun, &iface, dns, STUN_TIMEOUT, servers, fallbacks).await;
    let (mapping, _) = match configured {
        Ok(found) => found,
        Err(error) => {
            eprintln!("{error}; trying the built-in STUN servers");
            let (servers, fallbacks) = built_in_stun();
            first_mapping(stun, &iface, dns, STUN_TIMEOUT, servers, fallbacks).await?
        }
    };
    Ok(mapping)
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
        println!("{record}");
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
    println!("{mapping} via {target}");
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
            Err(error) => eprintln!("{error}; skipping {host}:{server_port}"),
        }
    }
    targets.extend(fallbacks);
    let mut failure = None;
    for target in targets {
        match stun.binding(target, timeout).await {
            Ok(mapping) => return Ok((mapping, target)),
            Err(error) => {
                eprintln!("{error}");
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
