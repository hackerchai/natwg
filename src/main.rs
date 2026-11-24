use clap::{Args, Parser, Subcommand};
use natwg::wire::dns::{self, Record, RecordKind};
use natwg::wire::transport::{BoundInterface, StunPort};
use natwg::{Error, Result, config::Config, keys::Key};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    time::Duration,
};

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
        /// A STUN server, resolved through --dns. Servers are tried in order.
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
    }
    Ok(())
}

fn probe(action: ProbeAction) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::new("RUNTIME_UNAVAILABLE", e.to_string()))?;
    runtime.block_on(async {
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
    for record in dns::resolve(&iface, dns, &lookup.name, kind, timeout).await? {
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
    let mut stun = StunPort::bind(iface.clone(), port).await?;
    let mut targets = Vec::new();
    for (host, server_port) in servers {
        match dns::resolve(&iface, uplink.dns, &host, RecordKind::A, uplink.timeout).await {
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
        match stun.binding(target, uplink.timeout).await {
            Ok(mapping) => {
                println!("{mapping} via {target}");
                return Ok(());
            }
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
