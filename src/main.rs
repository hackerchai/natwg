use clap::{Parser, Subcommand};
use natwg::{Result, config::Config, keys::Key};
use std::path::PathBuf;

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
    }
    Ok(())
}
