use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use doorward::{Config, Deps, build, serve, unlock};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser)]
#[command(name = "doorward")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Clears the login block of one account.
    Unlock {
        /// Path to the TOML config file.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        /// The account's email address.
        email: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("doorward: {err}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Some(Command::Unlock { config, email }) => {
            let config = Config::load(&config)?;
            unlock(&config, &email).await?;
            println!("unlocked {email}");
            Ok(())
        }
        None => match cli.config {
            Some(path) => start(&path).await,
            None => Err("--config is required".into()),
        },
    }
}

async fn start(config_path: &Path) -> Result<(), Box<dyn Error>> {
    let config = Config::load(config_path)?;
    let listen = config.listen;
    let https_without_proxy =
        config.public_url.starts_with("https://") && config.trusted_proxies.is_empty();
    let gateway = build(config, Deps::system()).await?;
    if https_without_proxy {
        eprintln!(
            "doorward: public_url is https but trusted_proxies is empty: if a proxy or tunnel is in front, every visitor shares one address for login throttling"
        );
    }
    let listener = TcpListener::bind(listen).await?;
    if let Some(code) = &gateway.setup_code {
        eprintln!("doorward setup code: {code}");
    }
    eprintln!("doorward listening on http://{}", listener.local_addr()?);
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    serve(listener, gateway.router, async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    })
    .await?;
    Ok(())
}
