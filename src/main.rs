use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use doorward::{Config, Deps, build, serve, unlock};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

/// The longest a health check may wait for the gateway's answer.
const HEALTH_LIMIT: Duration = Duration::from_secs(3);

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
        config: Option<PathBuf>,
        /// The account's email address.
        email: String,
    },
    /// Checks that the gateway answers on its listen address.
    Health {
        /// Path to the TOML config file.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("doorward: {err}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, Box<dyn Error>> {
    let top = cli.config;
    match cli.command {
        Some(Command::Unlock { config, email }) => {
            let config = load(config.or(top).as_deref())?;
            unlock(&config, &email).await?;
            println!("unlocked {email}");
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Health { config }) => {
            let config = load(config.or(top).as_deref())?;
            Ok(health(&config).await)
        }
        None => start(top.as_deref()).await,
    }
}

/// The settings from the file and the environment: the loader every subcommand uses.
fn load(path: Option<&Path>) -> Result<Config, Box<dyn Error>> {
    let vars: Vec<(String, String)> = std::env::vars_os()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect();
    Ok(Config::from_sources(path, &vars)?)
}

async fn start(config_path: Option<&Path>) -> Result<ExitCode, Box<dyn Error>> {
    let config = load(config_path)?;
    if let Some(line) = config.start_check()? {
        eprintln!("{line}");
    }
    let listen = config.listen;
    let gateway = build(config, Deps::system()).await?;
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
    Ok(ExitCode::SUCCESS)
}

/// Asks the gateway's `/healthz`: exit 0 on 200, else exit 1 with one line on stderr.
async fn health(config: &Config) -> ExitCode {
    let url = health_url(config.listen);
    match probe(&url).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("doorward: health check of {url} failed: {reason}");
            ExitCode::from(1)
        }
    }
}

/// The listen address as a URL; a wildcard address is asked on loopback of its family.
fn health_url(listen: SocketAddr) -> String {
    let host = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    format!("http://{}/healthz", SocketAddr::new(host, listen.port()))
}

async fn probe(url: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(HEALTH_LIMIT)
        .build()
        .map_err(|err| err.to_string())?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.status() == reqwest::StatusCode::OK {
        Ok(())
    } else {
        Err(format!("it answered {}", response.status()))
    }
}
