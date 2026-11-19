use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use doorward::{Config, Deps, build};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser)]
#[command(name = "doorward")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli.config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("doorward: {err}");
            ExitCode::from(2)
        }
    }
}

async fn run(config_path: &Path) -> Result<(), Box<dyn Error>> {
    let config = Config::load(config_path)?;
    let listen = config.listen;
    let router = build(config, Deps::system()).await?;
    let listener = TcpListener::bind(listen).await?;
    eprintln!("doorward listening on http://{}", listener.local_addr()?);
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = terminate.recv() => {}
            }
        })
        .await?;
    Ok(())
}
