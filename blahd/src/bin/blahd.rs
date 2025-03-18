use std::future::IntoFuture;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use blahd::config::{Config, ListenConfig};
use blahd::{AppState, Database};
use tokio::signal::unix::{signal, SignalKind};

/// Blah Chat Server
#[derive(Debug, clap::Parser)]
#[clap(about, version = env!("CFG_RELEASE"))]
enum Cli {
    /// Run the server with given configuration.
    Serve {
        /// The path to the configuration file.
        #[arg(long, short)]
        config: PathBuf,
    },

    /// Validate the configuration file and exit.
    Validate {
        /// The path to the configuration file.
        #[arg(long, short)]
        config: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = <Cli as clap::Parser>::parse();

    fn parse_config(path: &std::path::Path) -> Result<Config> {
        let src = std::fs::read_to_string(path)?;
        let config = toml::from_str::<Config>(&src)?;
        Ok(config)
    }

    match cli {
        Cli::Serve { config } => {
            let config = parse_config(&config)?;
            let db = Database::open(&config.database).context("failed to open database")?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to initialize tokio runtime")?
                .block_on(main_serve(db, config))
        }
        Cli::Validate { config } => {
            parse_config(&config)?;
            Ok(())
        }
    }
}

async fn main_serve(db: Database, config: Config) -> Result<()> {
    let st = AppState::new(db, config.server);

    let (listener_display, listener) = match &config.listen {
        ListenConfig::Address(addr) => (
            format!("address {addr:?}"),
            tokio::net::TcpListener::bind(addr)
                .await
                .context("failed to listen on socket")?,
        ),
        ListenConfig::Systemd(_) => {
            use rustix::net::{getsockname, SocketAddr};

            let [fd] = sd_notify::listen_fds()
                .context("failed to get fds from sd_listen_fds(3)")?
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| anyhow!("expecting exactly one fd from LISTEN_FDS"))?;
            // SAFETY: `fd` is valid by sd_listen_fds(3) protocol.
            let listener = unsafe { OwnedFd::from_raw_fd(fd) };

            let addr = getsockname(&listener).context("failed to getsockname")?;
            if let Ok(addr) = SocketAddr::try_from(addr.clone()) {
                let listener = std::net::TcpListener::from(listener);
                listener
                    .set_nonblocking(true)
                    .context("failed to set socket non-blocking")?;
                let listener = tokio::net::TcpListener::from_std(listener)
                    .context("failed to register async socket")?;
                (format!("tcp socket {addr:?} from LISTEN_FDS"), listener)
            } else {
                // Unix socket support for axum is currently overly complex.
                // WAIT: https://github.com/tokio-rs/axum/pull/2479
                bail!("unsupported socket type from LISTEN_FDS: {addr:?}");
            }
        }
    };

    tracing::info!("listening on {listener_display}");

    let router = blahd::router(Arc::new(st));

    let mut sigterm = signal(SignalKind::terminate()).context("failed to listen on SIGTERM")?;
    let service = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            sigterm.recv().await;
            tracing::info!("received SIGTERM, shutting down gracefully");
        })
        .into_future();

    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);
    service.await.context("failed to serve")?;
    Ok(())
}
