use std::future::IntoFuture;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use blahd::config::{Config, ListenConfig};
use blahd::{AppState, Database};
use futures_util::future::Either;
use tokio::signal::unix::{SignalKind, signal};

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

    let (listener, addr_display) = match &config.listen {
        ListenConfig::Address(addr) => {
            let tcp = tokio::net::TcpListener::bind(addr)
                .await
                .context("failed to listen on socket")?;
            (Either::Left(tcp), format!("tcp address {addr:?}"))
        }
        ListenConfig::Systemd(_) => {
            use rustix::net::{AddressFamily, getsockname};

            let [fd] = sd_notify::listen_fds()
                .context("failed to get fds from sd_listen_fds(3)")?
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| anyhow!("expecting exactly one fd from LISTEN_FDS"))?;
            // SAFETY: `fd` is valid by sd_listen_fds(3) protocol.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };

            let addr = getsockname(&fd).context("failed to getsockname")?;
            let listener = match addr.address_family() {
                AddressFamily::INET | AddressFamily::INET6 => {
                    let listener = std::net::TcpListener::from(fd);
                    listener
                        .set_nonblocking(true)
                        .context("failed to set socket non-blocking")?;
                    let listener = tokio::net::TcpListener::from_std(listener)
                        .context("failed to register async socket")?;
                    Either::Left(listener)
                }
                AddressFamily::UNIX => {
                    let uds = std::os::unix::net::UnixListener::from(fd);
                    uds.set_nonblocking(true)
                        .context("failed to set socket non-blocking")?;
                    let uds = tokio::net::UnixListener::from_std(uds)
                        .context("failed to register async socket")?;
                    Either::Right(uds)
                }
                _ => bail!("unsupported socket type from LISTEN_FDS: {addr:?}"),
            };
            (listener, format!("socket {addr:?} from LISTEN_FDS"))
        }
    };

    let router = blahd::router(Arc::new(st));

    let mut sigterm = signal(SignalKind::terminate()).context("failed to listen on SIGTERM")?;
    let shutdown = async move {
        sigterm.recv().await;
        tracing::info!("received SIGTERM, shutting down gracefully");
    };
    let service = match listener {
        Either::Left(tcp) => axum::serve(tcp, router)
            .with_graceful_shutdown(shutdown)
            .into_future(),
        Either::Right(uds) => axum::serve(uds, router)
            .with_graceful_shutdown(shutdown)
            .into_future(),
    };

    tracing::info!("serving on {addr_display}");
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);
    service.await.context("failed to serve")?;
    Ok(())
}
