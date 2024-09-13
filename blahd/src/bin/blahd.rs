use std::net::TcpListener;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use blahd::config::{Config, ListenConfig};
use blahd::{AppState, Database};

/// Blah Chat Server
#[derive(Debug, clap::Parser)]
#[clap(about, version = option_env!("CFG_RELEASE").unwrap_or(env!("CARGO_PKG_VERSION")))]
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

    let listener = match &config.listen {
        ListenConfig::Address(addr) => {
            tracing::info!("listening on {addr:?}");
            tokio::net::TcpListener::bind(addr)
                .await
                .context("failed to listen on socket")?
        }
        ListenConfig::Systemd(_) => {
            tracing::info!("listening on fd from environment");
            let [fd] = sd_notify::listen_fds()
                .context("failed to get fds from sd_listen_fds(3)")?
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| anyhow!("more than one fds available from sd_listen_fds(3)"))?;
            // SAFETY: `fd` is valid by sd_listen_fds(3) protocol.
            let listener = unsafe { TcpListener::from_raw_fd(fd) };
            listener
                .set_nonblocking(true)
                .context("failed to set socket non-blocking")?;
            tokio::net::TcpListener::from_std(listener)
                .context("failed to register async socket")?
        }
    };

    let router = blahd::router(Arc::new(st));
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

    axum::serve(listener, router)
        .await
        .context("failed to serve")?;
    Ok(())
}
