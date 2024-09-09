use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
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
        config.validate()?;
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
    let listener = match &config.listen {
        ListenConfig::Address(addr) => tokio::net::TcpListener::bind(addr)
            .await
            .context("failed to listen on socket")?,
    };
    let st = AppState::new(db, config.server);

    tracing::info!("listening on {:?}", config.listen);
    let router = blahd::router(Arc::new(st));
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

    axum::serve(listener, router)
        .await
        .context("failed to serve")?;
    Ok(())
}
