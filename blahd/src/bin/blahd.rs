use std::path::PathBuf;

use anyhow::{Context, Result};
use blahd::config::Config;
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
        let config = basic_toml::from_str::<Config>(&src)?;
        config.validate()?;
        Ok(config)
    }

    match cli {
        Cli::Serve { config } => {
            let config = parse_config(&config)?;
            let db = Database::open(&config.database).context("failed to open database")?;
            let st = AppState::new(db, config.server);
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to initialize tokio runtime")?
                .block_on(st.serve())
        }
        Cli::Validate { config } => {
            parse_config(&config)?;
            Ok(())
        }
    }
}
