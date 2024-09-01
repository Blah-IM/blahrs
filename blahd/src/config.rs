use std::path::PathBuf;

use anyhow::{ensure, Result};
use serde::Deserialize;
use serde_inline_default::serde_inline_default;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub database: DatabaseConfig,
    pub server: ServerConfig,
}

#[serde_inline_default]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    #[serde_inline_default("/var/lib/blahd/db.sqlite".into())]
    pub path: PathBuf,
}

#[serde_inline_default]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
    pub base_url: String,

    #[serde_inline_default(1024)]
    pub max_page_len: usize,
    #[serde_inline_default(4096)] // 4KiB
    pub max_request_len: usize,
    #[serde_inline_default(1024)]
    pub event_queue_len: usize,

    #[serde_inline_default(90)]
    pub timestamp_tolerance_secs: u64,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.server.base_url.ends_with("/"),
            "base_url must not have trailing slash",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config() {
        let src = std::fs::read_to_string("config.example.toml").unwrap();
        let config = basic_toml::from_str::<Config>(&src).unwrap();
        config.validate().unwrap();
    }
}
