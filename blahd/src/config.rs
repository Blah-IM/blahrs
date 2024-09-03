use std::path::PathBuf;
use std::time::Duration;

use anyhow::{ensure, Result};
use serde::{Deserialize, Deserializer};
use serde_inline_default::serde_inline_default;
use url::Url;

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
    pub base_url: Url,

    #[serde_inline_default(1024)]
    pub max_page_len: usize,
    #[serde_inline_default(4096)] // 4KiB
    pub max_request_len: usize,

    #[serde_inline_default(90)]
    pub timestamp_tolerance_secs: u64,

    #[serde_inline_default(Duration::from_secs(15))]
    #[serde(deserialize_with = "de_duration_sec")]
    pub ws_auth_timeout_sec: Duration,
    #[serde_inline_default(Duration::from_secs(15))]
    #[serde(deserialize_with = "de_duration_sec")]
    pub ws_send_timeout_sec: Duration,
    #[serde_inline_default(1024)]
    pub ws_event_queue_len: usize,
}

fn de_duration_sec<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
    <u64>::deserialize(de).map(Duration::from_secs)
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.server.base_url.cannot_be_a_base(),
            "base_url must be able to be a base",
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
