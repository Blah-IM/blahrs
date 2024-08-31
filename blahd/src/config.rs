use std::path::PathBuf;

use anyhow::{ensure, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub database: DatabaseConfig,
    pub server: ServerConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
    pub base_url: String,
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
