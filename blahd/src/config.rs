use serde::{Deserialize, Serialize};
use serde_constant::ConstBool;

use crate::{ServerConfig, database};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub database: database::Config,
    pub listen: ListenConfig,
    pub server: ServerConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenConfig {
    Address(String),
    Systemd(ConstBool<true>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example() {
        let src = std::fs::read_to_string("config.example.toml").unwrap();
        let _config = toml::from_str::<Config>(&src).unwrap();
    }

    #[test]
    fn minimal_address() {
        let src = r#"
[server]
base_url = "http://localhost"
[listen]
address = "localhost:8080"
        "#;
        let _config = toml::from_str::<Config>(src).unwrap();
    }

    #[test]
    fn minimal_systemd() {
        let src = r#"
[server]
base_url = "http://localhost"
[listen]
systemd = true
        "#;
        let _config = toml::from_str::<Config>(src).unwrap();
    }
}
