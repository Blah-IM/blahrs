use std::num::NonZero;

use serde::Deserialize;
use serde_constant::ConstBool;
use serde_inline_default::serde_inline_default;

use crate::{database, ServerConfig};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub database: database::Config,
    pub listen: ListenConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub metric: Option<MetricConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenConfig {
    Address(String),
    Systemd(ConstBool<true>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricConfig {
    Prometheus(#[serde(default)] PrometheusConfig),
}

#[serde_inline_default]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrometheusConfig {
    pub listen: ListenConfig,
    #[serde_inline_default(5.try_into().expect("not zero"))]
    pub upkeep_period_secs: NonZero<u32>,
    #[serde_inline_default(20.try_into().expect("not zero"))]
    pub bucket_duration_secs: NonZero<u32>,
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
