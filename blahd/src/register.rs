use std::num::NonZero;
use std::time::{Duration, Instant};

use anyhow::{anyhow, ensure};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use blah_types::identity::{IdUrl, UserIdentityDesc};
use blah_types::{get_timestamp, Signed, UserRegisterPayload, X_BLAH_DIFFICULTY, X_BLAH_NONCE};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::database::TransactionOps;
use crate::{ApiError, AppState};

const USER_AGENT: &str = concat!("blahd/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enable_public: bool,

    pub difficulty: u8,
    pub nonce_rotate_secs: NonZero<u64>,
    pub request_timeout_secs: u64,

    pub max_identity_description_bytes: usize,

    pub unsafe_allow_id_url_http: bool,
    pub unsafe_allow_id_url_custom_port: bool,
    pub unsafe_allow_id_url_single_label: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_public: false,

            difficulty: 16,
            nonce_rotate_secs: 60.try_into().expect("not zero"),
            request_timeout_secs: 5,

            max_identity_description_bytes: 64 << 10, // 64KiB

            unsafe_allow_id_url_http: false,
            unsafe_allow_id_url_custom_port: false,
            unsafe_allow_id_url_single_label: false,
        }
    }
}

impl Config {
    /// Check if the Identity URL is valid under the config.
    /// This only does additional checking besides rules of [`IdUrl`].
    fn validate_id_url(&self, url: &IdUrl) -> Result<(), &'static str> {
        if !self.unsafe_allow_id_url_http && url.scheme() == "http" {
            return Err("http id_url is not permitted for this server");
        }
        if !self.unsafe_allow_id_url_custom_port && url.port().is_some() {
            return Err("id_url with custom port is not permitted for this server");
        }
        let host = url.host_str().expect("checked by IdUrl");
        if host.starts_with('.') || host.ends_with('.') {
            return Err("unpermitted id_url with starting or trailing dot");
        }
        if !self.unsafe_allow_id_url_single_label && !host.contains('.') {
            return Err("single-label id_url is not permitted for this server");
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct State {
    nonces: Mutex<Nonces>,
    client: reqwest::Client,

    epoch: Instant,
    config: Config,
}

#[derive(Debug, Clone, Copy)]
struct Nonces {
    nonce: u32,
    prev_nonce: u32,
    update_period: u64,
}

impl State {
    pub fn new(config: Config) -> Self {
        // TODO: Audit this.
        let client = reqwest::ClientBuilder::new()
            .user_agent(USER_AGENT)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .build()
            .expect("initialize TLS");
        Self {
            nonces: Nonces {
                nonce: OsRng.next_u32(),
                prev_nonce: OsRng.next_u32(),
                update_period: 0,
            }
            .into(),
            client,
            epoch: Instant::now(),
            config,
        }
    }

    fn nonce(&self) -> [u32; 2] {
        let cur_period =
            Instant::now().duration_since(self.epoch).as_secs() / self.config.nonce_rotate_secs;
        let mut n = self.nonces.lock();
        if n.update_period == cur_period {
            [n.nonce, n.prev_nonce]
        } else {
            n.prev_nonce = if n.update_period + 1 == cur_period {
                n.nonce
            } else {
                OsRng.next_u32()
            };
            n.update_period = cur_period;
            n.nonce = OsRng.next_u32();
            [n.nonce, n.prev_nonce]
        }
    }

    pub fn challenge_headers(&self) -> HeaderMap {
        if !self.config.enable_public {
            return HeaderMap::new();
        }

        HeaderMap::from_iter([
            (
                const { HeaderName::from_static(X_BLAH_NONCE) },
                self.nonce()[0].into(),
            ),
            (
                const { HeaderName::from_static(X_BLAH_DIFFICULTY) },
                u16::from(self.config.difficulty).into(),
            ),
        ])
    }
}

pub async fn user_register(
    st: &AppState,
    msg: Signed<UserRegisterPayload>,
) -> Result<StatusCode, ApiError> {
    if !st.config.register.enable_public {
        return Err(error_response!(
            StatusCode::FORBIDDEN,
            "disabled",
            "public registration is disabled",
        ));
    }

    let reg = &msg.signee.payload;

    // Basic validity check.
    if reg.server_url != st.config.base_url {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_server_url",
            "unexpected server url in payload",
        ));
    }
    if let Err(err) = st.config.register.validate_id_url(&reg.id_url) {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_id_url",
            "{err}",
        ));
    }
    if !st.register.nonce().contains(&reg.challenge_nonce) {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_challenge_nonce",
            "invalid or outdated challenge nonce",
        ));
    }

    // Challenge verification.
    let expect_bits = st.register.config.difficulty;
    if expect_bits > 0 {
        let hash = {
            let signee = msg.canonical_signee();
            let mut h = Sha256::new();
            h.update(&signee);
            h.finalize()
        };
        let hash = &hash[..];
        // `difficulty` is u8 so it must be < 256
        let (bytes, bits) = (expect_bits as usize / 8, expect_bits as usize % 8);
        // NB. Shift by 8 would overflow and wrap around for u8. Convert it to u32 first.
        let ok = hash[..bytes].iter().all(|&b| b == 0) && (hash[bytes] as u32) >> (8 - bits) == 0;
        if !ok {
            return Err(error_response!(
                StatusCode::BAD_REQUEST,
                "invalid_challenge_hash",
                "challenge failed",
            ));
        }
    }

    // TODO: Limit concurrency for the same domain and/or id_key?

    let fetch_url = reg
        .id_url
        .join(UserIdentityDesc::WELL_KNOWN_PATH)
        .expect("URL is validated");
    let fut = async {
        let resp = st
            .register
            .client
            .get(fetch_url)
            .send()
            .await?
            .error_for_status()?;
        let body = reqwest::Body::from(resp);
        let body =
            http_body_util::Limited::new(body, st.config.register.max_identity_description_bytes)
                .collect()
                .await
                .map_err(|err| anyhow!("{err}"))?
                .to_bytes();
        let id_desc = serde_json::from_slice::<UserIdentityDesc>(&body)?;
        anyhow::Ok(id_desc)
    };
    let fetch_time = get_timestamp();

    let id_desc = match fut.await {
        Ok(id_desc) => id_desc,
        Err(err) => {
            return Err(error_response!(
                StatusCode::UNAUTHORIZED,
                "fetch_id_description",
                "failed to fetch identity description from {}: {}",
                reg.id_url,
                err,
            ))
        }
    };

    if let Err(err) = (|| {
        ensure!(reg.id_key == id_desc.id_key, "id_key mismatch");
        id_desc.verify(Some(&reg.id_url), fetch_time)?;
        Ok(())
    })() {
        return Err(error_response!(
            StatusCode::UNAUTHORIZED,
            "invalid_id_description",
            "{err}",
        ));
    }

    // Now the identity is verified.

    let id_desc_json = serde_jcs::to_string(&id_desc).expect("serialization cannot fail");
    st.db
        .with_write(|txn| txn.create_user(&id_desc, &id_desc_json, fetch_time))?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_unpermitted_id_url() {
        let mut conf = Config::default();
        let http_url = "http://example.com".parse().unwrap();
        conf.validate_id_url(&http_url).unwrap_err();
        conf.unsafe_allow_id_url_http = true;
        conf.validate_id_url(&http_url).unwrap();

        let custom_port = "https://example.com:8080".parse().unwrap();
        conf.validate_id_url(&custom_port).unwrap_err();
        conf.unsafe_allow_id_url_custom_port = true;
        conf.validate_id_url(&custom_port).unwrap();

        let single_label = "https://localhost".parse().unwrap();
        conf.validate_id_url(&single_label).unwrap_err();
        conf.unsafe_allow_id_url_single_label = true;
        conf.validate_id_url(&single_label).unwrap();

        conf.validate_id_url(&"https://.".parse().unwrap())
            .unwrap_err();
    }
}
