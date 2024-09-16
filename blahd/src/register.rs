use std::num::NonZero;
use std::time::{Duration, Instant};

use anyhow::{anyhow, ensure, Context};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use blah_types::{
    get_timestamp, Signed, UserIdentityDesc, UserKey, UserRegisterPayload, X_BLAH_DIFFICULTY,
    X_BLAH_NONCE,
};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{named_params, params, OptionalExtension};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::{ApiError, AppState};

const USER_AGENT: &str = concat!("blahd/", env!("CARGO_PKG_VERSION"));

/// Max domain length is limited by TLS certificate CommonName `ub-common-name`,
/// which is 64. Adding the schema and port, it should still be below 80.
/// Ref: https://www.rfc-editor.org/rfc/rfc3280
const MAX_ID_URL_LEN: usize = 80;

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
        }
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

/// Check if the Identity URL is valid under the config.
///
/// We only accept simple HTTPS (and HTTP, if configured) domains. It must not be an IP host and
/// must not have other parts like username, query, and etc.
///
/// Ref: https://docs.rs/url/2.5.2/url/enum.Position.html
/// ```text
/// url =
///    scheme ":"
///    [ "//" [ username [ ":" password ]? "@" ]? host [ ":" port ]? ]?
///    path [ "?" query ]? [ "#" fragment ]?
/// ```
fn is_id_url_valid(config: &Config, url: &Url) -> bool {
    use url::Position;

    url.as_str().len() <= MAX_ID_URL_LEN
        && (url.scheme() == "https" || config.unsafe_allow_id_url_http && url.scheme() == "http")
        && &url[Position::AfterScheme..Position::BeforeHost] == "://"
        && url
            .host()
            .is_some_and(|host| matches!(host, Host::Domain(_)))
        && (config.unsafe_allow_id_url_custom_port || url.port().is_none())
        && &url[Position::BeforePath..] == "/"
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
    if !is_id_url_valid(&st.config.register, &reg.id_url) {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_id_url",
            "invalid identity URL",
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
        let ok = hash[..bytes].iter().all(|&b| b == 0) && hash[bytes] >> (8 - bits) == 0;
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
                "failed to fetch identity description from domain {}: {}",
                reg.id_url,
                err,
            ))
        }
    };

    if let Err(err) = validate_id_desc(&reg.id_url, &reg.id_key, &id_desc, fetch_time) {
        return Err(error_response!(
            StatusCode::UNAUTHORIZED,
            "invalid_id_description",
            "{err}",
        ));
    }

    // Now the identity is verified.

    let id_desc_json = serde_jcs::to_string(&id_desc).expect("serialization cannot fail");

    let mut conn = st.db.get();
    let txn = conn.transaction()?;
    let uid = txn
        .query_row(
            r"
            INSERT INTO `user` (`userkey`, `last_fetch_time`, `id_desc`)
            VALUES (:id_key, :last_fetch_time, :id_desc)
            ON CONFLICT (`userkey`) DO UPDATE SET
                `last_fetch_time` = :last_fetch_time,
                `id_desc` = :id_desc
            WHERE `last_fetch_time` < :last_fetch_time
            RETURNING `uid`
            ",
            named_params! {
                ":id_key": reg.id_key,
                ":id_desc": id_desc_json,
                ":last_fetch_time": fetch_time,
            },
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| {
            error_response!(
                StatusCode::CONFLICT,
                "conflict",
                "racing register, please try again later",
            )
        })?;
    {
        txn.execute(
            r"
            DELETE FROM `user_act_key`
            WHERE `uid` = ?
            ",
            params![uid],
        )?;
        let mut stmt = txn.prepare(
            r"
            INSERT INTO `user_act_key` (`uid`, `act_key`, `expire_time`)
            VALUES (:uid, :act_key, :expire_time)
            ",
        )?;
        for kdesc in &id_desc.act_keys {
            stmt.execute(named_params! {
                ":uid": uid,
                ":act_key": kdesc.signee.payload.act_key,
                // FIXME: Other `u64` that will be stored in database should also be range checked.
                ":expire_time": kdesc.signee.payload.expire_time.min(i64::MAX as _),
            })?;
        }
    }
    txn.commit()?;

    Ok(StatusCode::NO_CONTENT)
}

fn validate_id_desc(
    id_url: &Url,
    id_key: &UserKey,
    id_desc: &UserIdentityDesc,
    now: u64,
) -> anyhow::Result<()> {
    ensure!(*id_key == id_desc.id_key, "id_key mismatch");

    let profile_signing_key = &id_desc.profile.signee.user;
    let mut profile_signed = false;

    for (i, act_key) in id_desc.act_keys.iter().enumerate() {
        let kdesc = &act_key.signee.payload;
        (|| {
            ensure!(act_key.signee.user == *id_key, "not signed by id_key");
            act_key.verify().context("signature verification failed")?;
            if now < kdesc.expire_time && *profile_signing_key == kdesc.act_key {
                profile_signed = true;
            }
            Ok(())
        })()
        .with_context(|| format!("in act_key {} {}", i, kdesc.act_key))?;
    }

    ensure!(profile_signed, "profile is not signed by valid act_keys");
    id_desc
        .profile
        .verify()
        .context("profile signature verification failed")?;
    ensure!(
        id_desc.profile.signee.payload.id_urls == std::slice::from_ref(id_url),
        "id_url list must consists of a single matching id_url",
    );
    Ok(())
}
