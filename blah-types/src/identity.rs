//! User identity description.
use std::str::FromStr;
use std::{fmt, ops};

use ed25519_dalek::SignatureError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{Host, Position, Url};

use crate::{PubKey, Signed};

/// User identity description structure.
// TODO: Revise and shrink duplicates (pubkey fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct UserIdentityDesc {
    /// User primary identity key, only for signing action keys.
    pub id_key: PubKey,
    /// User action subkeys, signed by the identity key.
    pub act_keys: Vec<Signed<UserActKeyDesc>>,
    /// User profile, signed by any valid action key.
    pub profile: Signed<UserProfile>,
}

/// Error on verifying [`UserIdentityDesc`].
#[derive(Debug, Error)]
#[error(transparent)]
pub struct VerifyError(#[from] VerifyErrorImpl);

#[derive(Debug, Error)]
enum VerifyErrorImpl {
    #[error("profile id_key mismatch")]
    ProfileIdKeyMismatch,
    #[error("act_key[{0}] has invalid expiring timestamp")]
    ActKeyTimestamp(usize),
    #[error("act_key[{0}] not signed by id_key")]
    ActKeySigner(usize),
    #[error("invalid act_key[{0}] signature: {1}")]
    ActKeySignature(usize, SignatureError),
    #[error("profile is not signed by any valid act_key")]
    ProfileSigner,
    #[error("invalid profile signature: {0}")]
    ProfileSignature(SignatureError),
    #[error("id_url is not in the valid list")]
    MissingIdUrl,
}

impl UserIdentityDesc {
    /// The relative path from domain to the well-known identity description file.
    pub const WELL_KNOWN_PATH: &str = "/.well-known/blah/identity.json";

    /// Validate signatures of the identity description at given time.
    pub fn verify(&self, id_url: Option<&IdUrl>, now_timestamp: u64) -> Result<(), VerifyError> {
        if let Some(id_url) = id_url {
            if !self.profile.signee.payload.id_urls.contains(id_url) {
                return Err(VerifyErrorImpl::MissingIdUrl.into());
            }
        }
        if self.id_key != self.profile.signee.user.id_key {
            return Err(VerifyErrorImpl::ProfileIdKeyMismatch.into());
        }

        let profile_signing_key = &self.profile.signee.user.act_key;
        let mut profile_signed = false;

        for (i, signed_kdesc) in self.act_keys.iter().enumerate() {
            let kdesc = &signed_kdesc.signee.payload;
            // act_key itself is signed by id_key, so both are id_key here.
            if signed_kdesc.signee.user.id_key != self.id_key
                || signed_kdesc.signee.user.act_key != self.id_key
            {
                return Err(VerifyErrorImpl::ActKeySigner(i).into());
            }
            if i64::try_from(kdesc.expire_time).is_err() {
                return Err(VerifyErrorImpl::ActKeyTimestamp(i).into());
            }
            signed_kdesc
                .verify()
                .map_err(|err| VerifyErrorImpl::ActKeySignature(i, err))?;
            if now_timestamp < kdesc.expire_time && *profile_signing_key == kdesc.act_key {
                profile_signed = true;
            }
        }

        if !profile_signed {
            return Err(VerifyErrorImpl::ProfileSigner.into());
        }
        self.profile
            .verify()
            .map_err(VerifyErrorImpl::ProfileSignature)?;
        Ok(())
    }
}

/// Description of an action key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "typ", rename = "user_act_key")]
pub struct UserActKeyDesc {
    /// Per-device action key for signing msgs.
    pub act_key: PubKey,
    /// The UNIX timestamp of expire time.
    pub expire_time: u64,
    /// User-provided arbitrary comment string.
    pub comment: String,
}

/// User profile describing their non-cryptographic metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "typ", rename = "user_profile")]
pub struct UserProfile {
    /// Preferred chat servers ordered by decreasing preference, for starting private chats.
    pub preferred_chat_server_urls: Vec<Url>,
    /// Allowed identity URLs (`id_url`) where this profile should be retrieved on.
    pub id_urls: Vec<IdUrl>,
}

/// Identity URL.
///
/// In short, it must be a valid URL in format `https?://some.domain.name(:\d+)?/`.
/// Servers may pose additional requirement including: requiring HTTPS, rejecting ports,
/// rejecting `localhost` or local hostnames, and etc.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Url")]
pub struct IdUrl(Url);

impl_json_schema_as!(IdUrl => Url);

impl fmt::Display for IdUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for IdUrl {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(ser)
    }
}

impl IdUrl {
    /// Max domain length is limited by TLS certificate CommonName `ub-common-name`,
    /// which is 64. Adding the schema and port, it should still be below 80.
    ///
    /// Ref: <https://www.rfc-editor.org/rfc/rfc3280>
    // TODO: IPFS URLs can be extensively long, should we keep this limit?
    pub const MAX_LEN: usize = 80;
}

impl ops::Deref for IdUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Error on validating [`IdUrl`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum IdUrlError {
    #[error("invalid id-URL: {0}")]
    ParseUrl(#[from] url::ParseError),
    #[error("id-URL too long")]
    TooLong,
    #[error("id-URL scheme must be https or http")]
    InvalidScheme,
    #[error("id-URL must not have username or password")]
    HasAuth,
    #[error("id-URL host must not be an IP")]
    InvalidHost,
    #[error("id-URL must has root path `/` without query or fragment")]
    InvalidPath,
}

impl TryFrom<Url> for IdUrl {
    type Error = IdUrlError;

    /// Validate identity URL.
    ///
    /// We only accept simple HTTPS (and HTTP, if configured) domains. It must not be an IP host
    /// and must not have other parts like username, query, and etc.
    fn try_from(url: Url) -> Result<Self, Self::Error> {
        // ```text
        // url =
        //    scheme ":"
        //    [ "//" [ username [ ":" password ]? "@" ]? host [ ":" port ]? ]?
        //    path [ "?" query ]? [ "#" fragment ]?
        // ```
        if url.as_str().len() > Self::MAX_LEN {
            return Err(IdUrlError::TooLong);
        }
        if !["https", "http"].contains(&url.scheme()) {
            return Err(IdUrlError::InvalidScheme);
        }
        if &url[Position::AfterScheme..Position::BeforeHost] != "://" {
            return Err(IdUrlError::HasAuth);
        }
        if !url
            .host()
            .is_some_and(|host| matches!(host, Host::Domain(_)))
        {
            return Err(IdUrlError::InvalidHost);
        }
        if &url[Position::BeforePath..] != "/" {
            return Err(IdUrlError::InvalidPath);
        }
        Ok(Self(url))
    }
}

impl FromStr for IdUrl {
    type Err = IdUrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s)?.try_into()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use crate::SignExt;

    use super::*;

    #[test]
    fn parse_id_url() {
        let parse = <str>::parse::<IdUrl>;

        // Error message.
        assert_eq!(
            parse("not-a-url").unwrap_err().to_string(),
            "invalid id-URL: relative URL without a base",
        );

        macro_rules! check_err {
            ($($s:expr, $err:expr;)*) => {
                $(
                    assert_eq!(parse(&$s), Err($err));
                )*
            };
        }

        check_err! {
            format!("https://{}.com/", "a".repeat(IdUrl::MAX_LEN)), IdUrlError::TooLong;
            "file:///etc/passwd", IdUrlError::InvalidScheme;

            "https://user@example.com/", IdUrlError::HasAuth;
            "https://user:passwd@example.com/", IdUrlError::HasAuth;
            "https://:passwd@example.com/", IdUrlError::HasAuth;

            "https://[::1]/", IdUrlError::InvalidHost;
            "https://127.0.0.1/", IdUrlError::InvalidHost;

            "https://example.com/path", IdUrlError::InvalidPath;
            "https://example.com//", IdUrlError::InvalidPath;
            "https://example.com/?query", IdUrlError::InvalidPath;
            "https://example.com/#hash", IdUrlError::InvalidPath;
            "https://example.com?query", IdUrlError::InvalidPath;
            "https://example.com#hash", IdUrlError::InvalidPath;
        }

        // Auto normalized.
        let expect = parse("https://example.com/").unwrap();
        assert_eq!(parse("https://example.com").unwrap(), expect);
        assert_eq!(parse("https://:@example.com").unwrap(), expect);
    }

    #[test]
    fn id_desc_verify() {
        const TIMESTAMP: u64 = 42;

        let rng = &mut rand::rngs::mock::StepRng::new(42, 1);
        let id_url = "https://example.com".parse::<IdUrl>().unwrap();
        let id_priv = SigningKey::from_bytes(&[42; 32]);
        let id_key = PubKey::from(id_priv.verifying_key());
        let mut id_desc = UserIdentityDesc {
            id_key: id_key.clone(),
            act_keys: Vec::new(),
            profile: UserProfile {
                preferred_chat_server_urls: Vec::new(),
                id_urls: vec![id_url],
            }
            .sign_msg_with(&id_key, &id_priv, TIMESTAMP, rng)
            .unwrap(),
        };

        macro_rules! assert_err {
            ($ret:expr, $pat:pat $(,)?) => {{
                let err: VerifyError = $ret.unwrap_err();
                assert!(
                    matches!(err.0, $pat),
                    "unexpected result, got: {err:?}, expect: {}",
                    stringify!($pat),
                )
            }};
        }

        // Mismatch.
        assert_err!(
            id_desc.verify(Some(&"https://not-example.com".parse().unwrap()), TIMESTAMP),
            VerifyErrorImpl::MissingIdUrl,
        );
        assert_err!(
            id_desc.verify(None, TIMESTAMP),
            VerifyErrorImpl::ProfileSigner,
        );

        // Ok.
        id_desc.act_keys.push(
            UserActKeyDesc {
                act_key: id_key.clone(),
                expire_time: TIMESTAMP + 1,
                comment: String::new(),
            }
            .sign_msg_with(&id_key, &id_priv, TIMESTAMP, rng)
            .unwrap(),
        );
        id_desc.verify(None, TIMESTAMP).unwrap();

        // Expired.
        assert_err!(
            id_desc.verify(None, TIMESTAMP + 2),
            VerifyErrorImpl::ProfileSigner,
        );

        let act_priv = SigningKey::from_bytes(&[24; 32]);
        let act_pub = PubKey::from(act_priv.verifying_key());
        id_desc.act_keys.push(
            UserActKeyDesc {
                act_key: act_pub.clone(),
                expire_time: TIMESTAMP + 1,
                comment: String::new(),
            }
            // Self-signed.
            .sign_msg_with(&id_key, &act_priv, TIMESTAMP, rng)
            .unwrap(),
        );
        assert_err!(
            id_desc.verify(None, TIMESTAMP),
            VerifyErrorImpl::ActKeySigner(1),
        );

        id_desc.act_keys[1] = UserActKeyDesc {
            act_key: act_pub.clone(),
            expire_time: TIMESTAMP + 1,
            comment: String::new(),
        }
        // Wrong id_key.
        .sign_msg_with(&act_pub, &act_priv, TIMESTAMP, rng)
        .unwrap();
        assert_err!(
            id_desc.verify(None, TIMESTAMP),
            VerifyErrorImpl::ActKeySigner(1),
        );

        // Timestamp overflows i64.
        id_desc.act_keys[1] = UserActKeyDesc {
            act_key: act_pub.clone(),
            expire_time: u64::MAX,
            comment: String::new(),
        }
        .sign_msg_with(&id_key, &id_priv, TIMESTAMP, rng)
        .unwrap();
        assert_err!(
            id_desc.verify(None, TIMESTAMP),
            VerifyErrorImpl::ActKeyTimestamp(1),
        );

        // OK act key.
        id_desc.act_keys[1] = UserActKeyDesc {
            act_key: act_pub.clone(),
            expire_time: TIMESTAMP + 1,
            comment: String::new(),
        }
        .sign_msg_with(&id_key, &id_priv, TIMESTAMP, rng)
        .unwrap();
        id_desc.verify(None, TIMESTAMP).unwrap();

        // Profile id_key mismatch.
        id_desc.profile = id_desc
            .profile
            .signee
            .payload
            .sign_msg(&act_pub, &act_priv)
            .unwrap();
        assert_err!(
            id_desc.verify(None, TIMESTAMP),
            VerifyErrorImpl::ProfileIdKeyMismatch,
        );

        // OK, signed by act key.
        id_desc.profile = id_desc
            .profile
            .signee
            .payload
            .sign_msg(&id_key, &act_priv)
            .unwrap();
        id_desc.verify(None, TIMESTAMP).unwrap();

        // Invalid signature.
        id_desc.profile.sig[0] = 0;
        assert_err!(
            id_desc.verify(None, TIMESTAMP),
            VerifyErrorImpl::ProfileSignature(_),
        );
        id_desc.act_keys[1].sig[0] = 0;
        assert_err!(
            id_desc.verify(None, TIMESTAMP),
            VerifyErrorImpl::ActKeySignature(1, _),
        );

        // Error message.
        assert_eq!(
            id_desc.verify(None, TIMESTAMP).unwrap_err().to_string(),
            "invalid act_key[1] signature: signature error: Verification equation was not satisfied",
        );
    }
}
