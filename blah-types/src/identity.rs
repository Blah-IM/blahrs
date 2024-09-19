use core::fmt;
use std::ops;
use std::str::FromStr;

use ed25519_dalek::SignatureError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{Host, Position, Url};

use crate::{PubKey, Signed};

/// User identity description structure.
// TODO: Revise and shrink duplicates (pubkey fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserIdentityDesc {
    /// User primary identity key, only for signing action keys.
    pub id_key: PubKey,
    /// User action subkeys, signed by the identity key.
    pub act_keys: Vec<Signed<UserActKeyDesc>>,
    /// User profile, signed by any valid action key.
    pub profile: Signed<UserProfile>,
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct VerfiyError(#[from] VerifyErrorImpl);

#[derive(Debug, Error)]
enum VerifyErrorImpl {
    #[error("profile id_key mismatch")]
    ProfileIdKeyMismatch,
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
    pub const WELL_KNOWN_PATH: &str = "/.well-known/blah/identity.json";

    /// Validate signatures of the identity description at given time.
    pub fn verify(&self, id_url: Option<&IdUrl>, now_timestamp: u64) -> Result<(), VerfiyError> {
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
        if let Some(id_url) = id_url {
            if !self.profile.signee.payload.id_urls.contains(id_url) {
                return Err(VerifyErrorImpl::MissingIdUrl.into());
            }
        }
        Ok(())
    }
}

// TODO: JWS or alike?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "typ", rename = "user_act_key")]
pub struct UserActKeyDesc {
    pub act_key: PubKey,
    pub expire_time: u64,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "typ", rename = "user_profile")]
pub struct UserProfile {
    pub preferred_chat_server_urls: Vec<Url>,
    pub id_urls: Vec<IdUrl>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Url")]
pub struct IdUrl(Url);

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
    pub const MAX_LEN: usize = 80;
}

impl ops::Deref for IdUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum IdUrlError {
    #[error(transparent)]
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
    use super::*;

    #[test]
    fn parse_id_url() {
        let parse = <str>::parse::<IdUrl>;

        assert!(matches!(
            parse("not-a-url").unwrap_err(),
            IdUrlError::ParseUrl(_)
        ));

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
}
