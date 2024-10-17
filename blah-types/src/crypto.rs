//! Cryptographic operations and types for user signatures.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{
    Signature, SignatureError, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// User pubkey pair to uniquely identity a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserKey {
    /// The identity key (`id_key`).
    pub id_key: PubKey,
    /// The action key (`act_key`).
    pub act_key: PubKey,
}

/// Raw Ed25519 public key, serialized in hex-encoded string.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PubKey(#[serde(with = "hex::serde")] pub [u8; PUBLIC_KEY_LENGTH]);

impl FromStr for PubKey {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::FromHex::from_hex(s).map(Self)
    }
}

impl fmt::Debug for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PubKey").field(&self.to_string()).finish()
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH * 2];
        hex::encode_to_slice(self.0, &mut buf).expect("buf size is correct");
        f.write_str(std::str::from_utf8(&buf).expect("hex must be UTF-8"))
    }
}

impl From<VerifyingKey> for PubKey {
    fn from(vk: VerifyingKey) -> Self {
        Self(vk.to_bytes())
    }
}

impl From<&VerifyingKey> for PubKey {
    fn from(vk: &VerifyingKey) -> Self {
        Self(vk.to_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    #[serde(with = "hex::serde")]
    pub sig: [u8; SIGNATURE_LENGTH],
    pub signee: Signee<T>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signee<T> {
    pub nonce: u32,
    pub payload: T,
    pub timestamp: u64,
    #[serde(flatten)]
    pub user: UserKey,
}

pub trait SignExt: Sized {
    fn sign_msg_with(
        self,
        id_key: &PubKey,
        act_key: &SigningKey,
        timestamp: u64,
        rng: &mut (impl RngCore + ?Sized),
    ) -> Result<Signed<Self>, SignatureError>;

    fn sign_msg(
        self,
        id_key: &PubKey,
        act_key: &SigningKey,
    ) -> Result<Signed<Self>, SignatureError> {
        self.sign_msg_with(id_key, act_key, get_timestamp(), &mut rand::thread_rng())
    }
}

impl<T: Serialize> SignExt for T {
    fn sign_msg_with(
        self,
        id_key: &PubKey,
        act_key: &SigningKey,
        timestamp: u64,
        rng: &mut (impl RngCore + ?Sized),
    ) -> Result<Signed<Self>, SignatureError> {
        Signed::new(id_key, act_key, timestamp, rng, self)
    }
}

pub fn get_timestamp() -> u64 {
    #[cfg(not(feature = "unsafe_use_mock_instant_for_testing"))]
    use std::time::SystemTime;

    #[cfg(feature = "unsafe_use_mock_instant_for_testing")]
    use mock_instant::thread_local::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("after UNIX epoch")
        .as_secs()
}

impl<T: Serialize> Signed<T> {
    /// Get the canonically serialized signee bytes.
    pub fn canonical_signee(&self) -> Vec<u8> {
        serde_jcs::to_vec(&self.signee).expect("serialization cannot fail")
    }

    /// Sign the payload with the given `key`.
    ///
    /// This operation only fail when serialization of `payload` fails.
    pub fn new(
        id_key: &PubKey,
        act_key: &SigningKey,
        timestamp: u64,
        rng: &mut (impl RngCore + ?Sized),
        payload: T,
    ) -> Result<Self, SignatureError> {
        let signee = Signee {
            nonce: rng.next_u32(),
            payload,
            timestamp,
            user: UserKey {
                act_key: act_key.verifying_key().into(),
                id_key: id_key.clone(),
            },
        };
        let canonical_signee = serde_jcs::to_vec(&signee).map_err(|_| SignatureError::new())?;
        let sig = act_key.sign(&canonical_signee).to_bytes();

        Ok(Self { sig, signee })
    }

    /// Verify `sig` is valid for `signee`.
    ///
    /// Note that this does not check validity of timestamp and other data.
    pub fn verify(&self) -> Result<(), SignatureError> {
        VerifyingKey::from_bytes(&self.signee.user.act_key.0)?
            .verify_strict(&self.canonical_signee(), &Signature::from_bytes(&self.sig))?;
        Ok(())
    }
}
