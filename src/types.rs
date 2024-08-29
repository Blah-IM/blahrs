use std::fmt;
// NB. All structs here that are part of signee must be lexically sorted, as RFC8785.
use std::time::SystemTime;

use anyhow::{ensure, Context};
use bitflags::bitflags;
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const TIMESTAMP_TOLERENCE: u64 = 90;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserKey(#[serde(with = "hex::serde")] pub [u8; PUBLIC_KEY_LENGTH]);

impl fmt::Display for UserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH * 2];
        hex::encode_to_slice(self.0, &mut buf).unwrap();
        f.write_str(std::str::from_utf8(&buf).unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSig<T> {
    // sorted
    #[serde(with = "hex::serde")]
    pub sig: [u8; SIGNATURE_LENGTH],
    pub signee: Signee<T>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signee<T> {
    // sorted
    pub nonce: u32,
    pub payload: T,
    pub timestamp: u64,
    pub user: UserKey,
}

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("after UNIX epoch")
        .as_secs()
}

impl<T: Serialize> WithSig<T> {
    pub fn sign(key: &SigningKey, rng: &mut impl RngCore, payload: T) -> anyhow::Result<Self> {
        let signee = Signee {
            nonce: rng.next_u32(),
            payload,
            timestamp: get_timestamp(),
            user: UserKey(key.verifying_key().to_bytes()),
        };
        let canonical_signee = serde_json::to_vec(&signee).context("failed to serialize")?;
        let sig = key.try_sign(&canonical_signee)?.to_bytes();
        Ok(Self { sig, signee })
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.signee.timestamp.abs_diff(get_timestamp()) < TIMESTAMP_TOLERENCE,
            "invalid timestamp"
        );

        let canonical_signee = serde_json::to_vec(&self.signee).context("failed to serialize")?;
        let sig = Signature::from_bytes(&self.sig);
        VerifyingKey::from_bytes(&self.signee.user.0)?.verify_strict(&canonical_signee, &sig)?;
        Ok(())
    }
}

// FIXME: `deny_unknown_fields` breaks this.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "typ", rename = "chat")]
pub struct ChatPayload {
    // sorted
    pub room: Uuid,
    pub text: String,
}

pub type ChatItem = WithSig<ChatPayload>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "typ", rename = "create_room")]
pub struct CreateRoomPayload {
    pub title: String,
    pub attrs: RoomAttrs,
}

/// Proof of room membership for read-access.
///
/// TODO: Should we use JWT here instead?
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "typ", rename = "auth")]
pub struct AuthPayload {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "typ", rename_all = "snake_case")]
pub enum RoomAdminPayload {
    AddMember {
        // sorted
        permission: RoomPermission,
        room: Uuid,
        user: UserKey,
    },
    // TODO: CRUD
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ServerPermission: u64 {
        const CREATE_ROOM = 1 << 0;

        const ALL = !0;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RoomPermission: u64 {
        const PUSH_CHAT = 1 << 0;
        const ADD_MEMBER = 1 << 1;

        const ALL = !0;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
    pub struct RoomAttrs: u64 {
        const PUBLIC_READABLE = 1 << 0;

        const _ = !0;
    }
}

mod sql_impl {
    use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef};
    use rusqlite::{Result, ToSql};

    use super::*;

    impl ToSql for UserKey {
        fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
            // TODO: Extensive key format?
            self.0.to_sql()
        }
    }

    impl FromSql for UserKey {
        fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
            let rawkey = <[u8; PUBLIC_KEY_LENGTH]>::column_result(value)?;
            let key = VerifyingKey::from_bytes(&rawkey)
                .map_err(|err| FromSqlError::Other(format!("invalid pubkey: {err}").into()))?;
            Ok(UserKey(key.to_bytes()))
        }
    }

    macro_rules! impl_u64_flag {
        ($($name:ident),*) => {
            $(
                impl ToSql for $name {
                    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
                        // Cast out the sign.
                        Ok((self.bits() as i64).into())
                    }
                }

                impl FromSql for $name {
                    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
                        // Cast out the sign.
                        i64::column_result(value).map(|v| $name::from_bits_retain(v as u64))
                    }
                }
            )*
        };
    }

    impl_u64_flag!(ServerPermission, RoomPermission, RoomAttrs);
}
