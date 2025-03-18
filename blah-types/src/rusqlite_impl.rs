use ed25519_dalek::{PUBLIC_KEY_LENGTH, VerifyingKey};
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef};
use rusqlite::{Result, ToSql};

use crate::msg::{MemberPermission, RichText, RoomAttrs, ServerPermission};
use crate::{Id, PubKey};

impl ToSql for Id {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

impl FromSql for Id {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        i64::column_result(value).map(Self)
    }
}

impl ToSql for PubKey {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        // TODO: Extensive key format?
        self.0.to_sql()
    }
}

impl FromSql for PubKey {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let rawkey = <[u8; PUBLIC_KEY_LENGTH]>::column_result(value)?;
        let key = VerifyingKey::from_bytes(&rawkey)
            .map_err(|err| FromSqlError::Other(format!("invalid pubkey: {err}").into()))?;
        Ok(key.into())
    }
}

impl ToSql for RichText {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        assert!(self.is_canonical());
        let json = serde_json::to_string(&self).expect("serialization cannot fail");
        Ok(json.into())
    }
}

impl FromSql for RichText {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        serde_json::from_str::<Self>(value.as_str()?)
            .map_err(|err| FromSqlError::Other(format!("invalid rich text: {err}").into()))
    }
}

macro_rules! impl_flag_to_from_sql {
    ($($name:ident),*) => {
        $(
            impl ToSql for $name {
                fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
                    Ok(self.bits().into())
                }
            }

            impl FromSql for $name {
                fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
                    i32::column_result(value).map($name::from_bits_retain)
                }
            }
        )*
    };
}

impl_flag_to_from_sql!(ServerPermission, MemberPermission, RoomAttrs);
