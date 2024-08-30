//! NB. All structs here that are part of signee must be lexically sorted, as RFC8785.
//! This is tested by `canonical_fields_sorted`.
//! See: https://www.rfc-editor.org/rfc/rfc8785
//! FIXME: `typ` is still always the first field because of `serde`'s implementation.
use std::fmt;
use std::time::SystemTime;

use anyhow::{ensure, Context};
use bitflags::bitflags;
use bitflags_serde_shim::impl_serde_for_bitflags;
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand_core::RngCore;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

const TIMESTAMP_TOLERENCE: u64 = 90;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(with = "hex::serde")]
    pub sig: [u8; SIGNATURE_LENGTH],
    pub signee: Signee<T>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signee<T> {
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
    pub rich_text: RichText,
    pub room: Uuid,
}

/// Ref: <https://github.com/Blah-IM/Weblah/blob/a3fa0f265af54c846f8d65f42aa4409c8dba9dd9/src/lib/richText.ts>
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RichText(pub Vec<RichTextPiece>);

#[derive(Debug, PartialEq, Eq)]
pub struct RichTextPiece {
    pub attrs: TextAttrs,
    pub text: String,
}

impl Serialize for RichTextPiece {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if is_default(&self.attrs) {
            self.text.serialize(ser)
        } else {
            (&self.text, &self.attrs).serialize(ser)
        }
    }
}

/// The protocol representation of `RichTextPiece`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RichTextPieceRaw {
    Text(String),
    TextWithAttrs(String, TextAttrs),
}

fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

impl<'de> Deserialize<'de> for RichText {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let pieces = <Vec<RichTextPieceRaw>>::deserialize(de)?;
        if pieces
            .iter()
            .any(|p| matches!(&p, RichTextPieceRaw::TextWithAttrs(_, attrs) if is_default(attrs)))
        {
            return Err(de::Error::custom("not in canonical form"));
        }
        let this = Self(
            pieces
                .into_iter()
                .map(|raw| {
                    let (text, attrs) = match raw {
                        RichTextPieceRaw::Text(text) => (text, TextAttrs::default()),
                        RichTextPieceRaw::TextWithAttrs(text, attrs) => (text, attrs),
                    };
                    RichTextPiece { text, attrs }
                })
                .collect(),
        );
        if !this.is_canonical() {
            return Err(de::Error::custom("not in canonical form"));
        }
        Ok(this)
    }
}

// TODO: This protocol format is quite large. Could use bitflags for database.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextAttrs {
    #[serde(default, rename = "b", skip_serializing_if = "is_default")]
    pub bold: bool,
    #[serde(default, rename = "m", skip_serializing_if = "is_default")]
    pub code: bool,
    #[serde(default, skip_serializing_if = "is_default")]
    pub hashtag: bool,
    #[serde(default, rename = "i", skip_serializing_if = "is_default")]
    pub italic: bool,
    // TODO: Should we validate and/or filter the URL.
    #[serde(default, skip_serializing_if = "is_default")]
    pub link: Option<String>,
    #[serde(default, rename = "s", skip_serializing_if = "is_default")]
    pub strike: bool,
    #[serde(default, rename = "u", skip_serializing_if = "is_default")]
    pub underline: bool,
}

impl From<&'_ str> for RichText {
    fn from(text: &'_ str) -> Self {
        text.to_owned().into()
    }
}

impl From<String> for RichText {
    fn from(text: String) -> Self {
        if text.is_empty() {
            Self::default()
        } else {
            Self(vec![RichTextPiece {
                text,
                attrs: TextAttrs::default(),
            }])
        }
    }
}

impl From<&'_ str> for RichTextPiece {
    fn from(text: &'_ str) -> Self {
        text.to_owned().into()
    }
}

impl From<String> for RichTextPiece {
    fn from(text: String) -> Self {
        Self {
            text,
            attrs: TextAttrs::default(),
        }
    }
}

impl RichText {
    /// Is this rich text valid and in the canonical form?
    ///
    /// This is automatically enforced by `Deserialize` impl.
    pub fn is_canonical(&self) -> bool {
        self.0.iter().all(|p| !p.text.is_empty())
            && self.0.windows(2).all(|w| w[0].attrs != w[1].attrs)
    }

    /// Format the text into plain text, stripping all styles.
    pub fn plain_text(&self) -> impl fmt::Display + '_ {
        struct Fmt<'a>(&'a RichText);
        impl fmt::Display for Fmt<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for p in &self.0 .0 {
                    f.write_str(&p.text)?;
                }
                Ok(())
            }
        }

        Fmt(self)
    }

    /// Format the text into HTML.
    pub fn html(&self) -> impl fmt::Display + '_ {
        struct Fmt<'a>(&'a RichText);
        impl fmt::Display for Fmt<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for p in &self.0 .0 {
                    let tags = [
                        (p.attrs.bold, "<b>", "</b>"),
                        (p.attrs.code, "<code>", "</code>"),
                        (p.attrs.italic, "<i>", "</i>"),
                        (p.attrs.strike, "<strike>", "</strike>"),
                        (p.attrs.underline, "<u>", "</u>"),
                        (p.attrs.hashtag || p.attrs.link.is_some(), "", "</a>"),
                    ];
                    for (cond, begin, _) in tags {
                        if cond {
                            f.write_str(begin)?;
                        }
                    }
                    if p.attrs.hashtag {
                        // TODO: Link target for hashtag?
                        write!(f, r#"<a class="hashtag">"#)?;
                    } else if let Some(link) = &p.attrs.link {
                        let href = html_escape::encode_quoted_attribute(link);
                        write!(f, r#"<a target="_blank" href="{href}""#)?;
                        let href = html_escape::encode_quoted_attribute(link);
                        write!(f, r#"<a target="_blank" href="{href}""#)?;
                    }
                    f.write_str(&p.text)?;
                    for (cond, _, end) in tags.iter().rev() {
                        if *cond {
                            f.write_str(end)?;
                        }
                    }
                }
                Ok(())
            }
        }

        Fmt(self)
    }
}

pub type ChatItem = WithSig<ChatPayload>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "typ", rename = "create_room")]
pub struct CreateRoomPayload {
    pub attrs: RoomAttrs,
    /// The initial member list. Besides invariants of `RoomMemberList`, this also must include the
    /// room creator themselves, with the highest permission (-1).
    pub members: RoomMemberList,
    pub title: String,
}

/// A collection of room members, with these invariants:
/// 1. Sorted by userkeys.
/// 2. No duplicated users.
#[derive(Debug, Deserialize)]
#[serde(try_from = "Vec<RoomMember>")]
pub struct RoomMemberList(pub Vec<RoomMember>);

impl Serialize for RoomMemberList {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(ser)
    }
}

impl TryFrom<Vec<RoomMember>> for RoomMemberList {
    type Error = &'static str;

    fn try_from(members: Vec<RoomMember>) -> Result<Self, Self::Error> {
        if members.windows(2).all(|w| w[0].user.0 < w[1].user.0) {
            Ok(Self(members))
        } else {
            Err("unsorted or duplicated users")
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoomMember {
    pub permission: MemberPermission,
    pub user: UserKey,
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
        permission: MemberPermission,
        room: Uuid,
        user: UserKey,
    },
    // TODO: CRUD
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ServerPermission: u64 {
        const CREATE_ROOM = 1 << 0;

        const ALL = !0;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemberPermission: u64 {
        const POST_CHAT = 1 << 0;
        const ADD_MEMBER = 1 << 1;

        const ALL = !0;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct RoomAttrs: u64 {
        const PUBLIC_READABLE = 1 << 0;

        const _ = !0;
    }
}

impl_serde_for_bitflags!(ServerPermission);
impl_serde_for_bitflags!(MemberPermission);
impl_serde_for_bitflags!(RoomAttrs);

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

    impl_u64_flag!(ServerPermission, MemberPermission, RoomAttrs);
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use syn::visit;

    use super::*;

    #[derive(Default)]
    struct Visitor {
        errors: String,
    }

    const SKIP_CHECK_STRUCTS: &[&str] = &["RichTextPiece", "RichTextPieceRaw"];

    impl<'ast> syn::visit::Visit<'ast> for Visitor {
        fn visit_fields_named(&mut self, i: &'ast syn::FieldsNamed) {
            let fields = i
                .named
                .iter()
                .flat_map(|f| f.ident.clone())
                .map(|i| i.to_string())
                .collect::<Vec<_>>();
            if !fields.windows(2).all(|w| w[0] < w[1]) {
                writeln!(self.errors, "unsorted fields: {fields:?}").unwrap();
            }
        }

        fn visit_item_struct(&mut self, i: &'ast syn::ItemStruct) {
            if !SKIP_CHECK_STRUCTS.contains(&&*i.ident.to_string()) {
                visit::visit_item_struct(self, i);
            }
        }
    }

    #[test]
    fn canonical_fields_sorted() {
        let src = std::fs::read_to_string(file!()).unwrap();
        let file = syn::parse_file(&src).unwrap();

        let mut v = Visitor::default();
        syn::visit::visit_file(&mut v, &file);
        if !v.errors.is_empty() {
            panic!("{}", v.errors);
        }
    }

    #[test]
    fn rich_text_serde() {
        let raw = r#"["before ",["bold ",{"b":true}],["italic bold ",{"b":true,"i":true}],"end"]"#;
        let text = serde_json::from_str::<RichText>(raw).unwrap();
        assert!(text.is_canonical());
        assert_eq!(
            text,
            RichText(vec![
                "before ".into(),
                RichTextPiece {
                    text: "bold ".into(),
                    attrs: TextAttrs {
                        bold: true,
                        ..TextAttrs::default()
                    }
                },
                RichTextPiece {
                    text: "italic bold ".into(),
                    attrs: TextAttrs {
                        italic: true,
                        bold: true,
                        ..TextAttrs::default()
                    }
                },
                "end".into(),
            ]),
        );
        let got = serde_json::to_string(&text).unwrap();
        assert_eq!(got, raw);
    }
}
