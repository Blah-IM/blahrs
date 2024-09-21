use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

use bitflags_serde_shim::impl_serde_for_bitflags;
use ed25519_dalek::{
    Signature, SignatureError, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use identity::IdUrl;
use rand_core::RngCore;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, DisplayFromStr};
use url::Url;

// Re-export of public dependencies.
pub use bitflags;
pub use ed25519_dalek;
pub use url;

pub mod identity;

pub const X_BLAH_NONCE: &str = "x-blah-nonce";
pub const X_BLAH_DIFFICULTY: &str = "x-blah-difficulty";

/// An opaque server-specific ID for rooms, messages, and etc.
/// It's currently serialized as a string for JavaScript's convenience.
#[serde_as]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id(#[serde_as(as = "DisplayFromStr")] pub i64);

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Id {
    pub const MIN: Self = Id(i64::MIN);
    pub const MAX: Self = Id(i64::MAX);
    pub const INVALID: Self = Self::MAX;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithMsgId<T> {
    pub cid: Id,
    #[serde(flatten)]
    pub msg: T,
}

impl<T> WithMsgId<T> {
    pub fn new(cid: Id, msg: T) -> Self {
        Self { cid, msg }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserKey {
    pub id_key: PubKey,
    pub act_key: PubKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PubKey(#[serde(with = "hex::serde")] pub [u8; PUBLIC_KEY_LENGTH]);

impl FromStr for PubKey {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::FromHex::from_hex(s).map(Self)
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH * 2];
        hex::encode_to_slice(self.0, &mut buf).expect("buf size is correct");
        f.write_str(std::str::from_utf8(&buf).expect("hex must be UTF-8"))
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
                act_key: PubKey(act_key.verifying_key().to_bytes()),
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

/// Register a user on a chat server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "typ", rename = "user_register")]
pub struct UserRegisterPayload {
    pub server_url: Url,
    pub id_url: IdUrl,
    pub id_key: PubKey,
    pub challenge_nonce: u32,
}

// FIXME: `deny_unknown_fields` breaks this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "typ", rename = "chat")]
pub struct ChatPayload {
    pub rich_text: RichText,
    pub room: Id,
}

/// Ref: <https://github.com/Blah-IM/Weblah/blob/a3fa0f265af54c846f8d65f42aa4409c8dba9dd9/src/lib/richText.ts>
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RichText(pub Vec<RichTextPiece>);

#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

pub type SignedChatMsg = Signed<ChatPayload>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomMetadata {
    /// Room id.
    pub rid: Id,
    /// Plain text room title. None for peer chat.
    pub title: Option<String>,
    /// Room attributes.
    pub attrs: RoomAttrs,

    // Extra information is only available for some APIs.
    /// The last message in the room.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_msg: Option<WithMsgId<SignedChatMsg>>,
    /// The current user's last seen message's `cid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_cid: Option<Id>,
    /// The number of unseen messages, ie. the number of messages from `last_seen_cid` to
    /// `last_msg.cid`.
    /// This may or may not be a precise number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unseen_cnt: Option<u64>,
    /// The member permission of current user in the room, or `None` if it is not a member.
    /// Only available with authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_permission: Option<MemberPermission>,
    /// The peer user, if this is a peer chat room.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_user: Option<PubKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "typ")]
pub enum CreateRoomPayload {
    #[serde(rename = "create_room")]
    Group(CreateGroup),
    #[serde(rename = "create_peer_chat")]
    PeerChat(CreatePeerChat),
}

/// Multi-user room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateGroup {
    pub attrs: RoomAttrs,
    pub title: String,
}

/// Peer-to-peer chat room with exactly two symmetric users.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePeerChat {
    pub peer: PubKey,
}

/// A collection of room members, with these invariants:
/// 1. Sorted by userkeys.
/// 2. No duplicated users.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomMember {
    pub permission: MemberPermission,
    pub user: PubKey,
}

/// Proof of room membership for read-access.
///
/// TODO: Should we use JWT here instead?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "typ", rename = "auth")]
pub struct AuthPayload {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// `typ` is provided by `RoomAdminOp`.
pub struct RoomAdminPayload {
    pub room: Id,
    #[serde(flatten)]
    pub op: RoomAdminOp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "typ", rename_all = "snake_case")]
pub enum RoomAdminOp {
    AddMember {
        permission: MemberPermission,
        user: PubKey,
    },
    RemoveMember {
        user: PubKey,
    },
    // TODO: RU
}

bitflags::bitflags! {
    /// TODO: Is this a really all about permission, or is a generic `UserFlags`?
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ServerPermission: u64 {
        const CREATE_ROOM = 1 << 0;

        const ACCEPT_PEER_CHAT = 1 << 16;

        const ALL = !0;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemberPermission: u64 {
        const POST_CHAT = 1 << 0;
        const ADD_MEMBER = 1 << 1;

        const MAX_SELF_ADD = Self::POST_CHAT.bits();
        const MAX_PEER_CHAT = Self::POST_CHAT.bits();

        const ALL = !0;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct RoomAttrs: u64 {
        // NB. Used by schema.
        const PUBLIC_READABLE = 1 << 0;
        const PUBLIC_JOINABLE = 1 << 1;

        const GROUP_ATTRS = (1 << 16) - 1;

        // NB. Used by schema.
        const PEER_CHAT = 1 << 16;

        const _ = !0;
    }
}

impl_serde_for_bitflags!(ServerPermission);
impl_serde_for_bitflags!(MemberPermission);
impl_serde_for_bitflags!(RoomAttrs);

#[cfg(feature = "rusqlite")]
mod sql_impl {
    use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef};
    use rusqlite::{Result, ToSql};

    use super::*;

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
            Ok(PubKey(key.to_bytes()))
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
    use expect_test::expect;

    use super::*;

    #[test]
    fn canonical_msg() {
        let mut fake_rng = rand::rngs::mock::StepRng::new(0x42, 1);
        let id_key = SigningKey::from_bytes(&[0x42; 32]);
        let act_key = SigningKey::from_bytes(&[0x43; 32]);
        let timestamp = 0xDEAD_BEEF;
        let msg = ChatPayload {
            rich_text: RichText::from("hello"),
            room: Id(42),
        }
        .sign_msg_with(
            &PubKey(id_key.verifying_key().to_bytes()),
            &act_key,
            timestamp,
            &mut fake_rng,
        )
        .unwrap();

        let json = serde_jcs::to_string(&msg).unwrap();
        let expect = expect![[
            r#"{"sig":"74ca2895ac94e741e086bae28ce8c282bf375e3e59a3408f562420d72e98d799f7e627879aa883fa0804a0799eb9b90398150b0150c2e3550635ff28b9991502","signee":{"act_key":"22fc297792f0b6ffc0bfcfdb7edb0c0aa14e025a365ec0e342e86e3829cb74b6","id_key":"2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12","nonce":66,"payload":{"rich_text":["hello"],"room":"42","typ":"chat"},"timestamp":3735928559}}"#
        ]];
        expect.assert_eq(&json);

        let roundtrip_msg = serde_json::from_str::<Signed<ChatPayload>>(&json).unwrap();
        assert_eq!(roundtrip_msg, msg);
        roundtrip_msg.verify().unwrap();
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

    #[test]
    fn room_admin_serde() {
        let data = RoomAdminPayload {
            room: Id(42),
            op: RoomAdminOp::AddMember {
                permission: MemberPermission::POST_CHAT,
                user: PubKey([0x42; PUBLIC_KEY_LENGTH]),
            },
        };
        let raw = serde_jcs::to_string(&data).unwrap();

        let expect = expect![[
            r#"{"permission":1,"room":"42","typ":"add_member","user":"4242424242424242424242424242424242424242424242424242424242424242"}"#
        ]];
        expect.assert_eq(&raw);
        let roundtrip = serde_json::from_str::<RoomAdminPayload>(&raw).unwrap();
        assert_eq!(roundtrip, data);
    }
}
