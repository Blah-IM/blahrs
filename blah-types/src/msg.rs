//! Core message subtypes.
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use serde::{Deserialize, Serialize, de, ser};
use url::Url;

use crate::identity::IdUrl;
use crate::{PubKey, Signed};

/// An opaque server-specific ID for rooms, messages, and etc.
/// It's currently serialized as a string for JavaScript's convenience.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(pub i64);

impl_json_schema_as!(Id => String);

impl Serialize for Id {
    fn serialize<S: ser::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        // TODO: No alloc?
        self.0.to_string().serialize(ser)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: de::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(de)?;
        s.parse()
            .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(s), &"a stringified integer"))
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Id {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        i64::from_str(s).map(Self)
    }
}

impl Id {
    pub const MIN: Self = Id(i64::MIN);
    pub const MAX: Self = Id(i64::MAX);
    pub const INVALID: Self = Self::MAX;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
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

/// Register a user on a chat server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "typ", rename = "user_register")]
pub struct UserRegisterPayload {
    /// The normalized server URL to register on.
    /// It must matches chat server's base_url.
    pub server_url: Url,
    /// The normalized identity URL.
    /// It should be in form `https://<domain>/`.
    pub id_url: IdUrl,
    /// Hex encoded user primary key (`id_key`).
    pub id_key: PubKey,
    /// Server specific register challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<UserRegisterChallengeResponse>,
}

/// The server-specific challenge data for registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum UserRegisterChallengeResponse {
    /// Proof of work challenge containing the same nonce from server challenge request.
    /// The whole msg signee hash should have enough prefix zero bits.
    Pow {
        /// The challenge nonce retrieved from a recent GET response of `/_blah/user/me`.
        nonce: u32,
    },
}

// FIXME: `deny_unknown_fields` breaks this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "typ", rename = "chat")]
pub struct ChatPayload {
    pub rich_text: RichText,
    pub room: Id,
}

/// Ref: <https://github.com/Blah-IM/Weblah/blob/a3fa0f265af54c846f8d65f42aa4409c8dba9dd9/src/lib/richText.ts>
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RichText(pub Vec<RichTextPiece>);

impl_json_schema_as!(RichText => Vec<RichTextPieceRaw>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichTextPiece {
    pub attrs: TextAttrs,
    pub text: String,
}

impl Serialize for RichTextPiece {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if is_default(&self.attrs) {
            self.text.serialize(ser)
        } else {
            (&self.text, &self.attrs).serialize(ser)
        }
    }
}

/// The representation on wire of `RichTextPiece`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
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
        D: de::Deserializer<'de>,
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
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
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
                for p in &self.0.0 {
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
                for p in &self.0.0 {
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
pub type SignedChatMsgWithId = WithMsgId<SignedChatMsg>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "typ")]
pub enum CreateRoomPayload {
    #[serde(rename = "create_room")]
    Group(CreateGroup),
    #[serde(rename = "create_peer_chat")]
    PeerChat(CreatePeerChat),
}

/// Multi-user room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct CreateGroup {
    pub attrs: RoomAttrs,
    pub title: String,
}

/// Peer-to-peer chat room with exactly two symmetric users.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct CreatePeerChat {
    pub peer: PubKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "typ", rename = "delete_room")]
pub struct DeleteRoomPayload {
    pub room: Id,
}

/// A collection of room members, with these invariants:
/// 1. Sorted by userkeys.
/// 2. No duplicated users.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(try_from = "Vec<RoomMember>")]
pub struct RoomMemberList(pub Vec<RoomMember>);

impl Serialize for RoomMemberList {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
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
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct RoomMember {
    pub permission: MemberPermission,
    pub user: PubKey,
}

/// Proof of room membership for read-access.
///
/// TODO: Should we use JWT here instead?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "typ", rename = "auth")]
pub struct AuthPayload {}

// FIXME: Remove this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
// `typ` is provided by `RoomAdminOp`.
pub struct RoomAdminPayload {
    #[serde(flatten)]
    pub op: RoomAdminOp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "typ", rename_all = "snake_case", rename = "remove_member")]
pub struct RemoveMemberPayload {
    pub room: Id,
    // TODO: This field name collide with `Signee::user`.
    pub user: PubKey,
}

// TODO: Maybe disallow adding other user without consent?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "typ", rename_all = "snake_case", rename = "add_member")]
pub struct AddMemberPayload {
    pub room: Id,
    #[serde(flatten)]
    pub member: RoomMember,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "typ", rename_all = "snake_case", rename = "update_member")]
pub struct UpdateMemberPayload {
    pub room: Id,
    #[serde(flatten)]
    pub member: RoomMember,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum RoomAdminOp {
    AddMember(AddMemberPayload),
    RemoveMember(RemoveMemberPayload),
}

bitflags::bitflags! {
    /// TODO: Is this a really all about permission, or is a generic `UserFlags`?
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ServerPermission: i32 {
        const CREATE_ROOM = 1 << 0;

        const ACCEPT_PEER_CHAT = 1 << 16;

        const ALL = !0;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemberPermission: i32 {
        const POST_CHAT = 1 << 0;
        const ADD_MEMBER = 1 << 1;
        // TODO: Group admin permissions together.
        const DELETE_ROOM = 1 << 2;
        const LIST_MEMBERS = 1 << 3;

        // TODO: Should we have multiple levels of removal permission, so that admins
        // may not remove all other admins?
        const REMOVE_MEMBER = 1 << 4;
        const UPDATE_MEMBER = 1 << 5;

        const MAX_SELF_ADD = Self::POST_CHAT.bits();
        const MAX_PEER_CHAT = Self::POST_CHAT.bits() | Self::DELETE_ROOM.bits() | Self::LIST_MEMBERS.bits();

        const ALL = !0;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct RoomAttrs: i32 {
        // NB. Used by schema.
        const PUBLIC_READABLE = 1 << 0;
        const PUBLIC_JOINABLE = 1 << 1;

        const GROUP_ATTRS = (1 << 16) - 1;

        // NB. Used by schema.
        const PEER_CHAT = 1 << 16;

        const _ = !0;
    }
}

macro_rules! impl_for_bitflags {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Serialize for $ty {
                fn serialize<S: ser::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
                    self.bits().serialize(ser)
                }
            }

            impl<'de> Deserialize<'de> for $ty {
                fn deserialize<D: de::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
                    <_>::deserialize(de).map(Self::from_bits_retain)
                }
            }

            impl_json_schema_as!($ty => <$ty as bitflags::Flags>::Bits);
        )*
    };
}

impl_for_bitflags!(ServerPermission, MemberPermission, RoomAttrs);

#[cfg(test)]
mod tests {
    use AddMemberPayload;
    use ed25519_dalek::{PUBLIC_KEY_LENGTH, SigningKey};
    use expect_test::expect;

    use crate::SignExt;

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
            &id_key.verifying_key().into(),
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
            op: RoomAdminOp::AddMember(AddMemberPayload {
                room: Id(42),
                member: RoomMember {
                    permission: MemberPermission::POST_CHAT,
                    user: PubKey([0x42; PUBLIC_KEY_LENGTH]),
                },
            }),
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
