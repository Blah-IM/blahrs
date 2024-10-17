//! Data types and constants for Chat Server interaction.

use std::fmt;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::msg::{Id, MemberPermission, RoomAttrs, SignedChatMsgWithId};
use crate::PubKey;

/// The response object returned as body on HTTP error status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct ErrorResponse<S = String> {
    /// The error object.
    pub error: ErrorObject<S>,
}

/// The response object of `/_blah/user/me` endpoint on HTTP error status.
/// It contains additional registration information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct ErrorResponseWithChallenge<S = String> {
    /// The error object.
    pub error: ErrorObject<S>,

    /// The challenge metadata returned by the `/_blah/user/me` endpoint for registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_challenge: Option<UserRegisterChallenge>,
}

/// The error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct ErrorObject<S = String> {
    /// A machine-readable error code string.
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub code: S,

    /// A human-readable error message.
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub message: S,
}

impl<S: fmt::Display> fmt::Display for ErrorObject<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "api error ({}): {}", self.code, self.message)
    }
}

impl<S: fmt::Display + fmt::Debug> std::error::Error for ErrorObject<S> {}

/// Metadata about the version and capabilities of a Chat Server.
///
/// It should be relatively stable and do not change very often.
/// It may contains extra fields and clients should ignore them for future compatibility.
/// Chat Servers can also include any custom fields here as long they have a `_` prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct ServerMetadata {
    /// A server-defined version string indicating its implementation name and the version.
    ///
    /// It is expected to be in form `<server-name>/<server-version>` but not mandatory.
    pub server: String,

    /// The URL to the source code of the Chat Server.
    ///
    /// It is expected to be a public accessible maybe-compressed tarball link without
    /// access control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_url: Option<Url>,

    /// The server capabilities set.
    pub capabilities: ServerCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct ServerCapabilities {
    /// Whether registration is open to public.
    pub allow_public_register: bool,
}

/// Registration challenge information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum UserRegisterChallenge {
    /// Proof-of-work (PoW) challenge.
    Pow { nonce: u32, difficulty: u8 },

    /// A catch-all unknown challenge type.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// Response to list rooms.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct RoomList {
    /// Result list of rooms.
    pub rooms: Vec<RoomMetadata>,
    /// The skip-token to fetch the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_token: Option<Id>,
}

/// The metadata of a room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
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
    pub last_msg: Option<SignedChatMsgWithId>,
    /// The current user's last seen message's `cid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_cid: Option<Id>,
    /// The number of unseen messages, ie. the number of messages from `last_seen_cid` to
    /// `last_msg.cid`.
    /// This may or may not be a precise number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unseen_cnt: Option<u32>,
    /// The member permission of current user in the room, or `None` if it is not a member.
    /// Only available with authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_permission: Option<MemberPermission>,
    /// The peer user, if this is a peer chat room.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_user: Option<PubKey>,
}

/// Response to list room msgs.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct RoomMsgs {
    /// Result list of msgs ordered in reverse of server-received time.
    pub msgs: Vec<SignedChatMsgWithId>,
    /// The skip-token to fetch the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_token: Option<Id>,
}

/// Response to list room members.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct RoomMemberList {
    /// Result list of members.
    pub members: Vec<RoomMember>,
    /// The skip-token to fetch the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_token: Option<Id>,
}

/// The description of a room member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct RoomMember {
    /// The identity key of the member user.
    pub id_key: PubKey,
    /// The user permission in the room.
    pub permission: MemberPermission,
    /// The user's last seen message `cid` in the room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_cid: Option<Id>,
}

/// A server-to-client event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ServerEvent {
    /// A message from a joined room.
    Msg(SignedChatMsgWithId),
    /// The receiver is too slow to receive and some events and are dropped.
    // FIXME: Should we indefinitely buffer them or just disconnect the client instead?
    Lagged,
}

/// A client-to-server event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ClientEvent {}
