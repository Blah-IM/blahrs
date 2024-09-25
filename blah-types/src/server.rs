//! Data types and constants for Chat Server interaction.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::msg::{Id, MemberPermission, RoomAttrs, SignedChatMsgWithId};
use crate::PubKey;

pub const X_BLAH_NONCE: &str = "x-blah-nonce";
pub const X_BLAH_DIFFICULTY: &str = "x-blah-difficulty";

/// Metadata about the version and capabilities of a Chat Server.
///
/// It should be relatively stable and do not change very often.
/// It may contains extra fields and clients should ignore them for future compatibility.
/// Chat Servers can also include any custom fields here as long they have a `_` prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerMetadata {
    /// A server-defined version string indicating its implementation name and the version.
    ///
    /// It is expected to be in form `<server-name>/<server-version>` but not mandatory.
    pub server: String,

    /// The URL to the source code of the Chat Server.
    ///
    /// It is expected to be a public accessible maybe-compressed tarball link without
    /// access control.
    pub src_url: Option<Url>,

    /// The server capabilities set.
    pub capabilities: ServerCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Whether registration is open to public.
    pub allow_public_register: bool,
}

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
