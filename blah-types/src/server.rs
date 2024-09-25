//! Data types and constants for Chat Server interaction.

use serde::{Deserialize, Serialize};

use crate::msg::{Id, MemberPermission, RoomAttrs, SignedChatMsgWithId};
use crate::PubKey;

pub const X_BLAH_NONCE: &str = "x-blah-nonce";
pub const X_BLAH_DIFFICULTY: &str = "x-blah-difficulty";

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
