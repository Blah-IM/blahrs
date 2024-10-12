use std::marker::PhantomData;
use std::num::NonZero;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use axum_extra::extract::WithRejection as R;
use blah_types::msg::{
    AddMemberPayload, ChatPayload, CreateGroup, CreatePeerChat, CreateRoomPayload,
    DeleteRoomPayload, MemberPermission, RemoveMemberPayload, RoomAdminOp, RoomAdminPayload,
    RoomAttrs, ServerPermission, SignedChatMsgWithId, UpdateMemberPayload, WithMsgId,
};
use blah_types::server::{
    ErrorResponseWithChallenge, RoomList, RoomMember, RoomMemberList, RoomMetadata, RoomMsgs,
    ServerCapabilities, ServerMetadata,
};
use blah_types::{get_timestamp, Id, PubKey, Signed, UserKey};
use data_encoding::BASE64_NOPAD;
use database::{Transaction, TransactionOps};
use id::IdExt;
use middleware::{Auth, ETag, MaybeAuth, NoContent, ResultExt as _, SignedJson};
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_inline_default::serde_inline_default;
use sha2::Digest;
use url::Url;
use utils::ExpiringSet;

#[macro_use]
mod middleware;

pub mod config;
mod database;
mod event;
mod feed;
mod id;
mod register;
mod utils;

pub use database::{Config as DatabaseConfig, Database};
pub use middleware::ApiError;

/// The server name and version, for metadata report and user agent.
pub(crate) const SERVER_AND_VERSION: &str = concat!("blahd/", env!("CARGO_PKG_VERSION"));
const SERVER_SRC_URL: Option<&str> = option_env!("CFG_SRC_URL");

const HEADER_PUBLIC_NO_CACHE: (HeaderName, HeaderValue) = (
    header::CACHE_CONTROL,
    HeaderValue::from_static("public, no-cache"),
);
const DEFAULT_CACHE_CONTROL: HeaderValue = HeaderValue::from_static("private, no-cache");

#[serde_inline_default]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(deserialize_with = "de_base_url")]
    pub base_url: Url,

    #[serde_inline_default(1024.try_into().expect("not zero"))]
    pub max_page_len: NonZero<u32>,
    #[serde_inline_default(4096)] // 4KiB
    pub max_request_len: usize,

    #[serde_inline_default(90)]
    pub timestamp_tolerance_secs: u64,

    #[serde(default)]
    pub feed: feed::Config,
    #[serde(default)]
    pub ws: event::Config,
    #[serde(default)]
    pub register: register::Config,
}

fn de_base_url<'de, D: Deserializer<'de>>(de: D) -> Result<Url, D::Error> {
    let url = Url::deserialize(de)?;
    if url.cannot_be_a_base() {
        return Err(serde::de::Error::custom(
            "base_url must be able to be a base",
        ));
    }
    if url.domain().is_none() {
        return Err(serde::de::Error::custom("base_url must have a domain"));
    }
    Ok(url)
}

// Locks must be grabbed in the field order.
#[derive(Debug)]
pub struct AppState {
    db: Database,
    used_nonces: Mutex<ExpiringSet<u32>>,
    event: event::State,
    register: register::State,

    server_metadata: (Bytes, ETag<Box<str>>),
    config: ServerConfig,
}

impl AppState {
    pub fn new(db: Database, config: ServerConfig) -> Self {
        let meta = ServerMetadata {
            server: SERVER_AND_VERSION.into(),
            src_url: SERVER_SRC_URL.map(|url| url.parse().expect("checked by build script")),
            capabilities: ServerCapabilities {
                allow_public_register: config.register.enable_public,
            },
        };
        let meta = Bytes::from(serde_json::to_string(&meta).expect("serialization cannot fail"));
        let meta_hash = sha2::Sha256::new_with_prefix(&meta).finalize();
        // Provide 2^-32 collision rate, which is enough for 136yr cache of a  daily update server.
        let meta_etag = ETag(Some(BASE64_NOPAD.encode(&meta_hash[..8]).into()));

        Self {
            db,
            used_nonces: Mutex::new(ExpiringSet::new(Duration::from_secs(
                config.timestamp_tolerance_secs,
            ))),
            event: event::State::default(),
            register: register::State::new(config.register.clone()),

            server_metadata: (meta, meta_etag),
            config,
        }
    }

    fn verify_signed_data<T: Serialize>(&self, data: &Signed<T>) -> Result<(), ApiError> {
        api_ensure!(data.verify().is_ok(), "signature verification failed");
        let timestamp_diff = get_timestamp().abs_diff(data.signee.timestamp);
        api_ensure!(
            timestamp_diff <= self.config.timestamp_tolerance_secs,
            "invalid timestamp",
        );
        api_ensure!(
            self.used_nonces.lock().try_insert(data.signee.nonce),
            "used nonce",
        );
        Ok(())
    }
}

type ArcState = State<Arc<AppState>>;

pub fn router(st: Arc<AppState>) -> Router {
    use axum::routing::{delete, get, post};

    // NB. Use consistent handler naming: `<method>_<path>[_<details>]`.
    // Use prefix `list` for GET with pagination.
    //
    // One route per line.
    #[rustfmt::skip]
    let router = Router::new()
        .route("/server", get(get_server_metadata))
        .route("/ws", get(event::get_ws))
        .route("/user/me", get(get_user).post(register::post_user))
        .route("/room", get(list_room))
        // TODO: Maybe just POST on `/room`?
        .route("/room/create", post(post_room_create))
        .route("/room/:rid", get(get_room).delete(delete_room))
        .route("/room/:rid/feed.json", get(feed::get_room_feed::<feed::JsonFeed>))
        .route("/room/:rid/feed.atom", get(feed::get_room_feed::<feed::AtomFeed>))
        .route("/room/:rid/msg", get(list_room_msg).post(post_room_msg))
        .route("/room/:rid/msg/:cid/seen", post(post_room_msg_seen))
        // TODO!: remove this.
        .route("/room/:rid/admin", post(post_room_admin))
        .route("/room/:rid/member", get(list_room_member).post(post_room_member))
        .route("/room/:rid/member/:uid", delete(delete_room_member).patch(patch_room_member))
        ;

    let router = router
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            st.config.max_request_len,
        ))
        .layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                header::CACHE_CONTROL,
                DEFAULT_CACHE_CONTROL,
            ),
        )
        // NB. This comes at last (outmost layer), so inner errors will still be wrapped with
        // correct CORS headers. Also `Authorization` must be explicitly included besides `*`.
        .layer(
            tower_http::cors::CorsLayer::permissive()
                .allow_headers([HeaderName::from_static("*"), header::AUTHORIZATION]),
        )
        .with_state(st);
    Router::new().nest("/_blah", router)
}

type RE<T> = R<T, ApiError>;

async fn get_server_metadata(State(st): ArcState) -> Response {
    let (json, etag) = st.server_metadata.clone();
    let headers = [
        (
            header::CONTENT_TYPE,
            const { HeaderValue::from_static("application/json") },
        ),
        HEADER_PUBLIC_NO_CACHE,
    ];
    (headers, etag, json).into_response()
}

async fn get_user(State(st): ArcState, auth: MaybeAuth) -> Response {
    let ret = (|| {
        match auth.into_optional()? {
            None => None,
            Some(user) => st.db.with_read(|txn| txn.get_user(&user)).ok(),
        }
        .ok_or(ApiError::UserNotFound)
    })();

    match ret {
        Ok(_) => NoContent.into_response(),
        Err(err) => {
            let (status, raw_err) = err.to_raw();
            if status != StatusCode::NOT_FOUND {
                return err.into_response();
            }
            let resp = Json(ErrorResponseWithChallenge {
                error: raw_err,
                register_challenge: st.register.challenge(&st.config.register),
            });
            (status, resp).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ListRoomParams {
    filter: ListRoomFilter,
    // Workaround: serde(flatten) breaks deserialization
    // See: https://github.com/nox/serde_urlencoded/issues/33
    skip_token: Option<Id>,
    top: Option<NonZero<u32>>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ListRoomFilter {
    /// List all public rooms.
    Public,
    /// List joined rooms (authentication required).
    Joined,
    /// List all joined rooms with unseen messages (authentication required).
    // TODO: Is this really useful, given most user keep messages unread forever?
    Unseen,
}

async fn list_room(
    st: ArcState,
    params: RE<Query<ListRoomParams>>,
    auth: MaybeAuth,
) -> Result<Json<RoomList>, ApiError> {
    let pagination = Pagination {
        skip_token: params.skip_token,
        top: params.top,
        until_token: None,
    };
    let page_len = pagination.effective_page_len(&st);
    let start_rid = pagination.skip_token.unwrap_or(Id::MIN);

    let rooms = st.db.with_read(|txn| match params.filter {
        ListRoomFilter::Public => txn.list_public_rooms(start_rid, page_len),
        ListRoomFilter::Joined => {
            let (uid, _) = txn.get_user(&auth?.0)?;
            txn.list_joined_rooms(uid, start_rid, page_len)
        }
        ListRoomFilter::Unseen => {
            let (uid, _) = txn.get_user(&auth?.0)?;
            txn.list_unseen_rooms(uid, start_rid, page_len)
        }
    })?;

    let skip_token = (rooms.len() as u32 == page_len.get())
        .then(|| rooms.last().expect("page must not be empty").rid);
    Ok(Json(RoomList { rooms, skip_token }))
}

async fn post_room_create(
    st: ArcState,
    SignedJson(params): SignedJson<CreateRoomPayload>,
) -> Result<Json<Id>, ApiError> {
    match params.signee.payload {
        CreateRoomPayload::Group(op) => room_create_group(&st, &params.signee.user, op).await,
        CreateRoomPayload::PeerChat(op) => {
            room_create_peer_chat(&st, &params.signee.user, op).await
        }
    }
}

async fn room_create_group(
    st: &AppState,
    user: &UserKey,
    op: CreateGroup,
) -> Result<Json<Id>, ApiError> {
    api_ensure!(
        RoomAttrs::GROUP_ATTRS.contains(op.attrs),
        "invalid group attributes",
    );

    let rid = st.db.with_write(|conn| {
        let (uid, perm) = conn.get_user(user)?;
        api_ensure!(
            perm.contains(ServerPermission::CREATE_ROOM),
            ApiError::PermissionDenied("the user does not have permission to create room"),
        );
        let rid = Id::gen();
        conn.create_group(rid, &op.title, op.attrs)?;
        conn.add_room_member(rid, uid, MemberPermission::ALL)?;
        Ok(rid)
    })?;

    Ok(Json(rid))
}

async fn room_create_peer_chat(
    st: &AppState,
    src_user: &UserKey,
    op: CreatePeerChat,
) -> Result<Json<Id>, ApiError> {
    let tgt_user_id_key = op.peer;
    api_ensure!(
        tgt_user_id_key != src_user.id_key,
        ApiError::NotImplemented("self-chat is not implemented yet"),
    );

    // TODO: Access control and throttling.
    let rid = st.db.with_write(|txn| {
        let (src_uid, _) = txn.get_user(src_user)?;
        let (tgt_uid, _) = txn
            .get_user_by_id_key(&tgt_user_id_key)
            .ok()
            .filter(|(_, perm)| perm.contains(ServerPermission::ACCEPT_PEER_CHAT))
            .ok_or(ApiError::PeerUserNotFound)?;
        let rid = Id::gen_peer_chat_rid();
        txn.create_peer_room_with_members(rid, RoomAttrs::PEER_CHAT, src_uid, tgt_uid)?;
        Ok(rid)
    })?;

    Ok(Json(rid))
}

/// Pagination query parameters.
///
/// Field names are inspired by Microsoft's design, which is an extension to OData spec.
/// See: <https://learn.microsoft.com/en-us/graph/query-parameters#odata-system-query-options>
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Pagination {
    /// A opaque token from previous response to fetch the next page.
    skip_token: Option<Id>,
    /// Maximum page size.
    top: Option<NonZero<u32>>,
    /// Only return items before (excluding) this token.
    /// Useful for `room_msg_list` to pass `last_seen_cid` without over-fetching.
    until_token: Option<Id>,
}

impl Pagination {
    fn effective_page_len(&self, st: &AppState) -> NonZero<u32> {
        self.top
            .unwrap_or(u32::MAX.try_into().expect("not zero"))
            .min(st.config.max_page_len)
    }
}

async fn list_room_msg(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    R(Query(pagination), _): RE<Query<Pagination>>,
    auth: MaybeAuth,
) -> Result<Json<RoomMsgs>, ApiError> {
    let (msgs, skip_token) = st.db.with_read(|txn| {
        if let Some(user) = auth.into_optional()? {
            txn.get_room_member(rid, &user)?;
        } else {
            txn.get_room_having(rid, RoomAttrs::PUBLIC_READABLE)?;
        }
        query_room_msgs(&st, txn, rid, pagination)
    })?;
    Ok(Json(RoomMsgs { msgs, skip_token }))
}

async fn get_room(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    auth: MaybeAuth,
) -> Result<Json<RoomMetadata>, ApiError> {
    let (attrs, title) = st.db.with_read(|txn| {
        let filter = if auth
            .into_optional()?
            .is_some_and(|user| txn.get_room_member(rid, &user).is_ok())
        {
            RoomAttrs::empty()
        } else {
            RoomAttrs::PUBLIC_READABLE
        };
        txn.get_room_having(rid, filter)
    })?;

    Ok(Json(RoomMetadata {
        rid,
        title,
        attrs,

        // TODO: Should we include these here?
        last_msg: None,
        last_seen_cid: None,
        unseen_cnt: None,
        member_permission: None,
        peer_user: None,
    }))
}

/// Get room messages with pagination parameters,
/// return a page of messages and the next `skip_token` if this is not the last page.
fn query_room_msgs(
    st: &AppState,
    txn: &Transaction<'_>,
    rid: Id,
    pagination: Pagination,
) -> Result<(Vec<SignedChatMsgWithId>, Option<Id>), ApiError> {
    let page_len = pagination.effective_page_len(st);
    let msgs = txn.list_room_msgs(
        rid,
        pagination.until_token.unwrap_or(Id::MIN),
        pagination.skip_token.unwrap_or(Id::MAX),
        page_len,
    )?;
    let skip_token = (msgs.len() as u32 == page_len.get())
        .then(|| msgs.last().expect("page must not be empty").cid);
    Ok((msgs, skip_token))
}

async fn post_room_msg(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    SignedJson(chat): SignedJson<ChatPayload>,
) -> Result<Json<Id>, ApiError> {
    api_ensure!(rid == chat.signee.payload.room, "room id mismatch with URI");

    let (cid, members) = st.db.with_write(|txn| {
        let (uid, perm, ..) = txn.get_room_member(rid, &chat.signee.user)?;
        api_ensure!(
            perm.contains(MemberPermission::POST_CHAT),
            ApiError::PermissionDenied("the user does not have permission to post in the room"),
        );

        let cid = Id::gen();
        txn.add_room_chat_msg(rid, uid, cid, &chat)?;
        let members = txn
            .list_room_members(rid, Id::MIN, None)?
            .into_iter()
            .map(|(uid, ..)| uid)
            .collect::<Vec<_>>();
        Ok((cid, members))
    })?;

    // FIXME: Optimize this to not traverses over all members.
    st.event.on_room_msg(WithMsgId::new(cid, chat), members);

    Ok(Json(cid))
}

async fn post_room_admin(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    SignedJson(op): SignedJson<RoomAdminPayload>,
) -> Result<NoContent, ApiError> {
    // TODO: This is a temporary endpoint so just reserialize them.
    fn transcode<T: Serialize, U: DeserializeOwned>(v: &T) -> SignedJson<U> {
        let v = serde_json::to_value(v).expect("serialization cannot fail");
        SignedJson(serde_json::from_value(v).expect("format should be compatible"))
    }

    match op.signee.payload.op {
        RoomAdminOp::AddMember(_) => {
            post_room_member(st, R(Path(rid), PhantomData), transcode(&op)).await
        }
        RoomAdminOp::RemoveMember(_) => {
            delete_room_member(
                st,
                R(Path((rid, op.signee.user.id_key.clone())), PhantomData),
                transcode(&op),
            )
            .await
        }
    }
}

async fn post_room_member(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    SignedJson(op): SignedJson<AddMemberPayload>,
) -> Result<NoContent, ApiError> {
    api_ensure!(rid == op.signee.payload.room, "room id mismatch with URI");
    api_ensure!(
        !rid.is_peer_chat(),
        "cannot add members to a peer chat room"
    );
    let member = op.signee.payload.member;
    api_ensure!(
        member.user == op.signee.user.id_key,
        ApiError::NotImplemented("only self-adding is implemented yet"),
    );
    api_ensure!(
        MemberPermission::MAX_SELF_ADD.contains(member.permission),
        "invalid member permission",
    );

    st.db.with_write(|txn| {
        let (uid, _perm) = txn.get_user(&op.signee.user)?;
        let (attrs, _) = txn.get_room_having(rid, RoomAttrs::PUBLIC_JOINABLE)?;
        // Sanity check.
        assert!(!attrs.contains(RoomAttrs::PEER_CHAT));
        txn.add_room_member(rid, uid, member.permission)?;
        Ok(NoContent)
    })
}

async fn delete_room_member(
    st: ArcState,
    R(Path((rid, id_key)), _): RE<Path<(Id, PubKey)>>,
    SignedJson(op): SignedJson<RemoveMemberPayload>,
) -> Result<NoContent, ApiError> {
    api_ensure!(rid == op.signee.payload.room, "room id mismatch with URI");
    api_ensure!(
        !rid.is_peer_chat(),
        "cannot remove members from a peer chat room"
    );
    let tgt_user = op.signee.payload.user;
    api_ensure!(id_key == tgt_user, "user id mismatch with URI");
    let is_self_removal = op.signee.user.id_key == tgt_user;

    st.db.with_write(|txn| {
        let (uid, perm, _) = txn.get_room_member(rid, &op.signee.user)?;
        api_ensure!(
            is_self_removal || perm.contains(MemberPermission::REMOVE_MEMBER),
            ApiError::PermissionDenied("the user does not have permission to remove members")
        );
        let (attrs, _) = txn.get_room_having(rid, RoomAttrs::empty())?;
        // Sanity check.
        assert!(!attrs.contains(RoomAttrs::PEER_CHAT));
        let tgt_uid = if is_self_removal {
            uid
        } else {
            txn.get_room_member_by_id_key(rid, &tgt_user)?.0
        };
        txn.remove_room_member(rid, tgt_uid)?;
        Ok(NoContent)
    })
}

async fn patch_room_member(
    st: ArcState,
    R(Path((rid, id_key)), _): RE<Path<(Id, PubKey)>>,
    SignedJson(op): SignedJson<UpdateMemberPayload>,
) -> Result<NoContent, ApiError> {
    api_ensure!(rid == op.signee.payload.room, "room id mismatch with URI");
    api_ensure!(!rid.is_peer_chat(), "cannot operate on a peer chat room");
    let op_member = op.signee.payload.member;
    api_ensure!(id_key == op_member.user, "user id mismatch with URI");

    st.db.with_write(|txn| {
        let (_src_uid, src_perm, ..) = txn.get_room_member(rid, &op.signee.user)?;
        api_ensure!(
            src_perm.contains(MemberPermission::UPDATE_MEMBER),
            ApiError::PermissionDenied("the user does not have permission to update permissions")
        );
        api_ensure!(
            src_perm.contains(op_member.permission),
            ApiError::PermissionDenied("cannot set a permission higher than setter's")
        );
        let (tgt_uid, tgt_prev_perm, ..) = txn.get_room_member_by_id_key(rid, &op_member.user)?;
        api_ensure!(
            src_perm.contains(tgt_prev_perm),
            ApiError::PermissionDenied(
                "cannot update a member having higher permission than setter's"
            ),
        );
        // Checked to exist.
        txn.update_room_member(rid, tgt_uid, op_member.permission)?;
        Ok(NoContent)
    })
}

async fn delete_room(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    SignedJson(op): SignedJson<DeleteRoomPayload>,
) -> Result<NoContent, ApiError> {
    api_ensure!(rid == op.signee.payload.room, "room id mismatch with URI");
    st.db.with_write(|txn| {
        // TODO: Should we only shadow delete here?
        let (_uid, perm, ..) = txn.get_room_member(rid, &op.signee.user)?;
        api_ensure!(
            perm.contains(MemberPermission::DELETE_ROOM),
            ApiError::PermissionDenied("the user does not have permission to delete the room")
        );
        txn.delete_room(rid)?;
        Ok(NoContent)
    })
}

async fn post_room_msg_seen(
    st: ArcState,
    R(Path((rid, cid)), _): RE<Path<(Id, i64)>>,
    Auth(user): Auth,
) -> Result<NoContent, ApiError> {
    st.db.with_write(|txn| {
        let (uid, _perm, prev_seen_cid) = txn.get_room_member(rid, &user)?;
        if cid < prev_seen_cid.0 {
            return Ok(());
        }
        txn.mark_room_msg_seen(rid, uid, Id(cid as _))
    })?;
    Ok(NoContent)
}

async fn list_room_member(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    R(Query(pagination), _): RE<Query<Pagination>>,
    Auth(user): Auth,
) -> Result<Json<RoomMemberList>, ApiError> {
    api_ensure!(
        pagination.until_token.is_none(),
        "untilToken is not supported for this API"
    );

    st.db.with_read(|txn| {
        let (_, perm, _) = txn.get_room_member(rid, &user)?;
        api_ensure!(
            perm.contains(MemberPermission::LIST_MEMBERS),
            ApiError::PermissionDenied("the user does not have permission to get room members"),
        );

        let page_len = pagination.effective_page_len(&st);
        let mut last_uid = None;
        let members = txn
            .list_room_members(
                rid,
                pagination.skip_token.unwrap_or(Id::MIN),
                Some(page_len),
            )?
            .into_iter()
            .map(|(uid, id_key, permission, last_seen_cid)| {
                last_uid = Some(Id(uid));
                RoomMember {
                    id_key,
                    permission,
                    last_seen_cid: (last_seen_cid != Id(0)).then_some(last_seen_cid),
                }
            })
            .collect::<Vec<_>>();
        let skip_token = (members.len() as u32 == page_len.get())
            .then(|| last_uid.expect("page must not be empty"));
        Ok(Json(RoomMemberList {
            members,
            skip_token,
        }))
    })
}
