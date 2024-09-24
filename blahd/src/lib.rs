use std::num::NonZero;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use axum::extract::{ws, OriginalUri};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::WithRejection as R;
use blah_types::{
    ChatPayload, CreateGroup, CreatePeerChat, CreateRoomPayload, DeleteRoomPayload, Id,
    MemberPermission, RoomAdminOp, RoomAdminPayload, RoomAttrs, RoomMetadata, ServerPermission,
    Signed, SignedChatMsg, UserKey, UserRegisterPayload, WithMsgId, X_BLAH_DIFFICULTY,
    X_BLAH_NONCE,
};
use database::{Transaction, TransactionOps};
use feed::FeedData;
use id::IdExt;
use middleware::{Auth, MaybeAuth, ResultExt as _, SignedJson};
use parking_lot::Mutex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_inline_default::serde_inline_default;
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

    config: ServerConfig,
}

impl AppState {
    pub fn new(db: Database, config: ServerConfig) -> Self {
        Self {
            db,
            used_nonces: Mutex::new(ExpiringSet::new(Duration::from_secs(
                config.timestamp_tolerance_secs,
            ))),
            event: event::State::default(),
            register: register::State::new(config.register.clone()),

            config,
        }
    }

    fn verify_signed_data<T: Serialize>(&self, data: &Signed<T>) -> Result<(), ApiError> {
        let Ok(()) = data.verify() else {
            return Err(error_response!(
                StatusCode::BAD_REQUEST,
                "invalid_signature",
                "signature verification failed"
            ));
        };
        let timestamp_diff = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after UNIX epoch")
            .as_secs()
            .abs_diff(data.signee.timestamp);
        if timestamp_diff > self.config.timestamp_tolerance_secs {
            return Err(error_response!(
                StatusCode::BAD_REQUEST,
                "invalid_timestamp",
                "invalid timestamp, off by {timestamp_diff}s"
            ));
        }
        if !self.used_nonces.lock().try_insert(data.signee.nonce) {
            return Err(error_response!(
                StatusCode::BAD_REQUEST,
                "duplicated_nonce",
                "duplicated nonce",
            ));
        }
        Ok(())
    }
}

type ArcState = State<Arc<AppState>>;

pub fn router(st: Arc<AppState>) -> Router {
    let router = Router::new()
        .route("/ws", get(handle_ws))
        .route("/user/me", get(user_get).post(user_register))
        .route("/room", get(room_list))
        .route("/room/create", post(room_create))
        .route("/room/:rid", get(room_get_metadata).delete(room_delete))
        .route("/room/:rid/feed.json", get(room_get_feed::<feed::JsonFeed>))
        .route("/room/:rid/feed.atom", get(room_get_feed::<feed::AtomFeed>))
        .route("/room/:rid/msg", get(room_msg_list).post(room_msg_post))
        .route("/room/:rid/msg/:cid/seen", post(room_msg_mark_seen))
        .route("/room/:rid/admin", post(room_admin))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            st.config.max_request_len,
        ))
        // NB. This comes at last (outmost layer), so inner errors will still be wrapped with
        // correct CORS headers. Also `Authorization` must be explicitly included besides `*`.
        .layer(
            tower_http::cors::CorsLayer::permissive()
                .allow_headers([HeaderName::from_static("*"), header::AUTHORIZATION])
                .expose_headers([
                    HeaderName::from_static(X_BLAH_NONCE),
                    HeaderName::from_static(X_BLAH_DIFFICULTY),
                ]),
        )
        .with_state(st);
    Router::new().nest("/_blah", router)
}

type RE<T> = R<T, ApiError>;

async fn handle_ws(State(st): ArcState, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |mut socket| async move {
        match event::handle_ws(st, &mut socket).await {
            #[allow(
                unreachable_patterns,
                reason = "compatibility before min_exhaustive_patterns"
            )]
            Ok(never) => match never {},
            Err(err) if err.is::<event::StreamEnded>() => {}
            Err(err) => {
                tracing::debug!(%err, "ws error");
                let _: Result<_, _> = socket
                    .send(ws::Message::Close(Some(ws::CloseFrame {
                        code: ws::close_code::ERROR,
                        reason: err.to_string().into(),
                    })))
                    .await;
            }
        }
    })
}

async fn user_get(
    State(st): ArcState,
    auth: MaybeAuth,
) -> Result<StatusCode, (HeaderMap, ApiError)> {
    let ret = (|| {
        match auth.into_optional()? {
            None => None,
            Some(user) => st.db.with_read(|txn| txn.get_user(&user)).ok(),
        }
        .ok_or_else(|| error_response!(StatusCode::NOT_FOUND, "not_found", "user does not exist"))
    })();

    match ret {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(err) => Err((st.register.challenge_headers(), err)),
    }
}

async fn user_register(
    State(st): ArcState,
    SignedJson(msg): SignedJson<UserRegisterPayload>,
) -> Result<StatusCode, ApiError> {
    register::user_register(&st, msg).await
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomList {
    pub rooms: Vec<RoomMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_token: Option<Id>,
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

async fn room_list(
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

async fn room_create(
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
    if !RoomAttrs::GROUP_ATTRS.contains(op.attrs) {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "deserialization",
            "invalid room attributes",
        ));
    }

    let rid = st.db.with_write(|conn| {
        let (uid, perm) = conn.get_user(user)?;
        if !perm.contains(ServerPermission::CREATE_ROOM) {
            return Err(error_response!(
                StatusCode::FORBIDDEN,
                "permission_denied",
                "the user does not have permission to create room",
            ));
        }
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
    if tgt_user_id_key == src_user.id_key {
        return Err(error_response!(
            StatusCode::NOT_IMPLEMENTED,
            "not_implemented",
            "self-chat is not implemented yet",
        ));
    }

    // TODO: Access control and throttling.
    let rid = st.db.with_write(|txn| {
        let (src_uid, _) = txn.get_user(src_user)?;
        let (tgt_uid, _) = txn
            .get_user_by_id_key(&tgt_user_id_key)
            .ok()
            .filter(|(_, perm)| perm.contains(ServerPermission::ACCEPT_PEER_CHAT))
            .ok_or_else(|| {
                error_response!(
                    StatusCode::NOT_FOUND,
                    "peer_user_not_found",
                    "peer user does not exist or disallows peer chat",
                )
            })?;
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

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomMsgs {
    pub msgs: Vec<WithMsgId<SignedChatMsg>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_token: Option<Id>,
}

async fn room_msg_list(
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

async fn room_get_metadata(
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

async fn room_get_feed<FT: feed::FeedType>(
    st: ArcState,
    R(OriginalUri(req_uri), _): RE<OriginalUri>,
    R(Path(rid), _): RE<Path<Id>>,
    R(Query(mut pagination), _): RE<Query<Pagination>>,
) -> Result<Response, ApiError> {
    // TODO: If-None-Match.
    let self_url = st
        .config
        .base_url
        .join(req_uri.path())
        .expect("base_url can be a base");

    pagination.top = Some(
        pagination
            .effective_page_len(&st)
            .min(st.config.feed.max_page_len),
    );

    let (title, msgs, skip_token) = st.db.with_read(|txn| {
        let (attrs, title) = txn.get_room_having(rid, RoomAttrs::PUBLIC_READABLE)?;
        // Sanity check.
        assert!(!attrs.contains(RoomAttrs::PEER_CHAT));
        let title = title.expect("public room must have title");
        let (msgs, skip_token) = query_room_msgs(&st, txn, rid, pagination)?;
        Ok((title, msgs, skip_token))
    })?;

    let next_url = skip_token.map(|skip_token| {
        let next_params = Pagination {
            skip_token: Some(skip_token),
            top: pagination.top,
            until_token: None,
        };
        let mut next_url = self_url.clone();
        {
            let mut query = next_url.query_pairs_mut();
            let ser = serde_urlencoded::Serializer::new(&mut query);
            next_params
                .serialize(ser)
                .expect("serialization cannot fail");
            query.finish();
        }
        next_url
    });

    Ok(FT::to_feed_response(FeedData {
        rid,
        title,
        msgs,
        self_url,
        next_url,
    }))
}

/// Get room messages with pagination parameters,
/// return a page of messages and the next `skip_token` if this is not the last page.
fn query_room_msgs(
    st: &AppState,
    txn: &Transaction<'_>,
    rid: Id,
    pagination: Pagination,
) -> Result<(Vec<WithMsgId<SignedChatMsg>>, Option<Id>), ApiError> {
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

async fn room_msg_post(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    SignedJson(chat): SignedJson<ChatPayload>,
) -> Result<Json<Id>, ApiError> {
    if rid != chat.signee.payload.room {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "URI and payload room id mismatch",
        ));
    }

    let (cid, members) = st.db.with_write(|txn| {
        let (uid, perm, ..) = txn.get_room_member(rid, &chat.signee.user)?;
        if !perm.contains(MemberPermission::POST_CHAT) {
            return Err(error_response!(
                StatusCode::FORBIDDEN,
                "permission_denied",
                "the user does not have permission to post in the room",
            ));
        }

        let cid = Id::gen();
        txn.add_room_chat_msg(rid, uid, cid, &chat)?;
        let members = txn.list_room_members(rid)?;
        Ok((cid, members))
    })?;

    let chat = Arc::new(chat);
    // FIXME: Optimize this to not traverses over all members.
    let listeners = st.event.user_listeners.lock();
    let mut cnt = 0usize;
    for uid in members {
        if let Some(tx) = listeners.get(&uid) {
            if tx.send(chat.clone()).is_ok() {
                cnt += 1;
            }
        }
    }
    if cnt != 0 {
        tracing::debug!("broadcasted event to {cnt} clients");
    }

    Ok(Json(cid))
}

async fn room_admin(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    SignedJson(op): SignedJson<RoomAdminPayload>,
) -> Result<StatusCode, ApiError> {
    if rid != op.signee.payload.room {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "URI and payload room id mismatch",
        ));
    }
    if rid.is_peer_chat() {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "operation not permitted on peer chat rooms",
        ));
    }

    match op.signee.payload.op {
        RoomAdminOp::AddMember { user, permission } => {
            if user != op.signee.user.id_key {
                return Err(error_response!(
                    StatusCode::NOT_IMPLEMENTED,
                    "not_implemented",
                    "only self-adding is implemented yet",
                ));
            }
            if !MemberPermission::MAX_SELF_ADD.contains(permission) {
                return Err(error_response!(
                    StatusCode::BAD_REQUEST,
                    "deserialization",
                    "invalid permission",
                ));
            }
            room_join(&st, rid, &op.signee.user, permission).await?;
        }
        RoomAdminOp::RemoveMember { user } => {
            if user != op.signee.user.id_key {
                return Err(error_response!(
                    StatusCode::NOT_IMPLEMENTED,
                    "not_implemented",
                    "only self-removing is implemented yet",
                ));
            }
            room_leave(&st, rid, &op.signee.user).await?;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn room_join(
    st: &AppState,
    rid: Id,
    user: &UserKey,
    permission: MemberPermission,
) -> Result<(), ApiError> {
    st.db.with_write(|txn| {
        let (uid, _perm) = txn.get_user(user)?;
        let (attrs, _) = txn.get_room_having(rid, RoomAttrs::PUBLIC_JOINABLE)?;
        // Sanity check.
        assert!(!attrs.contains(RoomAttrs::PEER_CHAT));
        txn.add_room_member(rid, uid, permission)?;
        Ok(())
    })
}

async fn room_leave(st: &AppState, rid: Id, user: &UserKey) -> Result<(), ApiError> {
    st.db.with_write(|txn| {
        let (uid, ..) = txn.get_room_member(rid, user)?;
        let (attrs, _) = txn.get_room_having(rid, RoomAttrs::empty())?;
        if attrs.contains(RoomAttrs::PEER_CHAT) {
            return Err(error_response!(
                StatusCode::BAD_REQUEST,
                "invalid_operation",
                "cannot leave a peer chat room without deleting it",
            ));
        }
        txn.remove_room_member(rid, uid)?;
        Ok(())
    })
}

async fn room_delete(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    SignedJson(op): SignedJson<DeleteRoomPayload>,
) -> Result<StatusCode, ApiError> {
    if rid != op.signee.payload.room {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "URI and payload room id mismatch",
        ));
    }
    st.db.with_write(|txn| {
        // TODO: Should we only shadow delete here?
        let (_uid, perm, ..) = txn.get_room_member(rid, &op.signee.user)?;
        if !perm.contains(MemberPermission::DELETE_ROOM) {
            return Err(error_response!(
                StatusCode::FORBIDDEN,
                "permission_denied",
                "the user does not have permission to delete the room",
            ));
        }
        txn.delete_room(rid)?;
        Ok(StatusCode::NO_CONTENT)
    })
}

async fn room_msg_mark_seen(
    st: ArcState,
    R(Path((rid, cid)), _): RE<Path<(Id, i64)>>,
    Auth(user): Auth,
) -> Result<StatusCode, ApiError> {
    st.db.with_write(|txn| {
        let (uid, _perm, prev_seen_cid) = txn.get_room_member(rid, &user)?;
        if cid < prev_seen_cid.0 {
            return Ok(());
        }
        txn.mark_room_msg_seen(rid, uid, Id(cid as _))
    })?;
    Ok(StatusCode::NO_CONTENT)
}
