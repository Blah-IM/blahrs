use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use axum::extract::ws;
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::WithRejection as R;
use blah_types::{
    ChatPayload, CreateGroup, CreatePeerChat, CreateRoomPayload, Id, MemberPermission, RoomAdminOp,
    RoomAdminPayload, RoomAttrs, RoomMetadata, ServerPermission, SignedChatMsg, Signee, UserKey,
    WithMsgId, WithSig,
};
use config::ServerConfig;
use ed25519_dalek::SIGNATURE_LENGTH;
use id::IdExt;
use middleware::{Auth, MaybeAuth, ResultExt as _, SignedJson};
use parking_lot::Mutex;
use rusqlite::{named_params, params, Connection, OptionalExtension, Row, ToSql};
use serde::{Deserialize, Serialize};
use url::Url;
use utils::ExpiringSet;

#[macro_use]
mod middleware;
pub mod config;
mod database;
mod event;
mod id;
mod utils;

pub use database::Database;
pub use middleware::ApiError;

// Locks must be grabbed in the field order.
#[derive(Debug)]
pub struct AppState {
    db: Database,
    used_nonces: Mutex<ExpiringSet<u32>>,
    event: event::State,

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

            config,
        }
    }

    fn verify_signed_data<T: Serialize>(&self, data: &WithSig<T>) -> Result<(), ApiError> {
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
    Router::new()
        .route("/ws", get(handle_ws))
        .route("/room", get(room_list))
        .route("/room/create", post(room_create))
        .route("/room/:rid", get(room_get_metadata))
        // NB. Sync with `feed_url` and `next_url` generation.
        .route("/room/:rid/feed.json", get(room_get_feed))
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
                .allow_headers([header::HeaderName::from_static("*"), header::AUTHORIZATION]),
        )
        .with_state(st)
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
    top: Option<NonZeroUsize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ListRoomFilter {
    /// List all public rooms.
    Public,
    /// List joined rooms (authentication required).
    Joined,
    /// List all joined rooms with unseen messages (authentication required).
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

    let query = |sql: &str, params: &[(&str, &dyn ToSql)]| -> Result<RoomList, ApiError> {
        let rooms = st
            .db
            .get()
            .prepare(sql)?
            .query_map(params, |row| {
                // TODO: Extract this into a function.
                let rid = row.get("rid")?;
                let last_msg = row
                    .get::<_, Option<Id>>("cid")?
                    .map(|cid| {
                        Ok::<_, rusqlite::Error>(WithMsgId {
                            cid,
                            msg: SignedChatMsg {
                                sig: row.get("sig")?,
                                signee: Signee {
                                    nonce: row.get("nonce")?,
                                    timestamp: row.get("timestamp")?,
                                    user: row.get("userkey")?,
                                    payload: ChatPayload {
                                        rich_text: row.get("rich_text")?,
                                        room: rid,
                                    },
                                },
                            },
                        })
                    })
                    .transpose()?;
                Ok(RoomMetadata {
                    rid,
                    title: row.get("title")?,
                    attrs: row.get("attrs")?,
                    last_msg,
                    last_seen_cid: Some(row.get::<_, Id>("last_seen_cid")?)
                        .filter(|cid| cid.0 != 0),
                    unseen_cnt: row.get("unseen_cnt").ok(),
                    member_permission: row.get("member_perm").ok(),
                    peer_user: row.get("peer_userkey").ok(),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let skip_token =
            (rooms.len() == page_len).then(|| rooms.last().expect("page must not be empty").rid);
        Ok(RoomList { rooms, skip_token })
    };

    match params.filter {
        ListRoomFilter::Public => query(
            r"
            SELECT `rid`, `title`, `attrs`, 0 AS `last_seen_cid`,
                `cid`, `last_author`.`userkey`, `timestamp`, `nonce`, `sig`, `rich_text`
            FROM `room`
            LEFT JOIN `msg` USING (`rid`)
            LEFT JOIN `user` AS `last_author` USING (`uid`)
            WHERE `rid` > :start_rid AND
                (`attrs` & :perm) = :perm
            GROUP BY `rid` HAVING `cid` IS MAX(`cid`)
            ORDER BY `rid` ASC
            LIMIT :page_len
            ",
            named_params! {
                ":start_rid": start_rid,
                ":page_len": page_len,
                ":perm": RoomAttrs::PUBLIC_READABLE,
            },
        ),
        ListRoomFilter::Joined => {
            let user = auth?.0;
            query(
                r"
                SELECT
                    `rid`, `title`, `attrs`, `last_seen_cid`, `room_member`.`permission` AS `member_perm`,
                    `cid`, `last_author`.`userkey`, `timestamp`, `nonce`, `sig`, `rich_text`,
                    `peer_user`.`userkey` AS `peer_userkey`
                FROM `user`
                JOIN `room_member` USING (`uid`)
                JOIN `room` USING (`rid`)
                LEFT JOIN `msg` USING (`rid`)
                LEFT JOIN `user` AS `last_author` ON (`last_author`.`uid` = `msg`.`uid`)
                LEFT JOIN `user` AS `peer_user` ON
                    (`peer_user`.`uid` = `room`.`peer1` + `room`.`peer2` - `user`.`uid`)
                WHERE `user`.`userkey` = :userkey AND
                    `rid` > :start_rid
                GROUP BY `rid` HAVING `cid` IS MAX(`cid`)
                ORDER BY `rid` ASC
                LIMIT :page_len
                ",
                named_params! {
                    ":start_rid": start_rid,
                    ":page_len": page_len,
                    ":userkey": user,
                },
            )
        }
        ListRoomFilter::Unseen => {
            let user = auth?.0;
            query(
                r"
                SELECT
                    `rid`, `title`, `attrs`, `last_seen_cid`, `room_member`.`permission` AS `member_perm`,
                    `cid`, `last_author`.`userkey`, `timestamp`, `nonce`, `sig`, `rich_text`,
                    `peer_user`.`userkey` AS `peer_userkey`,
                    (SELECT COUNT(*)
                        FROM `msg` AS `unseen_msg`
                        WHERE `unseen_msg`.`rid` = `room`.`rid` AND
                            `last_seen_cid` < `unseen_msg`.`cid`) AS `unseen_cnt`
                FROM `user`
                JOIN `room_member` USING (`uid`)
                JOIN `room` USING (`rid`)
                LEFT JOIN `msg` USING (`rid`)
                LEFT JOIN `user` AS `last_author` ON (`last_author`.`uid` = `msg`.`uid`)
                LEFT JOIN `user` AS `peer_user` ON
                    (`peer_user`.`uid` = `room`.`peer1` + `room`.`peer2` - `user`.`uid`)
                WHERE `user`.`userkey` = :userkey AND
                    `rid` > :start_rid AND
                    `cid` > `last_seen_cid`
                GROUP BY `rid` HAVING `cid` IS MAX(`cid`)
                ORDER BY `rid` ASC
                LIMIT :page_len
                ",
                named_params! {
                    ":start_rid": start_rid,
                    ":page_len": page_len,
                    ":userkey": user,
                },
            )
        }
    }
    .map(Json)
}

async fn room_create(
    st: ArcState,
    SignedJson(params): SignedJson<CreateRoomPayload>,
) -> Result<Json<Id>, ApiError> {
    match params.signee.payload {
        CreateRoomPayload::Group(op) => room_create_group(&st, params.signee.user, op).await,
        CreateRoomPayload::PeerChat(op) => room_create_peer_chat(&st, params.signee.user, op).await,
    }
}

async fn room_create_group(
    st: &AppState,
    user: UserKey,
    op: CreateGroup,
) -> Result<Json<Id>, ApiError> {
    if !RoomAttrs::GROUP_ATTRS.contains(op.attrs) {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "deserialization",
            "invalid room attributes",
        ));
    }

    let members = &op.members.0;
    if !members
        .iter()
        .any(|m| m.user == user && m.permission == MemberPermission::ALL)
    {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "deserialization",
            "invalid initial members",
        ));
    }

    let mut conn = st.db.get();
    let Some(true) = conn
        .query_row(
            r"
            SELECT `permission`
            FROM `user`
            WHERE `userkey` = ?
            ",
            params![user],
            |row| {
                let perm = row.get::<_, ServerPermission>("permission")?;
                Ok(perm.contains(ServerPermission::CREATE_ROOM))
            },
        )
        .optional()?
    else {
        return Err(error_response!(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "user does not have permission to create room",
        ));
    };

    let txn = conn.transaction()?;
    let rid = Id::gen();
    txn.execute(
        r"
        INSERT INTO `room` (`rid`, `title`, `attrs`)
        VALUES (:rid, :title, :attrs)
        ",
        named_params! {
            ":rid": rid,
            ":title": op.title,
            ":attrs": op.attrs,
        },
    )?;
    let mut insert_user = txn.prepare(
        r"
        INSERT INTO `user` (`userkey`)
        VALUES (?)
        ON CONFLICT (`userkey`) DO NOTHING
        ",
    )?;
    let mut insert_member = txn.prepare(
        r"
        INSERT INTO `room_member` (`rid`, `uid`, `permission`)
        SELECT :rid, `uid`, :permission
        FROM `user`
        WHERE `userkey` = :userkey
        ",
    )?;
    for member in members {
        insert_user.execute(params![member.user])?;
        insert_member.execute(named_params! {
            ":rid": rid,
            ":userkey": member.user,
            ":permission": member.permission,
        })?;
    }
    drop(insert_member);
    drop(insert_user);
    txn.commit()?;

    Ok(Json(rid))
}

async fn room_create_peer_chat(
    st: &AppState,
    src_user: UserKey,
    op: CreatePeerChat,
) -> Result<Json<Id>, ApiError> {
    let tgt_user = op.peer;
    if tgt_user == src_user {
        return Err(error_response!(
            StatusCode::NOT_IMPLEMENTED,
            "not_implemented",
            "self-chat is not implemented yet",
        ));
    }

    // TODO: Access control and throttling.

    let mut conn = st.db.get();
    let txn = conn.transaction()?;
    let tgt_uid = txn
        .query_row(
            r"
            SELECT `uid`
            FROM `user`
            WHERE `userkey` = :userkey AND
                `permission` & :perm = :perm
            ",
            named_params! {
                ":userkey": tgt_user,
                ":perm": ServerPermission::ACCEPT_PEER_CHAT,
            },
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| {
            error_response!(
                StatusCode::NOT_FOUND,
                "not_found",
                "peer user does not exist or disallows peer chat",
            )
        })?;
    let src_uid = txn
        .query_row(
            r"
            SELECT `uid` FROM `user`
            WHERE `userkey` = ?
            ",
            params![src_user],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let src_uid = match src_uid {
        Some(uid) => uid,
        None => {
            txn.execute(
                r"
                INSERT INTO `user` (`userkey`)
                VALUES (?)
                ",
                params![src_user],
            )?;
            txn.last_insert_rowid()
        }
    };

    let (peer1, peer2) = if src_uid <= tgt_uid {
        (src_uid, tgt_uid)
    } else {
        (tgt_uid, src_uid)
    };
    let rid = Id::gen_peer_chat_rid();
    let updated = txn.execute(
        r"
        INSERT INTO `room` (`rid`, `attrs`, `peer1`, `peer2`)
        VALUES (:rid, :attrs, :peer1, :peer2)
        ON CONFLICT (`peer1`, `peer2`) WHERE `rid` < 0 DO NOTHING
        ",
        named_params! {
            ":rid": rid,
            ":attrs": RoomAttrs::PEER_CHAT,
            ":peer1": peer1,
            ":peer2": peer2,
        },
    )?;
    if updated == 0 {
        return Err(error_response!(
            StatusCode::CONFLICT,
            "exists",
            "room already exists"
        ));
    }

    {
        let mut stmt = txn.prepare(
            r"
            INSERT INTO `room_member` (`rid`, `uid`, `permission`)
            VALUES (:rid, :uid, :perm)
            ",
        )?;
        // TODO: Limit permission of the src user?
        for uid in [peer1, peer2] {
            stmt.execute(named_params! {
                ":rid": rid,
                ":uid": uid,
                ":perm": MemberPermission::MAX_PEER_CHAT,
            })?;
        }
    }

    txn.commit()?;
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
    top: Option<NonZeroUsize>,
    /// Only return items before (excluding) this token.
    /// Useful for `room_msg_list` to pass `last_seen_cid` without over-fetching.
    until_token: Option<Id>,
}

impl Pagination {
    fn effective_page_len(&self, st: &AppState) -> usize {
        self.top
            .unwrap_or(usize::MAX.try_into().expect("not zero"))
            .min(st.config.max_page_len)
            .get()
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
    let (msgs, skip_token) = {
        let conn = st.db.get();
        get_room_if_readable(&conn, rid, auth.into_optional()?.as_ref(), |_row| Ok(()))?;
        query_room_msgs(&st, &conn, rid, pagination)?
    };
    Ok(Json(RoomMsgs { msgs, skip_token }))
}

async fn room_get_metadata(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    auth: MaybeAuth,
) -> Result<Json<RoomMetadata>, ApiError> {
    let conn = st.db.get();
    let (title, attrs) = get_room_if_readable(&conn, rid, auth.into_optional()?.as_ref(), |row| {
        Ok((
            row.get::<_, Option<String>>("title")?,
            row.get::<_, RoomAttrs>("attrs")?,
        ))
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

async fn room_get_feed(
    st: ArcState,
    R(Path(rid), _): RE<Path<Id>>,
    R(Query(pagination), _): RE<Query<Pagination>>,
) -> Result<impl IntoResponse, ApiError> {
    let title;
    let (msgs, skip_token) = {
        let conn = st.db.get();
        title = get_room_if_readable(&conn, rid, None, |row| row.get::<_, String>("title"))?;
        query_room_msgs(&st, &conn, rid, pagination)?
    };

    let items = msgs
        .into_iter()
        .map(|WithMsgId { cid, msg }| {
            let time = SystemTime::UNIX_EPOCH + Duration::from_secs(msg.signee.timestamp);
            let author = FeedAuthor {
                name: msg.signee.user.to_string(),
            };
            FeedItem {
                id: cid.to_string(),
                content_html: msg.signee.payload.rich_text.html().to_string(),
                date_published: humantime::format_rfc3339(time).to_string(),
                authors: (author,),
                extra: FeedItemExtra {
                    timestamp: msg.signee.timestamp,
                    nonce: msg.signee.nonce,
                    sig: msg.sig,
                },
            }
        })
        .collect::<Vec<_>>();

    let feed_url = st
        .config
        .base_url
        .join(&format!("/room/{rid}/feed.json"))
        .expect("base_url must be valid");
    let next_url = skip_token.map(|skip_token| {
        let next_params = Pagination {
            skip_token: Some(skip_token),
            top: pagination.top,
            until_token: None,
        };
        let mut next_url = feed_url.clone();
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
    let feed = FeedRoom {
        title,
        items,
        next_url,
        feed_url,
    };

    Ok((
        [(header::CONTENT_TYPE, "application/feed+json")],
        Json(feed),
    ))
}

/// Ref: <https://www.jsonfeed.org/version/1.1/>
#[derive(Debug, Serialize)]
#[serde(tag = "version", rename = "https://jsonfeed.org/version/1.1")]
struct FeedRoom {
    title: String,
    feed_url: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_url: Option<Url>,
    items: Vec<FeedItem>,
}

#[derive(Debug, Serialize)]
struct FeedItem {
    id: String,
    content_html: String,
    date_published: String,
    authors: (FeedAuthor,),
    #[serde(rename = "_blah")]
    extra: FeedItemExtra,
}

#[derive(Debug, Serialize)]
struct FeedAuthor {
    name: String,
}

#[derive(Debug, Serialize)]
struct FeedItemExtra {
    timestamp: u64,
    nonce: u32,
    #[serde(with = "hex::serde")]
    sig: [u8; SIGNATURE_LENGTH],
}

fn get_room_if_readable<T>(
    conn: &rusqlite::Connection,
    rid: Id,
    user: Option<&UserKey>,
    f: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<T, ApiError> {
    conn.query_row(
        r"
        SELECT `title`, `attrs`
        FROM `room`
        WHERE `rid` = :rid AND
            ((`attrs` & :perm) = :perm OR
            EXISTS(SELECT 1
                FROM `room_member`
                JOIN `user` USING (`uid`)
                WHERE `room_member`.`rid` = `room`.`rid` AND
                    `userkey` = :userkey))
        ",
        named_params! {
            ":rid": rid,
            ":perm": RoomAttrs::PUBLIC_READABLE,
            ":userkey": user,
        },
        f,
    )
    .optional()?
    .ok_or_else(|| {
        error_response!(
            StatusCode::NOT_FOUND,
            "not_found",
            "the room does not exist or the user is not a room member",
        )
    })
}

/// Get room messages with pagination parameters,
/// return a page of messages and the next `skip_token` if this is not the last page.
fn query_room_msgs(
    st: &AppState,
    conn: &Connection,
    rid: Id,
    pagination: Pagination,
) -> Result<(Vec<WithMsgId<SignedChatMsg>>, Option<Id>), ApiError> {
    let page_len = pagination.effective_page_len(st);
    let mut stmt = conn.prepare(
        r"
        SELECT `cid`, `timestamp`, `nonce`, `sig`, `userkey`, `sig`, `rich_text`
        FROM `msg`
        JOIN `user` USING (`uid`)
        WHERE `rid` = :rid AND
            :after_cid < `cid` AND
            `cid` < :before_cid
        ORDER BY `cid` DESC
        LIMIT :limit
        ",
    )?;
    let msgs = stmt
        .query_and_then(
            named_params! {
                ":rid": rid,
                ":after_cid": pagination.until_token.unwrap_or(Id::MIN),
                ":before_cid": pagination.skip_token.unwrap_or(Id::MAX),
                ":limit": page_len,
            },
            |row| {
                Ok(WithMsgId {
                    cid: row.get("cid")?,
                    msg: SignedChatMsg {
                        sig: row.get("sig")?,
                        signee: Signee {
                            nonce: row.get("nonce")?,
                            timestamp: row.get("timestamp")?,
                            user: row.get("userkey")?,
                            payload: ChatPayload {
                                room: rid,
                                rich_text: row.get("rich_text")?,
                            },
                        },
                    },
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let skip_token =
        (msgs.len() == page_len).then(|| msgs.last().expect("page must not be empty").cid);

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

    let (cid, txs) = {
        let conn = st.db.get();
        let (uid, perm) = conn
            .query_row(
                r"
                SELECT `uid`, `room_member`.`permission`
                FROM `room_member`
                JOIN `user` USING (`uid`)
                WHERE `rid` = :rid AND
                    `userkey` = :userkey
                ",
                named_params! {
                    ":rid": rid,
                    ":userkey": &chat.signee.user,
                },
                |row| {
                    Ok((
                        row.get::<_, u64>("uid")?,
                        row.get::<_, MemberPermission>("permission")?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                error_response!(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "the room does not exist or the user is not a room member",
                )
            })?;

        if !perm.contains(MemberPermission::POST_CHAT) {
            return Err(error_response!(
                StatusCode::FORBIDDEN,
                "permission_denied",
                "the user does not have permission to post in the room",
            ));
        }

        let cid = Id::gen();
        conn.execute(
            r"
            INSERT INTO `msg` (`cid`, `rid`, `uid`, `timestamp`, `nonce`, `sig`, `rich_text`)
            VALUES (:cid, :rid, :uid, :timestamp, :nonce, :sig, :rich_text)
            ",
            named_params! {
                ":cid": cid,
                ":rid": rid,
                ":uid": uid,
                ":timestamp": chat.signee.timestamp,
                ":nonce": chat.signee.nonce,
                ":rich_text": &chat.signee.payload.rich_text,
                ":sig": chat.sig,
            },
        )?;

        // FIXME: Optimize this to not traverses over all members.
        let mut stmt = conn.prepare(
            r"
            SELECT `uid`
            FROM `room_member`
            WHERE `rid` = :rid
            ",
        )?;
        let listeners = st.event.user_listeners.lock();
        let txs = stmt
            .query_map(params![rid], |row| row.get::<_, u64>(0))?
            .filter_map(|ret| match ret {
                Ok(uid) => listeners.get(&uid).map(|tx| Ok(tx.clone())),
                Err(err) => Some(Err(err)),
            })
            .collect::<Result<Vec<_>, _>>()?;

        (cid, txs)
    };

    if !txs.is_empty() {
        tracing::debug!("broadcasting event to {} clients", txs.len());
        let chat = Arc::new(chat);
        for tx in txs {
            if let Err(err) = tx.send(chat.clone()) {
                tracing::debug!(%err, "failed to broadcast event");
            }
        }
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
            if user != op.signee.user {
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
            room_join(&st, rid, user, permission).await?;
        }
        RoomAdminOp::RemoveMember { user } => {
            if user != op.signee.user {
                return Err(error_response!(
                    StatusCode::NOT_IMPLEMENTED,
                    "not_implemented",
                    "only self-removing is implemented yet",
                ));
            }
            room_leave(&st, rid, user).await?;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn room_join(
    st: &AppState,
    rid: Id,
    user: UserKey,
    permission: MemberPermission,
) -> Result<(), ApiError> {
    let mut conn = st.db.get();
    let txn = conn.transaction()?;
    let is_public_joinable = txn
        .query_row(
            r"
            SELECT `attrs`
            FROM `room`
            WHERE `rid` = ?
            ",
            params![rid],
            |row| row.get::<_, RoomAttrs>(0),
        )
        .optional()?
        .is_some_and(|attrs| attrs.contains(RoomAttrs::PUBLIC_JOINABLE));
    if !is_public_joinable {
        return Err(error_response!(
            StatusCode::NOT_FOUND,
            "not_found",
            "the room does not exist or the user is not allowed to join the room",
        ));
    }

    txn.execute(
        r"
        INSERT INTO `user` (`userkey`)
        VALUES (?)
        ON CONFLICT (`userkey`) DO NOTHING
        ",
        params![user],
    )?;
    let updated = txn.execute(
        r"
        INSERT INTO `room_member` (`rid`, `uid`, `permission`)
        SELECT :rid, `uid`, :perm
        FROM `user`
        WHERE `userkey` = :userkey
        ON CONFLICT (`rid`, `uid`) DO NOTHING
        ",
        named_params! {
           ":rid": rid,
           ":userkey": user,
           ":perm": permission,
        },
    )?;
    if updated == 0 {
        return Err(error_response!(
            StatusCode::CONFLICT,
            "exists",
            "the user is already in the room",
        ));
    }
    txn.commit()?;
    Ok(())
}

async fn room_leave(st: &AppState, rid: Id, user: UserKey) -> Result<(), ApiError> {
    let mut conn = st.db.get();
    let txn = conn.transaction()?;

    let uid = txn
        .query_row(
            r"
            SELECT `uid`
            FROM `room_member`
            JOIN `user` USING (`uid`)
            WHERE `rid` = :rid AND
                `userkey` = :userkey
            ",
            named_params! {
                ":rid": rid,
                ":userkey": user,
            },
            |row| row.get::<_, u64>("uid"),
        )
        .optional()?
        .ok_or_else(|| {
            error_response!(
                StatusCode::NOT_FOUND,
                "not_found",
                "the room does not exist or user is not a room member",
            )
        })?;

    txn.execute(
        r"
        DELETE FROM `room_member`
        WHERE `rid` = :rid AND
            `uid` = :uid
        ",
        named_params! {
            ":rid": rid,
            ":uid": uid,
        },
    )?;

    txn.commit()?;
    Ok(())
}

async fn room_msg_mark_seen(
    st: ArcState,
    R(Path((rid, cid)), _): RE<Path<(Id, u64)>>,
    Auth(user): Auth,
) -> Result<StatusCode, ApiError> {
    let changed = st.db.get().execute(
        r"
        UPDATE `room_member`
        SET `last_seen_cid` = MAX(`last_seen_cid`, :cid)
        WHERE
            `rid` = :rid AND
            `uid` = (SELECT `uid` FROM `user` WHERE `userkey` = :userkey)
        ",
        named_params! {
            ":cid": cid,
            ":rid": rid,
            ":userkey": user,
        },
    )?;

    if changed != 1 {
        return Err(error_response!(
            StatusCode::NOT_FOUND,
            "not_found",
            "the room does not exist or the user is not a room member",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}
