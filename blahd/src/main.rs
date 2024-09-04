use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use axum::extract::ws;
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::WithRejection as R;
use blah::types::{
    ChatItem, ChatPayload, CreateRoomPayload, MemberPermission, RoomAdminOp, RoomAdminPayload,
    RoomAttrs, ServerPermission, Signee, UserKey, WithSig,
};
use config::Config;
use database::Database;
use ed25519_dalek::SIGNATURE_LENGTH;
use middleware::{ApiError, MaybeAuth, ResultExt as _, SignedJson};
use parking_lot::Mutex;
use rusqlite::{named_params, params, Connection, OptionalExtension, Row, ToSql};
use serde::{Deserialize, Serialize};
use url::Url;
use utils::ExpiringSet;
use uuid::Uuid;

#[macro_use]
mod middleware;
mod config;
mod database;
mod event;
mod utils;

/// Blah Chat Server
#[derive(Debug, clap::Parser)]
#[clap(about, version = option_env!("CFG_RELEASE").unwrap_or(env!("CARGO_PKG_VERSION")))]
enum Cli {
    /// Run the server with given configuration.
    Serve {
        /// The path to the configuration file.
        #[arg(long, short)]
        config: PathBuf,
    },

    /// Validate the configuration file and exit.
    Validate {
        /// The path to the configuration file.
        #[arg(long, short)]
        config: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = <Cli as clap::Parser>::parse();

    fn parse_config(path: &std::path::Path) -> Result<Config> {
        let src = std::fs::read_to_string(path)?;
        let config = basic_toml::from_str::<Config>(&src)?;
        config.validate()?;
        Ok(config)
    }

    match cli {
        Cli::Serve { config } => {
            let config = parse_config(&config)?;
            let st = AppState::init(config).context("failed to initialize state")?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to initialize tokio runtime")?
                .block_on(main_async(st))
        }
        Cli::Validate { config } => {
            parse_config(&config)?;
            Ok(())
        }
    }
}

// Locks must be grabbed in the field order.
#[derive(Debug)]
struct AppState {
    db: Database,
    used_nonces: Mutex<ExpiringSet<u32>>,
    event: event::State,

    config: Config,
}

impl AppState {
    fn init(config: Config) -> Result<Self> {
        Ok(Self {
            db: Database::open(&config.database).context("failed to open database")?,
            used_nonces: Mutex::new(ExpiringSet::new(Duration::from_secs(
                config.server.timestamp_tolerance_secs,
            ))),
            event: event::State::default(),

            config,
        })
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
        if timestamp_diff > self.config.server.timestamp_tolerance_secs {
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

async fn main_async(st: AppState) -> Result<()> {
    let st = Arc::new(st);

    let app = Router::new()
        .route("/ws", get(handle_ws))
        .route("/room", get(room_list))
        .route("/room/create", post(room_create))
        .route("/room/:ruuid", get(room_get_metadata))
        // NB. Sync with `feed_url` and `next_url` generation.
        .route("/room/:ruuid/feed.json", get(room_get_feed))
        .route("/room/:ruuid/item", get(room_get_item).post(room_post_item))
        .route("/room/:ruuid/admin", post(room_admin))
        .with_state(st.clone())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            st.config.server.max_request_len,
        ))
        // NB. This comes at last (outmost layer), so inner errors will still be wrapped with
        // correct CORS headers. Also `Authorization` must be explicitly included besides `*`.
        .layer(
            tower_http::cors::CorsLayer::permissive()
                .allow_headers([header::HeaderName::from_static("*"), header::AUTHORIZATION]),
        );

    let listener = tokio::net::TcpListener::bind(&st.config.server.listen)
        .await
        .context("failed to listen on socket")?;
    tracing::info!("listening on {}", st.config.server.listen);
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

    axum::serve(listener, app)
        .await
        .context("failed to serve")?;
    Ok(())
}

type RE<T> = R<T, ApiError>;

async fn handle_ws(State(st): ArcState, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |mut socket| async move {
        match event::handle_ws(st, &mut socket).await {
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

#[derive(Debug, Serialize)]
struct RoomList {
    rooms: Vec<RoomMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_token: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ListRoomParams {
    filter: ListRoomFilter,
    // Workaround: serde(flatten) breaks deserialization
    // See: https://github.com/nox/serde_urlencoded/issues/33
    skip_token: Option<u64>,
    top: Option<NonZeroUsize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ListRoomFilter {
    Public,
    Joined,
}

async fn room_list(
    st: ArcState,
    params: RE<Query<ListRoomParams>>,
    auth: MaybeAuth,
) -> Result<Json<RoomList>, ApiError> {
    let pagination = Pagination {
        skip_token: params.skip_token,
        top: params.top,
    };
    let page_len = pagination.effective_page_len(&st);
    let start_rid = pagination.skip_token.unwrap_or(0);

    let query = |sql: &str, params: &[(&str, &dyn ToSql)]| -> Result<RoomList, ApiError> {
        let mut last_rid = None;
        let rooms = st
            .db
            .get()
            .prepare(sql)?
            .query_map(params, |row| {
                // TODO: Extract this into a function.
                last_rid = Some(row.get::<_, u64>("rid")?);
                let ruuid = row.get("ruuid")?;
                let title = row.get("title")?;
                let attrs = row.get("attrs")?;
                let last_chat = row
                    .get::<_, Option<UserKey>>("userkey")?
                    .map(|user| {
                        Ok::<_, rusqlite::Error>(ChatItem {
                            sig: row.get("sig")?,
                            signee: Signee {
                                nonce: row.get("nonce")?,
                                timestamp: row.get("timestamp")?,
                                user,
                                payload: ChatPayload {
                                    rich_text: row.get("rich_text")?,
                                    room: ruuid,
                                },
                            },
                        })
                    })
                    .transpose()?;
                Ok(RoomMetadata {
                    ruuid,
                    title,
                    attrs,
                    last_chat,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let skip_token = (rooms.len() == page_len).then_some(()).and(last_rid);
        Ok(RoomList { rooms, skip_token })
    };

    match params.filter {
        ListRoomFilter::Public => query(
            r"
            SELECT `rid`, `ruuid`, `title`, `attrs`,
                `last_author`.`userkey` AS `userkey`, `timestamp`, `nonce`, `sig`, `rich_text`
            FROM `room`
            LEFT JOIN `room_item` USING (`rid`)
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
                    `rid`, `ruuid`, `title`, `attrs`,
                    `last_author`.`userkey`, `timestamp`, `nonce`, `sig`, `rich_text`
                FROM `user`
                JOIN `room_member` USING (`uid`)
                JOIN `room` USING (`rid`)
                LEFT JOIN `room_item` USING (`rid`)
                LEFT JOIN `user` AS `last_author` ON (`last_author`.`uid` = `room_item`.`uid`)
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
    }
    .map(Json)
}

async fn room_create(
    st: ArcState,
    SignedJson(params): SignedJson<CreateRoomPayload>,
) -> Result<Json<Uuid>, ApiError> {
    let members = &params.signee.payload.members.0;
    if !members
        .iter()
        .any(|m| m.user == params.signee.user && m.permission == MemberPermission::ALL)
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
            params![params.signee.user],
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

    let ruuid = Uuid::new_v4();

    let txn = conn.transaction()?;
    txn.execute(
        r"
        INSERT INTO `room` (`ruuid`, `title`, `attrs`)
        VALUES (:ruuid, :title, :attrs)
        ",
        named_params! {
            ":ruuid": ruuid,
            ":title": params.signee.payload.title,
            ":attrs": params.signee.payload.attrs,
        },
    )?;
    let rid = txn.last_insert_rowid() as u64;
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

    Ok(Json(ruuid))
}

/// Pagination query parameters.
///
/// Field names are inspired by Microsoft's design, which is an extension to OData spec.
/// See: <https://learn.microsoft.com/en-us/graph/query-parameters#odata-system-query-options>
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Pagination {
    /// A opaque token from previous response to fetch the next page.
    skip_token: Option<u64>,
    /// Maximum page size.
    top: Option<NonZeroUsize>,
}

impl Pagination {
    fn effective_page_len(&self, st: &AppState) -> usize {
        self.top
            .unwrap_or(usize::MAX.try_into().expect("not zero"))
            .min(st.config.server.max_page_len)
            .get()
    }
}

#[derive(Debug, Serialize)]
struct RoomItems {
    items: Vec<ChatItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_token: Option<String>,
}

async fn room_get_item(
    st: ArcState,
    R(Path(ruuid), _): RE<Path<Uuid>>,
    R(Query(pagination), _): RE<Query<Pagination>>,
    auth: MaybeAuth,
) -> Result<Json<RoomItems>, ApiError> {
    let (items, skip_token) = {
        let conn = st.db.get();
        get_room_if_readable(&conn, ruuid, auth.into_optional()?.as_ref(), |_row| Ok(()))?;
        query_room_items(&st, &conn, ruuid, pagination)?
    };
    let items = items.into_iter().map(|(_, item)| item).collect();
    Ok(Json(RoomItems {
        items,
        skip_token: skip_token.map(|x| x.to_string()),
    }))
}

async fn room_get_metadata(
    st: ArcState,
    R(Path(ruuid), _): RE<Path<Uuid>>,
    auth: MaybeAuth,
) -> Result<Json<RoomMetadata>, ApiError> {
    let (title, attrs) =
        get_room_if_readable(&st.db.get(), ruuid, auth.into_optional()?.as_ref(), |row| {
            Ok((
                row.get::<_, String>("title")?,
                row.get::<_, RoomAttrs>("attrs")?,
            ))
        })?;

    Ok(Json(RoomMetadata {
        ruuid,
        title,
        attrs,
        last_chat: None,
    }))
}

async fn room_get_feed(
    st: ArcState,
    R(Path(ruuid), _): RE<Path<Uuid>>,
    R(Query(pagination), _): RE<Query<Pagination>>,
) -> Result<impl IntoResponse, ApiError> {
    let title;
    let (items, skip_token) = {
        let conn = st.db.get();
        title = get_room_if_readable(&conn, ruuid, None, |row| row.get::<_, String>("title"))?;
        query_room_items(&st, &conn, ruuid, pagination)?
    };

    let items = items
        .into_iter()
        .map(|(cid, item)| {
            let time = SystemTime::UNIX_EPOCH + Duration::from_secs(item.signee.timestamp);
            let author = FeedAuthor {
                name: item.signee.user.to_string(),
            };
            FeedItem {
                id: cid.to_string(),
                content_html: item.signee.payload.rich_text.html().to_string(),
                date_published: humantime::format_rfc3339(time).to_string(),
                authors: (author,),
                extra: FeedItemExtra {
                    timestamp: item.signee.timestamp,
                    nonce: item.signee.nonce,
                    sig: item.sig,
                },
            }
        })
        .collect::<Vec<_>>();

    let feed_url = st
        .config
        .server
        .base_url
        .join(&format!("/room/{ruuid}/feed.json"))
        .expect("base_url must be valid");
    let next_url = skip_token.map(|skip_token| {
        let next_params = Pagination {
            skip_token: Some(skip_token),
            top: pagination.top,
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

#[derive(Debug, Serialize)]
pub struct RoomMetadata {
    pub ruuid: Uuid,
    pub title: String,
    pub attrs: RoomAttrs,

    /// Optional extra information. Only included by the global room list response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_chat: Option<ChatItem>,
}

fn get_room_if_readable<T>(
    conn: &rusqlite::Connection,
    ruuid: Uuid,
    user: Option<&UserKey>,
    f: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<T, ApiError> {
    conn.query_row(
        r"
        SELECT `rid`, `title`, `attrs`
        FROM `room`
        WHERE `ruuid` = :ruuid AND
            ((`attrs` & :perm) = :perm OR
            EXISTS(SELECT 1
                FROM `room_member`
                JOIN `user` USING (`uid`)
                WHERE `room_member`.`rid` = `room`.`rid` AND
                    `userkey` = :userkey))
        ",
        named_params! {
            ":perm": RoomAttrs::PUBLIC_READABLE,
            ":ruuid": ruuid,
            ":userkey": user,
        },
        f,
    )
    .optional()?
    .ok_or_else(|| error_response!(StatusCode::NOT_FOUND, "not_found", "room not found"))
}

type ChatItemWithId = (u64, ChatItem);

/// Get room items with pagination parameters,
/// return a page of items and the next skip_token if this is not the last page.
fn query_room_items(
    st: &AppState,
    conn: &Connection,
    ruuid: Uuid,
    pagination: Pagination,
) -> Result<(Vec<ChatItemWithId>, Option<u64>), ApiError> {
    let page_len = pagination.effective_page_len(st);
    let mut stmt = conn.prepare(
        r"
        SELECT `cid`, `timestamp`, `nonce`, `sig`, `userkey`, `sig`, `rich_text`
        FROM `room`
        JOIN `room_item` USING (`rid`)
        JOIN `user` USING (`uid`)
        WHERE `ruuid` = :ruuid AND
            (:before_cid IS NULL OR `cid` < :before_cid)
        ORDER BY `cid` DESC
        LIMIT :limit
        ",
    )?;
    let items = stmt
        .query_and_then(
            named_params! {
                ":ruuid": ruuid,
                ":before_cid": pagination.skip_token,
                ":limit": page_len,
            },
            |row| {
                let cid = row.get::<_, u64>("cid")?;
                let item = ChatItem {
                    sig: row.get("sig")?,
                    signee: Signee {
                        nonce: row.get("nonce")?,
                        timestamp: row.get("timestamp")?,
                        user: row.get("userkey")?,
                        payload: ChatPayload {
                            room: ruuid,
                            rich_text: row.get("rich_text")?,
                        },
                    },
                };
                Ok((cid, item))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let skip_token =
        (items.len() == page_len).then(|| items.last().expect("page must not be empty").0);

    Ok((items, skip_token))
}

async fn room_post_item(
    st: ArcState,
    R(Path(ruuid), _): RE<Path<Uuid>>,
    SignedJson(chat): SignedJson<ChatPayload>,
) -> Result<Json<u64>, ApiError> {
    if ruuid != chat.signee.payload.room {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "URI and payload room id mismatch",
        ));
    }

    let (cid, txs) = {
        let conn = st.db.get();
        let Some((rid, uid)) = conn
            .query_row(
                r"
                SELECT `rid`, `uid`
                FROM `room`
                JOIN `room_member` USING (`rid`)
                JOIN `user` USING (`uid`)
                WHERE `ruuid` = :ruuid AND
                    `userkey` = :userkey AND
                    (`room_member`.`permission` & :perm) = :perm
                ",
                named_params! {
                    ":ruuid": ruuid,
                    ":userkey": &chat.signee.user,
                    ":perm": MemberPermission::POST_CHAT,
                },
                |row| Ok((row.get::<_, u64>("rid")?, row.get::<_, u64>("uid")?)),
            )
            .optional()?
        else {
            return Err(error_response!(
                StatusCode::FORBIDDEN,
                "permission_denied",
                "the user does not have permission to post in this room",
            ));
        };

        let cid = conn.query_row(
            r"
            INSERT INTO `room_item` (`rid`, `uid`, `timestamp`, `nonce`, `sig`, `rich_text`)
            VALUES (:rid, :uid, :timestamp, :nonce, :sig, :rich_text)
            RETURNING `cid`
            ",
            named_params! {
                ":rid": rid,
                ":uid": uid,
                ":timestamp": chat.signee.timestamp,
                ":nonce": chat.signee.nonce,
                ":rich_text": &chat.signee.payload.rich_text,
                ":sig": chat.sig,
            },
            |row| row.get::<_, u64>(0),
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
    R(Path(ruuid), _): RE<Path<Uuid>>,
    SignedJson(op): SignedJson<RoomAdminPayload>,
) -> Result<StatusCode, ApiError> {
    if ruuid != op.signee.payload.room {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "URI and payload room id mismatch",
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
            if permission.is_empty() || !MemberPermission::MAX_SELF_ADD.contains(permission) {
                return Err(error_response!(
                    StatusCode::BAD_REQUEST,
                    "deserialization",
                    "invalid permission",
                ));
            }
            room_join(&st, ruuid, user, permission).await?;
        }
        RoomAdminOp::RemoveMember { user } => {
            if user != op.signee.user {
                return Err(error_response!(
                    StatusCode::NOT_IMPLEMENTED,
                    "not_implemented",
                    "only self-removing is implemented yet",
                ));
            }
            room_leave(&st, ruuid, user).await?;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn room_join(
    st: &AppState,
    ruuid: Uuid,
    user: UserKey,
    permission: MemberPermission,
) -> Result<(), ApiError> {
    let mut conn = st.db.get();
    let txn = conn.transaction()?;
    let Some(rid) = txn
        .query_row(
            r"
            SELECT `rid`
            FROM `room`
            WHERE `ruuid` = :ruuid AND
                (`room`.`attrs` & :joinable) = :joinable
            ",
            named_params! {
                ":ruuid": ruuid,
                ":joinable": RoomAttrs::PUBLIC_JOINABLE,
            },
            |row| row.get::<_, u64>("rid"),
        )
        .optional()?
    else {
        return Err(error_response!(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "room does not exists or user is not allowed to join this room",
        ));
    };
    txn.execute(
        r"
        INSERT INTO `user` (`userkey`)
        VALUES (?)
        ON CONFLICT (`userkey`) DO NOTHING
        ",
        params![user],
    )?;
    txn.execute(
        r"
        INSERT INTO `room_member` (`rid`, `uid`, `permission`)
        SELECT :rid, `uid`, :perm
        FROM `user`
        WHERE `userkey` = :userkey
        ON CONFLICT (`rid`, `uid`) DO UPDATE SET
            `permission` = :perm
        ",
        named_params! {
           ":rid": rid,
           ":userkey": user,
           ":perm": permission,
        },
    )?;
    txn.commit()?;
    Ok(())
}

async fn room_leave(st: &AppState, ruuid: Uuid, user: UserKey) -> Result<(), ApiError> {
    let mut conn = st.db.get();
    let txn = conn.transaction()?;

    let Some((rid, uid)) = txn
        .query_row(
            r"
            SELECT `rid`, `uid`
            FROM `room_member`
            JOIN `room` USING (`rid`)
            JOIN `user` USING (`uid`)
            WHERE `ruuid` = :ruuid AND
                `userkey` = :userkey
            ",
            named_params! {
                ":ruuid": ruuid,
                ":userkey": user,
            },
            |row| Ok((row.get::<_, u64>("rid")?, row.get::<_, u64>("uid")?)),
        )
        .optional()?
    else {
        return Err(error_response!(
            StatusCode::NOT_FOUND,
            "not_found",
            "room does not exists or user is not a room member",
        ));
    };
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
