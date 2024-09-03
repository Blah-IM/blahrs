use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use axum::extract::ws;
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::WithRejection;
use blah::types::{
    ChatItem, ChatPayload, CreateRoomPayload, MemberPermission, RoomAdminPayload, RoomAttrs,
    ServerPermission, Signee, UserKey, WithSig,
};
use config::Config;
use ed25519_dalek::SIGNATURE_LENGTH;
use middleware::{ApiError, OptionalAuth, SignedJson};
use rusqlite::{named_params, params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use utils::ExpiringSet;
use uuid::Uuid;

#[macro_use]
mod middleware;
mod config;
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
            let db = rusqlite::Connection::open(&config.database.path)
                .context("failed to open database")?;
            let st = AppState::init(config, db).context("failed to initialize state")?;
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
    conn: Mutex<rusqlite::Connection>,
    used_nonces: Mutex<ExpiringSet<u32>>,
    event: event::State,

    config: Config,
}

impl AppState {
    fn init(config: Config, conn: rusqlite::Connection) -> Result<Self> {
        static INIT_SQL: &str = include_str!("../init.sql");

        // Should be validated by `Config`.
        assert!(!config.server.base_url.ends_with('/'));

        conn.execute_batch(INIT_SQL)
            .context("failed to initialize database")?;
        Ok(Self {
            conn: Mutex::new(conn),
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
        if !self
            .used_nonces
            .lock()
            .unwrap()
            .try_insert(data.signee.nonce)
        {
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
        .route("/room/create", post(room_create))
        .route("/room/:ruuid", get(room_get_metadata))
        // NB. Sync with `feed_url` and `next_url` generation.
        .route("/room/:ruuid/feed.json", get(room_get_feed))
        .route("/room/:ruuid/item", get(room_get_item).post(room_post_item))
        .route("/room/:ruuid/admin", post(room_admin))
        .with_state(st.clone())
        // NB. This comes at last (outmost layer), so inner errors will still be wrapped with
        // correct CORS headers.
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            st.config.server.max_request_len,
        ))
        .layer(tower_http::cors::CorsLayer::permissive());

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

    let mut conn = st.conn.lock().unwrap();
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
    let rid = txn.query_row(
        r"
        INSERT INTO `room` (`ruuid`, `title`)
        VALUES (:ruuid, :title)
        RETURNING `rid`
        ",
        named_params! {
            ":ruuid": ruuid,
            ":title": params.signee.payload.title,
        },
        |row| row.get::<_, u64>(0),
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

    Ok(Json(ruuid))
}

// NB. `next_url` generation depends on this structure.
#[derive(Debug, Deserialize)]
struct GetRoomItemParams {
    #[serde(
        default,
        deserialize_with = "serde_aux::field_attributes::deserialize_number_from_string"
    )]
    before_id: u64,
    page_len: Option<usize>,
}

async fn room_get_item(
    st: ArcState,
    WithRejection(Path(ruuid), _): WithRejection<Path<Uuid>, ApiError>,
    WithRejection(params, _): WithRejection<Query<GetRoomItemParams>, ApiError>,
    OptionalAuth(user): OptionalAuth,
) -> Result<impl IntoResponse, ApiError> {
    let (room_meta, items) = query_room_items(&st, ruuid, user.as_ref(), &params)?;

    // TODO: This format is to-be-decided. Or do we even need this interface other than
    // `feed.json`?
    Ok(Json((room_meta, items)))
}

async fn room_get_metadata(
    st: ArcState,
    WithRejection(Path(ruuid), _): WithRejection<Path<Uuid>, ApiError>,
    OptionalAuth(user): OptionalAuth,
) -> Result<Json<RoomMetadata>, ApiError> {
    let (room_meta, _) = query_room_items(
        &st,
        ruuid,
        user.as_ref(),
        &GetRoomItemParams {
            before_id: 0,
            page_len: Some(0),
        },
    )?;
    Ok(Json(room_meta))
}

async fn room_get_feed(
    st: ArcState,
    WithRejection(Path(ruuid), _): WithRejection<Path<Uuid>, ApiError>,
    params: Query<GetRoomItemParams>,
) -> Result<impl IntoResponse, ApiError> {
    let (room_meta, items) = query_room_items(&st, ruuid, None, &params)?;

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

    let page_len = params
        .page_len
        .unwrap_or(st.config.server.max_page_len)
        .min(st.config.server.max_page_len);

    let base_url = &st.config.server.base_url;
    let feed_url = format!("{base_url}/room/{ruuid}/feed.json");
    let next_url = (items.len() == page_len).then(|| {
        let last_id = &items.last().expect("page size is not 0").id;
        format!("{feed_url}?before_id={last_id}")
    });
    let feed = FeedRoom {
        title: room_meta.title,
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
    feed_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_url: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct RoomMetadata {
    pub title: String,
    pub attrs: RoomAttrs,
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

fn query_room_items(
    st: &AppState,
    ruuid: Uuid,
    user: Option<&UserKey>,
    params: &GetRoomItemParams,
) -> Result<(RoomMetadata, Vec<(u64, ChatItem)>), ApiError> {
    let conn = st.conn.lock().unwrap();

    let (rid, title, attrs) = get_room_if_readable(&conn, ruuid, user, |row| {
        Ok((
            row.get::<_, u64>("rid")?,
            row.get::<_, String>("title")?,
            row.get::<_, RoomAttrs>("attrs")?,
        ))
    })?;

    let room_meta = RoomMetadata { title, attrs };

    if params.page_len == Some(0) {
        return Ok((room_meta, Vec::new()));
    }

    let page_len = params
        .page_len
        .unwrap_or(st.config.server.max_page_len)
        .min(st.config.server.max_page_len);

    let mut stmt = conn.prepare(
        r"
        SELECT `cid`, `timestamp`, `nonce`, `sig`, `userkey`, `sig`, `rich_text`
        FROM `room_item`
        JOIN `user` USING (`uid`)
        WHERE `rid` = :rid AND
            (:before_cid = 0 OR `cid` < :before_cid)
        ORDER BY `cid` DESC
        LIMIT :limit
        ",
    )?;
    let items = stmt
        .query_and_then(
            named_params! {
                ":rid": rid,
                ":before_cid": params.before_id,
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

    Ok((room_meta, items))
}

async fn room_post_item(
    st: ArcState,
    Path(ruuid): Path<Uuid>,
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
        let conn = st.conn.lock().unwrap();
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
        let listeners = st.event.user_listeners.lock().unwrap();
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
    Path(ruuid): Path<Uuid>,
    SignedJson(op): SignedJson<RoomAdminPayload>,
) -> Result<StatusCode, ApiError> {
    if ruuid != *op.signee.payload.room() {
        return Err(error_response!(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "URI and payload room id mismatch",
        ));
    }

    let RoomAdminPayload::AddMember {
        permission, user, ..
    } = op.signee.payload;
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

    let mut conn = st.conn.lock().unwrap();
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

    Ok(StatusCode::NO_CONTENT)
}
