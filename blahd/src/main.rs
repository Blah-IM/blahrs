use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{sse, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::WithRejection;
use blah::types::{
    ChatItem, ChatPayload, CreateRoomPayload, MemberPermission, RoomAttrs, ServerPermission,
    Signee, UserKey, WithSig,
};
use config::Config;
use ed25519_dalek::SIGNATURE_LENGTH;
use middleware::{ApiError, OptionalAuth, SignedJson};
use rusqlite::{named_params, params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use utils::ExpiringSet;
use uuid::Uuid;

const PAGE_LEN: usize = 64;
const EVENT_QUEUE_LEN: usize = 1024;
const MAX_BODY_LEN: usize = 4 << 10; // 4KiB
const TIMESTAMP_TOLERENCE: u64 = 90;

#[macro_use]
mod middleware;
mod config;
mod utils;

#[derive(Debug, clap::Parser)]
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
    room_listeners: Mutex<HashMap<u64, broadcast::Sender<Arc<ChatItem>>>>,
    used_nonces: Mutex<ExpiringSet<u32>>,

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
            room_listeners: Mutex::new(HashMap::new()),
            used_nonces: Mutex::new(ExpiringSet::new(Duration::from_secs(TIMESTAMP_TOLERENCE))),

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
        if timestamp_diff > TIMESTAMP_TOLERENCE {
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
        .route("/room/create", post(room_create))
        // NB. Sync with `feed_url` and `next_url` generation.
        .route("/room/:ruuid/feed.json", get(room_get_feed))
        .route("/room/:ruuid/event", get(room_event))
        .route("/room/:ruuid/item", get(room_get_item).post(room_post_item))
        .with_state(st.clone())
        // NB. This comes at last (outmost layer), so inner errors will still be wraped with
        // correct CORS headers.
        .layer(tower_http::limit::RequestBodyLimitLayer::new(MAX_BODY_LEN))
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
}

async fn room_get_item(
    st: ArcState,
    WithRejection(Path(ruuid), _): WithRejection<Path<Uuid>, ApiError>,
    WithRejection(params, _): WithRejection<Query<GetRoomItemParams>, ApiError>,
    OptionalAuth(user): OptionalAuth,
) -> Result<impl IntoResponse, ApiError> {
    let (room_meta, items) =
        query_room_items(&st.conn.lock().unwrap(), ruuid, user.as_ref(), &params)?;

    // TODO: This format is to-be-decided. Or do we even need this interface other than
    // `feed.json`?
    Ok(Json((room_meta, items)))
}

async fn room_get_feed(
    st: ArcState,
    WithRejection(Path(ruuid), _): WithRejection<Path<Uuid>, ApiError>,
    params: Query<GetRoomItemParams>,
) -> Result<impl IntoResponse, ApiError> {
    let (room_meta, items) = query_room_items(&st.conn.lock().unwrap(), ruuid, None, &params)?;

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

    let base_url = &st.config.server.base_url;
    let feed_url = format!("{base_url}/room/{ruuid}/feed.json");
    let next_url = (items.len() == PAGE_LEN).then(|| {
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

/// Ref: https://www.jsonfeed.org/version/1.1/
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
    conn: &rusqlite::Connection,
    ruuid: Uuid,
    user: Option<&UserKey>,
    params: &GetRoomItemParams,
) -> Result<(RoomMetadata, Vec<(u64, ChatItem)>), ApiError> {
    let (rid, title, attrs) = get_room_if_readable(conn, ruuid, user, |row| {
        Ok((
            row.get::<_, u64>("rid")?,
            row.get::<_, String>("title")?,
            row.get::<_, RoomAttrs>("attrs")?,
        ))
    })?;

    let room_meta = RoomMetadata { title, attrs };

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
                ":limit": PAGE_LEN,
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

    let (rid, cid) = {
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
        (rid, cid)
    };

    let mut listeners = st.room_listeners.lock().unwrap();
    if let Some(tx) = listeners.get(&rid) {
        if tx.send(Arc::new(chat)).is_err() {
            // Clean up because all receivers died.
            listeners.remove(&rid);
        }
    }

    Ok(Json(cid))
}

async fn room_event(
    st: ArcState,
    Path(ruuid): Path<Uuid>,
    // TODO: There is actually no way to add headers via `EventSource` in client side.
    // But this API is kinda temporary and need a better replacement anyway.
    // So just only support public room for now.
    OptionalAuth(user): OptionalAuth,
) -> Result<impl IntoResponse, ApiError> {
    let rid = get_room_if_readable(&st.conn.lock().unwrap(), ruuid, user.as_ref(), |row| {
        row.get::<_, u64>(0)
    })?;

    let rx = match st.room_listeners.lock().unwrap().entry(rid) {
        Entry::Occupied(ent) => ent.get().subscribe(),
        Entry::Vacant(ent) => {
            let (tx, rx) = broadcast::channel(EVENT_QUEUE_LEN);
            ent.insert(tx);
            rx
        }
    };

    // Do clean up when this stream is closed.
    struct CleanOnDrop {
        st: Arc<AppState>,
        rid: u64,
    }
    impl Drop for CleanOnDrop {
        fn drop(&mut self) {
            if let Ok(mut listeners) = self.st.room_listeners.lock() {
                if let Some(tx) = listeners.get(&self.rid) {
                    if tx.receiver_count() == 0 {
                        listeners.remove(&self.rid);
                    }
                }
            }
        }
    }

    let _guard = CleanOnDrop { st: st.0, rid };

    let stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(move |ret| {
        let _guard = &_guard;
        // On stream closure or lagging, close the current stream so client can retry.
        let item = ret.ok()?;
        let evt = sse::Event::default()
            .json_data(&*item)
            .expect("serialization cannot fail");
        Some(Ok::<_, Infallible>(evt))
    });
    // NB. Send an empty event immediately to trigger client ready event.
    let first_event = sse::Event::default().comment("");
    let stream = futures_util::stream::iter(Some(Ok(first_event))).chain(stream);
    Ok(sse::Sse::new(stream).keep_alive(sse::KeepAlive::default()))
}