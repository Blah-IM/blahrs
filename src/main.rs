use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{ensure, Context, Result};
use axum::extract::{FromRequest, Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::response::{sse, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{async_trait, Json, Router};
use blah::types::{
    ChatItem, ChatPayload, CreateRoomPayload, RoomPermission, ServerPermission, UserKey, WithSig,
};
use ed25519_dalek::SIGNATURE_LENGTH;
use rusqlite::{named_params, params, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use uuid::Uuid;

const PAGE_LEN: usize = 1024;
const EVENT_QUEUE_LEN: usize = 1024;

#[derive(Debug, clap::Parser)]
struct Cli {
    /// Address to listen on.
    #[arg(long)]
    listen: String,

    /// Path to the SQLite database.
    #[arg(long)]
    database: PathBuf,

    /// The global absolute URL prefix where this service is hosted.
    /// It is for link generation and must not have trailing slash.
    #[arg(long)]
    base_url: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = <Cli as clap::Parser>::parse();

    let db = rusqlite::Connection::open(&cli.database).context("failed to open database")?;
    let st = AppState::init(&*cli.base_url, db).context("failed to initialize state")?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to initialize tokio runtime")?
        .block_on(main_async(cli, st))?;
    Ok(())
}

#[derive(Debug)]
struct AppState {
    conn: Mutex<rusqlite::Connection>,
    room_listeners: Mutex<HashMap<u64, broadcast::Sender<Arc<ChatItem>>>>,

    base_url: Box<str>,
}

impl AppState {
    fn init(base_url: impl Into<Box<str>>, conn: rusqlite::Connection) -> Result<Self> {
        static INIT_SQL: &str = include_str!("../init.sql");

        let base_url = base_url.into();
        ensure!(
            !base_url.ends_with('/'),
            "base_url must not has trailing slash",
        );

        conn.execute_batch(INIT_SQL)
            .context("failed to initialize database")?;
        Ok(Self {
            conn: Mutex::new(conn),
            room_listeners: Mutex::new(HashMap::new()),
            base_url,
        })
    }
}

type ArcState = State<Arc<AppState>>;

async fn main_async(opt: Cli, st: AppState) -> Result<()> {
    let app = Router::new()
        .route("/room/create", post(room_create))
        // NB. Sync with `feed_url` and `next_url` generation.
        .route("/room/:ruuid/feed.json", get(room_get_feed))
        .route("/room/:ruuid/event", get(room_event))
        .route("/room/:ruuid/item", post(room_post_item))
        .with_state(Arc::new(st))
        .layer(tower_http::cors::CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(&opt.listen)
        .await
        .context("failed to listen on socket")?;

    tracing::info!("listening on {}", opt.listen);
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

    axum::serve(listener, app)
        .await
        .context("failed to serve")?;
    Ok(())
}

fn from_db_error(err: rusqlite::Error) -> StatusCode {
    match err {
        rusqlite::Error::QueryReturnedNoRows => StatusCode::NOT_FOUND,
        err => {
            tracing::error!(%err, "database error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn room_create(
    st: ArcState,
    SignedJson(params): SignedJson<CreateRoomPayload>,
) -> Result<Json<Uuid>, StatusCode> {
    let mut conn = st.conn.lock().unwrap();
    let Some((uid, _perm)) = conn
        .query_row(
            r"
            SELECT `uid`, `permission`
            FROM `user`
            WHERE `userkey` = ?
            ",
            params![params.signee.user],
            |row| {
                let uid = row.get::<_, u64>("uid")?;
                let perm = row.get::<_, ServerPermission>("permission")?;
                Ok((uid, perm))
            },
        )
        .optional()
        .map_err(from_db_error)?
        .filter(|(_, perm)| perm.contains(ServerPermission::CREATE_ROOM))
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let ruuid = Uuid::new_v4();

    (|| {
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
        txn.execute(
            r"
            INSERT INTO `room_member` (`rid`, `uid`, `permission`)
            VALUES (:rid, :uid, :permission)
            ",
            named_params! {
                ":rid": rid,
                ":uid": uid,
                ":permission": RoomPermission::ALL,
            },
        )?;
        txn.commit()?;
        Ok(())
    })()
    .map_err(from_db_error)?;

    Ok(Json(ruuid))
}

// NB. `next_url` generation depends on this structure.
#[derive(Debug, Deserialize)]
struct GetRoomParams {
    #[serde(
        default,
        deserialize_with = "serde_aux::field_attributes::deserialize_number_from_string"
    )]
    before_id: u64,
}

async fn room_get_feed(
    st: ArcState,
    Path(ruuid): Path<Uuid>,
    params: Query<GetRoomParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let room_feed = query_feed(&st.conn.lock().unwrap(), &st.base_url, ruuid, &params)
        .map_err(from_db_error)?;
    Ok((
        [(header::CONTENT_TYPE, "application/feed+json")],
        Json(room_feed),
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
    content_text: String,
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

fn query_feed(
    conn: &rusqlite::Connection,
    base_url: &str,
    ruuid: Uuid,
    params: &GetRoomParams,
) -> rusqlite::Result<FeedRoom> {
    let (rid, title) = conn.query_row(
        r"
        SELECT `rid`, `title`
        FROM `room`
        WHERE `ruuid` = ?
        ",
        params![ruuid],
        |row| {
            let rid = row.get::<_, u64>("rid")?;
            let title = row.get::<_, String>("title")?;
            Ok((rid, title))
        },
    )?;

    let mut stmt = conn.prepare(
        r"
        SELECT `cid`, `timestamp`, `nonce`, `sig`, `userkey`, `sig`, `message`
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
                let timestamp = row.get::<_, u64>("timestamp")?;
                let time = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);
                let author = FeedAuthor {
                    name: row.get::<_, UserKey>("userkey")?.to_string(),
                };
                Ok(FeedItem {
                    id: row.get::<_, u64>("cid")?.to_string(),
                    content_text: row.get("message")?,
                    date_published: humantime::format_rfc3339(time).to_string(),
                    authors: (author,),
                    extra: FeedItemExtra {
                        timestamp,
                        nonce: row.get("nonce")?,
                        sig: row.get("sig")?,
                    },
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let feed_url = format!("{base_url}/room/{ruuid}/feed.json");
    let next_url = (items.len() == PAGE_LEN).then(|| {
        let last_id = &items.last().expect("page size is not 0").id;
        format!("{feed_url}?before_id={last_id}")
    });

    Ok(FeedRoom {
        title,
        items,
        next_url,
        feed_url,
    })
}

/// Extractor for verified JSON payload.
#[derive(Debug)]
struct SignedJson<T>(WithSig<T>);

#[async_trait]
impl<S: Send + Sync, T: Serialize + DeserializeOwned> FromRequest<S> for SignedJson<T> {
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(data) = <Json<WithSig<T>> as FromRequest<S>>::from_request(req, state)
            .await
            .map_err(|err| err.into_response())?;
        data.verify().map_err(|err| {
            tracing::debug!(%err, "unsigned payload");
            StatusCode::BAD_REQUEST.into_response()
        })?;
        Ok(Self(data))
    }
}

async fn room_post_item(
    st: ArcState,
    Path(ruuid): Path<Uuid>,
    SignedJson(chat): SignedJson<ChatPayload>,
) -> Result<Json<u64>, StatusCode> {
    if ruuid != chat.signee.payload.room {
        return Err(StatusCode::BAD_REQUEST);
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
                    `userkey` = :userkey
                ",
                named_params! {
                    ":ruuid": ruuid,
                    ":userkey": &chat.signee.user,
                },
                |row| Ok((row.get::<_, u64>("rid")?, row.get::<_, u64>("uid")?)),
            )
            .optional()
            .map_err(from_db_error)?
        else {
            tracing::debug!("rejected post: unpermitted user {:?}", chat.signee.user);
            return Err(StatusCode::UNAUTHORIZED);
        };

        let cid = conn
            .query_row(
                r"
                INSERT INTO `room_item` (`rid`, `uid`, `timestamp`, `nonce`, `sig`, `message`)
                VALUES (:rid, :uid, :timestamp, :nonce, :sig, :message)
                RETURNING `cid`
                ",
                named_params! {
                    ":rid": rid,
                    ":uid": uid,
                    ":timestamp": chat.signee.timestamp,
                    ":nonce": chat.signee.nonce,
                    ":message": &chat.signee.payload.text,
                    ":sig": chat.sig,
                },
                |row| row.get::<_, u64>(0),
            )
            .map_err(from_db_error)?;
        (rid, cid)
    };

    {
        let mut listeners = st.room_listeners.lock().unwrap();
        if let Some(tx) = listeners.get(&rid) {
            if tx.send(Arc::new(chat)).is_err() {
                // Clean up because all receivers died.
                listeners.remove(&rid);
            }
        }
    }

    Ok(Json(cid))
}

async fn room_event(
    Path(ruuid): Path<Uuid>,
    st: ArcState,
) -> Result<impl IntoResponse, StatusCode> {
    let rid = st
        .conn
        .lock()
        .unwrap()
        .query_row(
            r"
            SELECT `rid`
            FROM `room`
            WHERE `ruuid` = ?
            ",
            params![ruuid],
            |row| row.get::<_, u64>(0),
        )
        .map_err(from_db_error)?;

    let rx = match st.room_listeners.lock().unwrap().entry(rid) {
        Entry::Occupied(ent) => ent.get().subscribe(),
        Entry::Vacant(ent) => {
            let (tx, rx) = broadcast::channel(EVENT_QUEUE_LEN);
            ent.insert(tx);
            rx
        }
    };

    let stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|ret| {
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
