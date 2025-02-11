use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use axum::extract::ws::{close_code, CloseFrame, Message, WebSocket};
use axum::extract::WebSocketUpgrade;
use axum::response::Response;
use blah_types::msg::{AuthPayload, SignedChatMsgWithId};
use blah_types::server::{ClientEvent, ServerEvent};
use blah_types::Signed;
use futures_util::future::Either;
use futures_util::stream::SplitSink;
use futures_util::{stream_select, SinkExt as _, Stream, StreamExt};
use parking_lot::Mutex;
use serde::{de, Deserialize};
use serde_inline_default::serde_inline_default;
use tokio::sync::broadcast;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;

use crate::database::TransactionOps;
use crate::{AppState, ArcState};

#[serde_inline_default]
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    #[serde(deserialize_with = "de_duration_sec")]
    pub auth_timeout_sec: Duration,
    #[serde(deserialize_with = "de_duration_sec")]
    pub send_timeout_sec: Duration,
    pub event_queue_len: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auth_timeout_sec: Duration::from_secs(15),
            send_timeout_sec: Duration::from_secs(15),
            event_queue_len: 1024,
        }
    }
}

fn de_duration_sec<'de, D: de::Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
    <u64>::deserialize(de).map(Duration::from_secs)
}

#[derive(Debug, Default)]
pub struct State {
    user_listeners: Mutex<HashMap<i64, UserEventSender>>,
}

impl State {
    pub fn on_room_msg(&self, msg: SignedChatMsgWithId, room_members: Vec<i64>) {
        let listeners = self.user_listeners.lock();
        let mut cnt = 0usize;
        let msg = Arc::new(ServerEvent::Msg(msg));
        for uid in &room_members {
            if let Some(tx) = listeners.get(uid) {
                if tx.send(msg.clone()).is_ok() {
                    cnt += 1;
                }
            }
        }
        if cnt != 0 {
            tracing::debug!("broadcasted event to {cnt} clients");
        }
    }
}

#[derive(Debug)]
pub struct StreamEnded;

impl fmt::Display for StreamEnded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("stream unexpectedly ended")
    }
}

impl std::error::Error for StreamEnded {}

struct WsSenderWrapper<'ws, 'c> {
    inner: SplitSink<&'ws mut WebSocket, Message>,
    config: &'c Config,
}

impl WsSenderWrapper<'_, '_> {
    async fn send(&mut self, msg: &ServerEvent) -> Result<()> {
        let data = serde_json::to_string(&msg).expect("serialization cannot fail");
        let fut = tokio::time::timeout(
            self.config.send_timeout_sec,
            self.inner.send(Message::Text(data.into())),
        );
        match fut.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_send_err)) => Err(StreamEnded.into()),
            Err(_elapsed) => bail!("send timeout"),
        }
    }
}

type UserEventSender = broadcast::Sender<Arc<ServerEvent>>;

#[derive(Debug)]
struct UserEventReceiver {
    rx: BroadcastStream<Arc<ServerEvent>>,
    st: Arc<AppState>,
    uid: i64,
}

impl Drop for UserEventReceiver {
    fn drop(&mut self) {
        tracing::debug!(%self.uid, "user disconnected");
        let mut map = self.st.event.user_listeners.lock();
        if let Some(tx) = map.get_mut(&self.uid) {
            if tx.receiver_count() == 1 {
                map.remove(&self.uid);
            }
        }
    }
}

impl Stream for UserEventReceiver {
    type Item = Result<Arc<ServerEvent>, BroadcastStreamRecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_next_unpin(cx)
    }
}

// TODO: Authenticate via HTTP query?
pub async fn get_ws(st: ArcState, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |mut socket| async move {
        match handle_ws(st.0, &mut socket).await {
            #[allow(
                unreachable_patterns,
                reason = "compatibility before min_exhaustive_patterns"
            )]
            Ok(never) => match never {},
            Err(err) if err.is::<StreamEnded>() => {}
            Err(err) => {
                tracing::debug!(%err, "ws error");
                let _: Result<_, _> = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: close_code::ERROR,
                        reason: err.to_string().into(),
                    })))
                    .await;
            }
        }
    })
}

async fn handle_ws(st: Arc<AppState>, ws: &mut WebSocket) -> Result<Infallible> {
    let config = &st.config.ws;
    let (ws_tx, ws_rx) = ws.split();
    let mut ws_rx = ws_rx.map(|ret| match ret {
        Ok(Message::Text(data)) => Ok(data),
        Ok(Message::Close(_)) | Err(_) => Err(StreamEnded.into()),
        _ => bail!("unexpected message type"),
    });
    let mut ws_tx = WsSenderWrapper {
        inner: ws_tx,
        config,
    };

    let uid = {
        let payload = tokio::time::timeout(config.auth_timeout_sec, ws_rx.next())
            .await
            .context("authentication timeout")?
            .ok_or(StreamEnded)??;
        let auth = serde_json::from_str::<Signed<AuthPayload>>(&payload)?;
        st.verify_signed_data(&auth)?;

        let (uid, _) = st.db.with_read(|txn| txn.get_user(&auth.signee.user))?;
        uid
    };

    tracing::debug!(%uid, "user connected");

    let event_rx = {
        let rx = match st.event.user_listeners.lock().entry(uid) {
            Entry::Occupied(ent) => ent.get().subscribe(),
            Entry::Vacant(ent) => {
                let (tx, rx) = broadcast::channel::<Arc<ServerEvent>>(config.event_queue_len);
                ent.insert(tx);
                rx
            }
        };
        UserEventReceiver {
            rx: rx.into(),
            st: st.clone(),
            uid,
        }
    };

    let mut stream = stream_select!(ws_rx.map(Either::Left), event_rx.map(Either::Right));
    loop {
        match stream.next().await.ok_or(StreamEnded)? {
            Either::Left(msg) => match serde_json::from_str::<ClientEvent>(&msg?)? {},
            Either::Right(ret) => {
                let event = match &ret {
                    Ok(event) => &**event,
                    Err(BroadcastStreamRecvError::Lagged(_)) => &ServerEvent::Lagged,
                };
                // TODO: Concurrent send.
                ws_tx.send(event).await?;
            }
        }
    }
}
