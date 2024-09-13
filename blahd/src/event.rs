use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{bail, Context as _, Result};
use axum::extract::ws::{Message, WebSocket};
use blah_types::{AuthPayload, Signed, SignedChatMsg};
use futures_util::future::Either;
use futures_util::stream::SplitSink;
use futures_util::{stream_select, SinkExt as _, Stream, StreamExt};
use parking_lot::Mutex;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;

use crate::config::ServerConfig;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub enum Incoming {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outgoing<'a> {
    /// A message from a joined room.
    Msg(&'a SignedChatMsg),
    /// The receiver is too slow to receive and some events and are dropped.
    // FIXME: Should we indefinitely buffer them or just disconnect the client instead?
    Lagged,
}

#[derive(Debug, Default)]
pub struct State {
    pub user_listeners: Mutex<HashMap<u64, UserEventSender>>,
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
    config: &'c ServerConfig,
}

impl WsSenderWrapper<'_, '_> {
    async fn send(&mut self, msg: &Outgoing<'_>) -> Result<()> {
        let data = serde_json::to_string(&msg).expect("serialization cannot fail");
        let fut = tokio::time::timeout(
            self.config.ws_send_timeout_sec,
            self.inner.send(Message::Text(data)),
        );
        match fut.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_send_err)) => Err(StreamEnded.into()),
            Err(_elapsed) => bail!("send timeout"),
        }
    }
}

type UserEventSender = broadcast::Sender<Arc<SignedChatMsg>>;

#[derive(Debug)]
struct UserEventReceiver {
    rx: BroadcastStream<Arc<SignedChatMsg>>,
    st: Arc<AppState>,
    uid: u64,
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
    type Item = Result<Arc<SignedChatMsg>, BroadcastStreamRecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_next_unpin(cx)
    }
}

pub async fn handle_ws(st: Arc<AppState>, ws: &mut WebSocket) -> Result<Infallible> {
    let (ws_tx, ws_rx) = ws.split();
    let mut ws_rx = ws_rx.map(|ret| ret.and_then(|msg| msg.into_text()).map_err(|_| StreamEnded));
    let mut ws_tx = WsSenderWrapper {
        inner: ws_tx,
        config: &st.config,
    };

    let uid = {
        let payload = tokio::time::timeout(st.config.ws_auth_timeout_sec, ws_rx.next())
            .await
            .context("authentication timeout")?
            .ok_or(StreamEnded)??;
        let auth = serde_json::from_str::<Signed<AuthPayload>>(&payload)?;
        st.verify_signed_data(&auth)?;

        st.db
            .get()
            .query_row(
                r"
                SELECT `uid`
                FROM `user`
                WHERE `userkey` = ?
                ",
                params![auth.signee.user],
                |row| row.get::<_, u64>(0),
            )
            .optional()?
            .context("invalid user")?
    };

    tracing::debug!(%uid, "user connected");

    let event_rx = {
        let rx = match st.event.user_listeners.lock().entry(uid) {
            Entry::Occupied(ent) => ent.get().subscribe(),
            Entry::Vacant(ent) => {
                let (tx, rx) = broadcast::channel(st.config.ws_event_queue_len);
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
            Either::Left(msg) => match serde_json::from_str::<Incoming>(&msg?)? {},
            Either::Right(ret) => {
                let msg = match &ret {
                    Ok(chat) => Outgoing::Msg(chat),
                    Err(BroadcastStreamRecvError::Lagged(_)) => Outgoing::Lagged,
                };
                // TODO: Concurrent send.
                ws_tx.send(&msg).await?;
            }
        }
    }
}
