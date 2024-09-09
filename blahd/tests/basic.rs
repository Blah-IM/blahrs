// FIXME: False positive?
#![allow(clippy::unwrap_used)]
use std::fmt;
use std::future::IntoFuture;
use std::sync::Arc;

use blahd::{AppState, Database, RoomList};
use reqwest::Client;
use rstest::{fixture, rstest};
use rusqlite::Connection;
use tokio::net::TcpListener;

// Avoid name resolution.
const LOCALHOST: &str = "127.0.0.1";

#[derive(Debug)]
struct Server {
    port: u16,
}

impl Server {
    fn url(&self, rhs: impl fmt::Display) -> String {
        format!("http://{}:{}{}", LOCALHOST, self.port, rhs)
    }
}

#[fixture]
fn server() -> Server {
    let mut conn = Connection::open_in_memory().unwrap();
    Database::maybe_init(&mut conn).unwrap();
    let db = Database::from_raw(conn).unwrap();

    // Use std's to avoid async, since we need no name resolution.
    let listener = std::net::TcpListener::bind(format!("{LOCALHOST}:0")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = TcpListener::from_std(listener).unwrap();

    // TODO: Testing config is hard to build because it does have a `Default` impl.
    let config = basic_toml::from_str(&format!(
        r#"
listen = "" # TODO: unused
base_url = "http://{LOCALHOST}:{port}"
    "#
    ))
    .unwrap();
    let st = AppState::new(db, config);
    let router = blahd::router(Arc::new(st));

    tokio::spawn(axum::serve(listener, router).into_future());
    Server { port }
}

#[fixture]
fn client() -> Client {
    Client::new()
}

#[rstest]
#[tokio::test]
async fn smoke(client: Client, server: Server) {
    let got = client
        .get(server.url("/room?filter=public"))
        .send()
        .await
        .unwrap()
        .json::<RoomList>()
        .await
        .unwrap();
    let exp = RoomList {
        rooms: Vec::new(),
        skip_token: None,
    };
    assert_eq!(got, exp);
}
