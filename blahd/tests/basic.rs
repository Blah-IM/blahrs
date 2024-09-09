// FIXME: False positive?
#![allow(clippy::unwrap_used)]
use std::fmt;
use std::future::IntoFuture;
use std::sync::{Arc, LazyLock};

use anyhow::Result;
use blah::types::{
    get_timestamp, AuthPayload, CreateRoomPayload, Id, MemberPermission, RoomAttrs, RoomMember,
    RoomMemberList, ServerPermission, UserKey, WithSig,
};
use blahd::{ApiError, AppState, Database, RoomList, RoomMetadata};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use reqwest::{header, Method, StatusCode};
use rstest::{fixture, rstest};
use rusqlite::{params, Connection};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

// Avoid name resolution.
const LOCALHOST: &str = "127.0.0.1";

static ALICE_PRIV: LazyLock<SigningKey> = LazyLock::new(|| SigningKey::from_bytes(&[b'A'; 32]));
static ALICE: LazyLock<UserKey> = LazyLock::new(|| UserKey(ALICE_PRIV.verifying_key().to_bytes()));
static BOB_PRIV: LazyLock<SigningKey> = LazyLock::new(|| SigningKey::from_bytes(&[b'B'; 32]));
// static BOB: LazyLock<UserKey> = LazyLock::new(|| UserKey(BOB_PRIV.verifying_key().to_bytes()));

fn mock_rng() -> impl RngCore {
    rand::rngs::mock::StepRng::new(9, 1)
}

trait ResultExt {
    fn expect_api_err(self, status: StatusCode, code: &str);
}

impl<T: fmt::Debug> ResultExt for Result<T> {
    #[track_caller]
    fn expect_api_err(self, status: StatusCode, code: &str) {
        let err = self.unwrap_err().downcast::<ApiError>().unwrap();
        assert_eq!(err.status, status);
        assert_eq!(err.code, code);
    }
}

#[derive(Debug)]
struct Server {
    port: u16,
    client: reqwest::Client,
}

impl Server {
    fn url(&self, rhs: impl fmt::Display) -> String {
        format!("http://{}:{}{}", LOCALHOST, self.port, rhs)
    }

    async fn request<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        method: Method,
        url: impl fmt::Display,
        auth: Option<&str>,
        body: Option<Req>,
    ) -> Result<Option<Resp>> {
        let mut b = self.client.request(method, self.url(url));
        if let Some(auth) = auth {
            b = b.header(header::AUTHORIZATION, auth);
        }
        if let Some(body) = &body {
            b = b.json(body);
        }
        let resp = b.send().await?;
        let status = resp.status();
        let resp_str = resp.text().await?;

        if !status.is_success() {
            #[derive(Deserialize)]
            struct Resp {
                error: ApiError,
            }
            let Resp { mut error } = serde_json::from_str(&resp_str)?;
            error.status = status;
            Err(error.into())
        } else if resp_str.is_empty() {
            Ok(None)
        } else {
            Ok(Some(serde_json::from_str(&resp_str)?))
        }
    }

    async fn get<Resp: DeserializeOwned>(
        &self,
        url: impl fmt::Display,
        auth: Option<&str>,
    ) -> Result<Resp> {
        Ok(self
            .request(Method::GET, url, auth, None::<()>)
            .await?
            .unwrap())
    }
}

#[fixture]
fn server() -> Server {
    let mut conn = Connection::open_in_memory().unwrap();
    Database::maybe_init(&mut conn).unwrap();
    conn.execute(
        "INSERT INTO `user` (`userkey`, `permission`) VALUES (?, ?)",
        params![*ALICE, ServerPermission::ALL],
    )
    .unwrap();
    let db = Database::from_raw(conn).unwrap();

    // Use std's to avoid async, since we need no name resolution.
    let listener = std::net::TcpListener::bind(format!("{LOCALHOST}:0")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = TcpListener::from_std(listener).unwrap();

    // TODO: Testing config is hard to build because it does have a `Default` impl.
    let config = toml::from_str(&format!(r#"base_url="http://{LOCALHOST}:{port}""#)).unwrap();
    let st = AppState::new(db, config);
    let router = blahd::router(Arc::new(st));

    tokio::spawn(axum::serve(listener, router).into_future());
    let client = reqwest::ClientBuilder::new().no_proxy().build().unwrap();
    Server { port, client }
}

#[rstest]
#[tokio::test]
async fn smoke(server: Server) {
    let got: RoomList = server.get("/room?filter=public", None).await.unwrap();
    let exp = RoomList {
        rooms: Vec::new(),
        skip_token: None,
    };
    assert_eq!(got, exp);
}

fn sign<T: Serialize>(key: &SigningKey, rng: &mut impl RngCore, payload: T) -> WithSig<T> {
    WithSig::sign(key, get_timestamp(), rng, payload).unwrap()
}

fn auth(key: &SigningKey, rng: &mut impl RngCore) -> String {
    serde_json::to_string(&sign(key, rng, AuthPayload {})).unwrap()
}

async fn create_room(
    server: &Server,
    key: &SigningKey,
    rng: &mut impl RngCore,
    attrs: RoomAttrs,
    title: impl fmt::Display,
) -> Result<Id> {
    let req = sign(
        key,
        rng,
        CreateRoomPayload {
            attrs,
            members: RoomMemberList(vec![RoomMember {
                permission: MemberPermission::ALL,
                user: UserKey(key.verifying_key().to_bytes()),
            }]),
            title: title.to_string(),
        },
    );
    Ok(server
        .request(Method::POST, "/room/create", None, Some(&req))
        .await?
        .unwrap())
}

#[rstest]
#[case::public(true)]
#[case::private(false)]
#[tokio::test]
async fn room_create_get(server: Server, #[case] public: bool) {
    let rng = &mut mock_rng();
    let mut room_meta = RoomMetadata {
        rid: Id(0),
        title: "test room".into(),
        attrs: if public {
            RoomAttrs::PUBLIC_READABLE | RoomAttrs::PUBLIC_JOINABLE
        } else {
            RoomAttrs::empty()
        },
        last_chat: None,
        last_seen_cid: None,
        unseen_cnt: None,
    };

    // Alice has permission.
    let rid = create_room(&server, &ALICE_PRIV, rng, room_meta.attrs, &room_meta.title)
        .await
        .unwrap();
    room_meta.rid = rid;

    // Bob has no permission.
    create_room(
        &server,
        &BOB_PRIV,
        rng,
        room_meta.attrs,
        room_meta.title.clone(),
    )
    .await
    .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");

    // Alice can always access it.
    let got_meta = server
        .get::<RoomMetadata>(format!("/room/{rid}"), Some(&auth(&ALICE_PRIV, rng)))
        .await
        .unwrap();
    assert_eq!(got_meta, room_meta);

    // Bob or public can access it when it is public.
    for auth in [None, Some(auth(&BOB_PRIV, rng))] {
        let resp = server
            .get::<RoomMetadata>(format!("/room/{rid}"), auth.as_deref())
            .await;
        if public {
            assert_eq!(resp.unwrap(), room_meta);
        } else {
            resp.expect_api_err(StatusCode::NOT_FOUND, "not_found");
        }
    }

    // The room appears in public list only when it is public.
    let expect_list = |has: bool| RoomList {
        rooms: has.then(|| room_meta.clone()).into_iter().collect(),
        skip_token: None,
    };
    assert_eq!(
        server
            .get::<RoomList>("/room?filter=public", None)
            .await
            .unwrap(),
        expect_list(public),
    );

    // Joined rooms endpoint always require authentication.
    server
        .get::<RoomList>("/room?filter=joined", None)
        .await
        .expect_api_err(StatusCode::UNAUTHORIZED, "unauthorized");
    let got_joined = server
        .get::<RoomList>("/room?filter=joined", Some(&auth(&ALICE_PRIV, rng)))
        .await
        .unwrap();
    assert_eq!(got_joined, expect_list(true));

    let got_joined = server
        .get::<RoomList>("/room?filter=joined", Some(&auth(&BOB_PRIV, rng)))
        .await
        .unwrap();
    assert_eq!(got_joined, expect_list(false));
}
