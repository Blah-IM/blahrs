#![expect(
    clippy::unwrap_used,
    reason = "WAIT: https://github.com/rust-lang/rust-clippy/issues/11119"
)]
use std::fmt;
use std::future::{Future, IntoFuture};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use blah_types::identity::{IdUrl, UserActKeyDesc, UserIdentityDesc, UserProfile};
use blah_types::msg::{
    self, AddMemberPayload, AuthPayload, ChatPayload, CreateGroup, CreatePeerChat,
    CreateRoomPayload, DeleteRoomPayload, MemberPermission, RemoveMemberPayload, RichText,
    RoomAttrs, ServerPermission, SignedChatMsg, SignedChatMsgWithId, UpdateMemberPayload,
    UserRegisterChallengeResponse, UserRegisterPayload, WithMsgId,
};
use blah_types::server::{
    RoomList, RoomMember, RoomMemberList, RoomMetadata, RoomMsgs, ServerEvent, ServerMetadata,
    UserIdentityDescResponse, UserRegisterChallenge,
};
use blah_types::{Id, SignExt, Signed, UserKey};
use blahd::{AppState, Database};
use ed25519_dalek::SigningKey;
use expect_test::expect;
use futures_util::future::BoxFuture;
use futures_util::{SinkExt, Stream, StreamExt, TryFutureExt};
use parking_lot::Mutex;
use reqwest::{header, Method, StatusCode};
use rstest::{fixture, rstest};
use rusqlite::{params, Connection};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

// Register API requires a non-IP hostname.
const LOCALHOST: &str = "localhost";
const REGISTER_DIFFICULTY: u8 = 1;
const BASE_URL: &str = "http://base.example.com";

const TIME_TOLERANCE: Duration = Duration::from_millis(100);
const WS_CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);

const CONFIG: fn(u16) -> String = |_port| {
    format!(
        r#"
base_url="{BASE_URL}"

[ws]
auth_timeout_sec = 1

[feed]
max_page_len = 2

[register]
enable_public = true
request_timeout_secs = 1
unsafe_allow_id_url_http = true
unsafe_allow_id_url_custom_port = true
unsafe_allow_id_url_single_label = true

[register.challenge.pow]
difficulty = {REGISTER_DIFFICULTY}
nonce_rotate_secs = 60
        "#
    )
};

struct User {
    name: u8,
    pubkeys: UserKey,
    id_priv: SigningKey,
    act_priv: SigningKey,
}

impl User {
    fn new(b: u8) -> Self {
        assert!(b.is_ascii_uppercase());
        let id_priv = SigningKey::from_bytes(&[b; 32]);
        let act_priv = SigningKey::from_bytes(&[b.to_ascii_lowercase(); 32]);
        Self {
            name: b,
            pubkeys: UserKey {
                id_key: id_priv.verifying_key().into(),
                act_key: act_priv.verifying_key().into(),
            },
            id_priv,
            act_priv,
        }
    }
}

static ALICE: LazyLock<User> = LazyLock::new(|| User::new(b'A'));
static BOB: LazyLock<User> = LazyLock::new(|| User::new(b'B'));
static CAROL: LazyLock<User> = LazyLock::new(|| User::new(b'C'));

#[derive(Debug, Serialize, Deserialize)]
enum NoContent {}

trait ResultExt {
    fn expect_api_err(self, status: StatusCode, code: &str);
    fn expect_invalid_request(self, message: &str);
}

impl<T: fmt::Debug> ResultExt for Result<T> {
    #[track_caller]
    fn expect_api_err(self, status: StatusCode, code: &str) {
        let err = self.unwrap_err().downcast::<ApiError>().unwrap();
        assert_eq!(
            (err.status, &*err.code),
            (status, code),
            "unexpecteed API error: {err}",
        );
    }

    #[track_caller]
    fn expect_invalid_request(self, message: &str) {
        let err = self.unwrap_err().downcast::<ApiError>().unwrap();
        assert_eq!(
            (err.status, &*err.code, &*err.message),
            (StatusCode::BAD_REQUEST, "invalid_request", message),
            "unexpected API error: {err}"
        );
    }
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
    register_challenge: Option<UserRegisterChallenge>,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "status={} code={}: {}",
            self.status, self.code, self.message,
        )
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug)]
struct Server {
    port: u16,
    client: reqwest::Client,
}

impl Server {
    fn url(&self, rhs: impl fmt::Display) -> String {
        format!("http://{}/_blah{}", self.domain(), rhs)
    }

    fn domain(&self) -> String {
        format!("{}:{}", LOCALHOST, self.port)
    }

    async fn connect_ws(
        &self,
        auth_user: Option<&User>,
    ) -> Result<impl Stream<Item = Result<ServerEvent>> + Unpin> {
        let url = format!("ws://{}/_blah/ws", self.domain());
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        if let Some(user) = auth_user {
            ws.send(tokio_tungstenite::tungstenite::Message::Text(auth(user)))
                .await
                .unwrap();
        }
        Ok(ws
            .map(|ret| {
                let wsmsg = ret?;
                if wsmsg.is_close() {
                    return Ok(None);
                }
                let event = serde_json::from_slice::<ServerEvent>(&wsmsg.into_data())?;
                Ok(Some(event))
            })
            .filter_map(|ret| std::future::ready(ret.transpose())))
    }

    fn request<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        method: Method,
        url: &str,
        auth: Option<&str>,
        body: Option<Req>,
    ) -> impl Future<Output = Result<Option<Resp>>> + use<'_, Req, Resp> {
        let mut b = self.client.request(method, self.url(url));
        if let Some(auth) = auth {
            b = b.header(header::AUTHORIZATION, auth);
        }
        if let Some(body) = &body {
            b = b.json(body);
        }

        async move {
            let resp = b.send().await?;
            let status = resp.status();
            let resp_str = resp.text().await?;

            if !status.is_success() {
                #[derive(Deserialize)]
                struct Resp {
                    error: RespErr,
                    #[serde(default)]
                    register_challenge: Option<UserRegisterChallenge>,
                }
                #[derive(Deserialize)]
                struct RespErr {
                    code: String,
                    message: String,
                }

                let resp = serde_json::from_str::<Resp>(&resp_str)
                    .with_context(|| format!("failed to parse response {resp_str:?}"))?;
                Err(ApiError {
                    status,
                    code: resp.error.code,
                    message: resp.error.message,
                    register_challenge: resp.register_challenge,
                }
                .into())
            } else if resp_str.is_empty() {
                Ok(None)
            } else {
                Ok(Some(serde_json::from_str(&resp_str)?))
            }
        }
    }

    fn get<Resp: DeserializeOwned>(
        &self,
        url: &str,
        auth: Option<&str>,
    ) -> impl Future<Output = Result<Resp>> + use<'_, Resp> {
        self.request::<NoContent, Resp>(Method::GET, url, auth, None)
            .map_ok(|resp| resp.unwrap())
    }

    fn sign<T: Serialize>(&self, user: &User, msg: T) -> Signed<T> {
        msg.sign_msg(&user.pubkeys.id_key, &user.act_priv).unwrap()
    }

    async fn get_metadata(&self) -> Result<ServerMetadata> {
        self.get::<ServerMetadata>("/server", None).await
    }

    fn create_room(
        &self,
        user: &User,
        attrs: RoomAttrs,
        title: &str,
    ) -> impl Future<Output = Result<Id>> + use<'_> {
        let req = self.sign(
            user,
            CreateRoomPayload::Group(CreateGroup {
                attrs,
                title: title.to_string(),
            }),
        );
        async move {
            Ok(self
                .request(Method::POST, "/room", None, Some(&req))
                .await?
                .unwrap())
        }
    }

    fn create_peer_chat(
        &self,
        src: &User,
        tgt: &User,
    ) -> impl Future<Output = Result<Id>> + use<'_> {
        let req = self.sign(
            src,
            CreateRoomPayload::PeerChat(CreatePeerChat {
                peer: tgt.pubkeys.id_key.clone(),
            }),
        );
        async move {
            Ok(self
                .request(Method::POST, "/room", None, Some(&req))
                .await?
                .unwrap())
        }
    }

    fn delete_room(&self, rid: Id, user: &User) -> impl Future<Output = Result<()>> + use<'_> {
        let req = self.sign(user, DeleteRoomPayload { room: rid });
        self.request::<_, NoContent>(Method::DELETE, &format!("/room/{rid}"), None, Some(req))
            .map_ok(|None| {})
    }

    fn join_room(
        &self,
        rid: Id,
        user: &User,
        permission: MemberPermission,
    ) -> impl Future<Output = Result<()>> + use<'_> {
        let req = self.sign(
            user,
            AddMemberPayload {
                room: rid,
                member: msg::RoomMember {
                    permission,
                    user: user.pubkeys.id_key.clone(),
                },
            },
        );
        self.request::<_, NoContent>(
            Method::POST,
            &format!("/room/{rid}/member"),
            None,
            Some(req),
        )
        .map_ok(|None| {})
    }

    fn leave_room(&self, rid: Id, user: &User) -> impl Future<Output = Result<()>> + use<'_> {
        self.remove_member(rid, user, user)
    }

    fn remove_member(
        &self,
        rid: Id,
        act_user: &User,
        tgt_user: &User,
    ) -> impl Future<Output = Result<()>> + use<'_> {
        let tgt_user_id = tgt_user.pubkeys.id_key.clone();
        let req = self.sign(
            act_user,
            RemoveMemberPayload {
                room: rid,
                user: tgt_user_id.clone(),
            },
        );
        self.request::<_, NoContent>(
            Method::DELETE,
            &format!("/room/{rid}/member/{tgt_user_id}"),
            None,
            Some(req),
        )
        .map_ok(|None| {})
    }

    fn update_member_perm(
        &self,
        rid: Id,
        act_user: &User,
        tgt_user: &User,
        permission: MemberPermission,
    ) -> impl Future<Output = Result<()>> + use<'_> {
        let tgt_user_id = tgt_user.pubkeys.id_key.clone();
        let req = self.sign(
            act_user,
            UpdateMemberPayload {
                room: rid,
                member: msg::RoomMember {
                    permission,
                    user: tgt_user_id.clone(),
                },
            },
        );
        self.request::<_, NoContent>(
            Method::PATCH,
            &format!("/room/{rid}/member/{tgt_user_id}"),
            None,
            Some(req),
        )
        .map_ok(|None| {})
    }

    fn post_chat(
        &self,
        rid: Id,
        user: &User,
        text: &str,
    ) -> impl Future<Output = Result<SignedChatMsgWithId>> + use<'_> {
        let msg = self.sign(
            user,
            ChatPayload {
                room: rid,
                rich_text: text.into(),
            },
        );
        async move {
            let cid = self
                .request::<_, Id>(
                    Method::POST,
                    &format!("/room/{rid}/msg"),
                    None,
                    Some(msg.clone()),
                )
                .await?
                .unwrap();
            Ok(WithMsgId { cid, msg })
        }
    }

    async fn get_me(&self, auth_user: Option<&User>) -> Result<(), Option<(u32, u8)>> {
        let auth = auth_user.map(auth);
        match self
            .request::<(), NoContent>(Method::GET, "/user/me", auth.as_deref(), None)
            .await
        {
            Ok(None) => Ok(()),
            Err(err) => {
                let err = err.downcast::<ApiError>().unwrap();
                assert_eq!(err.status, StatusCode::NOT_FOUND);
                Err(match err.register_challenge {
                    Some(UserRegisterChallenge::Pow { nonce, difficulty }) => {
                        Some((nonce, difficulty))
                    }
                    Some(UserRegisterChallenge::Unknown) => unreachable!(),
                    None => None,
                })
            }
        }
    }
}

#[fixture]
fn server() -> Server {
    let _ = tracing_subscriber::fmt::try_init();

    let mut conn = Connection::open_in_memory().unwrap();
    Database::maybe_init(&mut conn).unwrap();
    {
        let mut add_user = conn
            .prepare(
                r"
                INSERT INTO `user` (`id_key`, `permission`, `last_fetch_time`, `id_desc`)
                VALUES (?, ?, 0, ?)
                ",
            )
            .unwrap();
        let mut add_act_key = conn
            .prepare(
                r"
                INSERT INTO `user_act_key` (`uid`, `act_key`, `expire_time`)
                VALUES (?, ?, ?)
                ",
            )
            .unwrap();
        for (user, perm) in [
            (&*ALICE, ServerPermission::ALL),
            (&BOB, ServerPermission::empty()),
        ] {
            // Fake value.
            let id_desc = json!({"user": user.name as char }).to_string();
            add_user
                .execute(params![user.pubkeys.id_key, perm, id_desc])
                .unwrap();
            let uid = conn.last_insert_rowid();
            add_act_key
                .execute(params![uid, user.pubkeys.act_key, i64::MAX])
                .unwrap();
        }
    }
    let db = Database::from_raw(conn).unwrap();
    server_with(db, &CONFIG)
}

// TODO: Testing config is hard to build because it lacks a `Default` impl.
#[track_caller]
fn server_with(db: Database, config: &dyn Fn(u16) -> String) -> Server {
    // Use std's to avoid async, since we need no name resolution.
    let listener = std::net::TcpListener::bind(format!("{LOCALHOST}:0")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = TcpListener::from_std(listener).unwrap();

    let config = toml::from_str(&config(port)).unwrap();
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

#[rstest]
#[tokio::test]
#[expect(clippy::print_stdout, reason = "allowed in tests for debugging")]
async fn server_metadata(server: Server) {
    let meta = server.get_metadata().await.unwrap();
    println!("{meta:#?}");
    assert!(meta.server.starts_with("blahd/"));
}

fn auth(user: &User) -> String {
    let msg = AuthPayload {}
        .sign_msg(&user.pubkeys.id_key, &user.act_priv)
        .unwrap();
    serde_json::to_string(&msg).unwrap()
}

#[rstest]
#[case::public(true)]
#[case::private(false)]
#[tokio::test]
async fn room_create_get(server: Server, #[case] public: bool) {
    let title = "test room";
    let mut room_meta = RoomMetadata {
        rid: Id(0),
        title: Some(title.into()),
        attrs: if public {
            RoomAttrs::PUBLIC_READABLE | RoomAttrs::PUBLIC_JOINABLE
        } else {
            RoomAttrs::empty()
        },
        last_msg: None,
        last_seen_cid: None,
        unseen_cnt: None,
        member_permission: None,
        peer_user: None,
    };

    // Alice has permission.
    let rid = server
        .create_room(&ALICE, room_meta.attrs, title)
        .await
        .unwrap();
    room_meta.rid = rid;

    // Bob has no permission.
    server
        .create_room(&BOB, room_meta.attrs, title)
        .await
        .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");

    // Alice can always access it.
    let got_meta = server
        .get::<RoomMetadata>(&format!("/room/{rid}"), Some(&auth(&ALICE)))
        .await
        .unwrap();
    assert_eq!(got_meta, room_meta);

    // Bob or public can access it when it is public.
    for auth in [None, Some(auth(&BOB))] {
        let resp = server
            .get::<RoomMetadata>(&format!("/room/{rid}"), auth.as_deref())
            .await;
        if public {
            assert_eq!(resp.unwrap(), room_meta);
        } else {
            resp.expect_api_err(StatusCode::NOT_FOUND, "room_not_found");
        }
    }

    // The room appears in public list only when it is public.
    let expect_list = |has: bool, perm: Option<MemberPermission>| RoomList {
        rooms: if has {
            vec![RoomMetadata {
                member_permission: perm,
                ..room_meta.clone()
            }]
        } else {
            Vec::new()
        },
        skip_token: None,
    };
    assert_eq!(
        server
            .get::<RoomList>("/room?filter=public", None)
            .await
            .unwrap(),
        expect_list(public, None),
    );

    // Joined rooms endpoint always require authentication.
    server
        .get::<RoomList>("/room?filter=joined", None)
        .await
        .expect_api_err(StatusCode::UNAUTHORIZED, "unauthorized");
    let got_joined = server
        .get::<RoomList>("/room?filter=joined", Some(&auth(&ALICE)))
        .await
        .unwrap();
    assert_eq!(got_joined, expect_list(true, Some(MemberPermission::ALL)));

    let got_joined = server
        .get::<RoomList>("/room?filter=joined", Some(&auth(&BOB)))
        .await
        .unwrap();
    assert_eq!(got_joined, expect_list(false, None));
}

#[rstest]
#[tokio::test]
async fn room_join_leave(server: Server) {
    let rid_pub = server
        .create_room(&ALICE, RoomAttrs::PUBLIC_JOINABLE, "public room")
        .await
        .unwrap();
    let rid_priv = server
        .create_room(&ALICE, RoomAttrs::empty(), "private room")
        .await
        .unwrap();

    let join = |rid, user| server.join_room(rid, user, MemberPermission::MAX_SELF_ADD);

    // Ok.
    join(rid_pub, &BOB).await.unwrap();
    // Already joined.
    join(rid_pub, &BOB)
        .await
        .expect_api_err(StatusCode::CONFLICT, "exists");
    // Not permitted.
    join(rid_priv, &BOB)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");
    // Not exists.
    join(Id::INVALID, &BOB)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");
    // Overly high permission.
    server
        .join_room(rid_priv, &BOB, MemberPermission::ALL)
        .await
        .expect_invalid_request("invalid member permission");

    // Bob is joined now.
    assert_eq!(
        server
            .get::<RoomList>("/room?filter=joined", Some(&auth(&BOB)))
            .await
            .unwrap()
            .rooms
            .len(),
        1,
    );

    let leave = |rid, user| server.leave_room(rid, user);

    // Ok.
    leave(rid_pub, &BOB).await.unwrap();
    // Already left.
    leave(rid_pub, &BOB)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");
    // Unpermitted and not inside.
    leave(rid_priv, &BOB)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");
    // Invalid room.
    leave(Id::INVALID, &BOB)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");
}

#[rstest]
#[tokio::test]
async fn room_chat_post_read(server: Server) {
    let rid_pub = server
        .create_room(
            &ALICE,
            RoomAttrs::PUBLIC_READABLE | RoomAttrs::PUBLIC_JOINABLE,
            "public room",
        )
        .await
        .unwrap();
    let rid_priv = server
        .create_room(&ALICE, RoomAttrs::empty(), "private room")
        .await
        .unwrap();

    let chat = |rid: Id, user: &User, msg: &str| {
        server.sign(
            user,
            ChatPayload {
                room: rid,
                rich_text: RichText::from(msg),
            },
        )
    };
    let post = |rid: Id, chat: SignedChatMsg| {
        server
            .request::<_, Id>(Method::POST, &format!("/room/{rid}/msg"), None, Some(chat))
            .map_ok(|opt| opt.unwrap())
    };

    // Ok.
    let chat1 = chat(rid_pub, &ALICE, "one");
    let chat2 = chat(rid_pub, &ALICE, "two");
    let cid1 = post(rid_pub, chat1.clone()).await.unwrap();
    let cid2 = post(rid_pub, chat2.clone()).await.unwrap();

    // Duplicated chat.
    post(rid_pub, chat2.clone())
        .await
        .expect_invalid_request("used nonce");

    // Wrong room.
    post(rid_pub, chat(rid_priv, &ALICE, "wrong room"))
        .await
        .expect_invalid_request("room id mismatch with URI");

    // Not a member.
    post(rid_pub, chat(rid_pub, &BOB, "not a member"))
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");

    // Is a member but without permission.
    server
        .join_room(rid_pub, &BOB, MemberPermission::empty())
        .await
        .unwrap();
    post(rid_pub, chat(rid_pub, &BOB, "no permission"))
        .await
        .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");

    // Room not exists.
    post(Id::INVALID, chat(Id::INVALID, &ALICE, "not permitted"))
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");

    //// Msgs listing ////

    let chat1 = WithMsgId::new(cid1, chat1);
    let chat2 = WithMsgId::new(cid2, chat2);

    // List with default page size.
    let msgs = server
        .get::<RoomMsgs>(&format!("/room/{rid_pub}/msg"), None)
        .await
        .unwrap();
    assert_eq!(
        msgs,
        RoomMsgs {
            msgs: vec![chat2.clone(), chat1.clone()],
            skip_token: None,
        },
    );

    // List with small page size.
    let msgs = server
        .get::<RoomMsgs>(&format!("/room/{rid_pub}/msg?top=1"), None)
        .await
        .unwrap();
    assert_eq!(
        msgs,
        RoomMsgs {
            msgs: vec![chat2.clone()],
            skip_token: Some(cid2),
        },
    );

    // Second page.
    let msgs = server
        .get::<RoomMsgs>(&format!("/room/{rid_pub}/msg?skipToken={cid2}&top=1"), None)
        .await
        .unwrap();
    assert_eq!(
        msgs,
        RoomMsgs {
            msgs: vec![chat1.clone()],
            skip_token: Some(cid1),
        },
    );

    // No more.
    let msgs = server
        .get::<RoomMsgs>(&format!("/room/{rid_pub}/msg?skipToken={cid1}&top=1"), None)
        .await
        .unwrap();
    assert_eq!(msgs, RoomMsgs::default());

    //// Private room ////

    // Access without token.
    server
        .get::<RoomMsgs>(&format!("/room/{rid_priv}/msg"), None)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");

    // Not a member.
    server
        .get::<RoomMsgs>(&format!("/room/{rid_priv}/msg"), Some(&auth(&BOB)))
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");

    // Ok.
    let msgs = server
        .get::<RoomMsgs>(&format!("/room/{rid_priv}/msg"), Some(&auth(&ALICE)))
        .await
        .unwrap();
    assert_eq!(msgs, RoomMsgs::default());
}

#[cfg(feature = "unsafe_use_mock_instant_for_testing")]
#[rstest]
#[case::json("json")]
#[case::atom("atom")]
#[tokio::test]
async fn room_feed(server: Server, #[case] typ: &'static str) {
    use mock_instant::thread_local::MockClock;

    MockClock::set_time(Duration::ZERO);
    MockClock::set_system_time(Duration::ZERO);

    // Only public readable rooms provides feed. Not even for public joinable ones.
    let rid_need_join = server
        .create_room(&ALICE, RoomAttrs::PUBLIC_JOINABLE, "not so public")
        .await
        .unwrap();
    server
        .get::<NoContent>(&format!("/room/{rid_need_join}/feed.{typ}"), None)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");

    let rid = server
        .create_room(
            &ALICE,
            RoomAttrs::PUBLIC_READABLE | RoomAttrs::PUBLIC_JOINABLE,
            "public",
        )
        .await
        .unwrap();
    server
        .join_room(rid, &BOB, MemberPermission::POST_CHAT)
        .await
        .unwrap();
    let feed_url = server.url(format!("/room/{rid}/feed.{typ}"));
    let get_feed = |etag: Option<&str>| {
        let mut req = server.client.get(&feed_url);
        if let Some(etag) = etag {
            req = req.header(header::IF_NONE_MATCH, etag);
        }
        async move {
            let resp = req.send().await.unwrap().error_for_status().unwrap();
            if resp.status() == StatusCode::NOT_MODIFIED {
                None
            } else {
                let etag = resp.headers()[header::ETAG].to_str().unwrap().to_owned();
                Some((etag, resp.text().await.unwrap()))
            }
        }
    };

    // Empty yet.
    let etag_zero = "\"0\"";
    assert_eq!(get_feed(None).await.unwrap().0, etag_zero);
    // ETag should track from empty -> empty.
    assert_eq!(get_feed(Some(etag_zero)).await, None);

    // Post some chats.
    let cid1 = server.post_chat(rid, &ALICE, "a").await.unwrap().cid;
    // Got some response.
    let etag_one = format!("\"{cid1}\"");
    {
        let resp1 = get_feed(None).await.unwrap();
        // ETag should track from empty -> non-empty.
        let resp2 = get_feed(Some(etag_zero)).await.unwrap();
        // Idempotent.
        assert_eq!(resp1, resp2);
        assert_eq!(resp1.0, etag_one);
    }

    // Post more chats.
    server.post_chat(rid, &BOB, "b1").await.unwrap();
    let cid3 = server.post_chat(rid, &BOB, "b2").await.unwrap().cid;

    let etag_last = format!("\"{cid3}\"");
    let resp = {
        let resp1 = get_feed(None).await.unwrap();
        // ETag should track from non-empty -> non-empty.
        let resp2 = get_feed(Some(&etag_one)).await.unwrap();
        // Idempotent.
        assert_eq!(resp1, resp2);
        assert_eq!(resp1.0, etag_last);
        assert_eq!(get_feed(Some(&etag_last)).await, None);
        resp1.1
    };

    if typ == "json" {
        let feed = serde_json::from_str::<serde_json::Value>(&resp).unwrap();
        let got_pretty = serde_json::to_string_pretty(&feed).unwrap();
        let expect = expect![[r#"
            {
              "feed_url": "http://base.example.com/_blah/room/2/feed.json",
              "items": [
                {
                  "authors": [
                    {
                      "name": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
                    }
                  ],
                  "content_html": "b2",
                  "date_published": "1970-01-01T00:00:00Z",
                  "id": "tag:base.example.com,1970:blah/msg/5"
                },
                {
                  "authors": [
                    {
                      "name": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
                    }
                  ],
                  "content_html": "b1",
                  "date_published": "1970-01-01T00:00:00Z",
                  "id": "tag:base.example.com,1970:blah/msg/4"
                }
              ],
              "next_url": "http://base.example.com/_blah/room/2/feed.json?skipToken=4&top=2",
              "title": "public",
              "version": "https://jsonfeed.org/version/1.1"
            }"#]];
        expect.assert_eq(&got_pretty);

        let next_url = feed["next_url"]
            .as_str()
            .unwrap()
            .strip_prefix(BASE_URL)
            .unwrap()
            .strip_prefix("/_blah")
            .unwrap();
        let feed2 = server
            .get::<serde_json::Value>(next_url, None)
            .await
            .unwrap();
        let got2_pretty = serde_json::to_string_pretty(&feed2).unwrap();

        expect![[r#"
            {
              "feed_url": "http://base.example.com/_blah/room/2/feed.json",
              "items": [
                {
                  "authors": [
                    {
                      "name": "db995fe25169d141cab9bbba92baa01f9f2e1ece7df4cb2ac05190f37fcc1f9d"
                    }
                  ],
                  "content_html": "a",
                  "date_published": "1970-01-01T00:00:00Z",
                  "id": "tag:base.example.com,1970:blah/msg/3"
                }
              ],
              "title": "public",
              "version": "https://jsonfeed.org/version/1.1"
            }"#]]
        .assert_eq(&got2_pretty);
    } else {
        assert!(resp.starts_with(r#"<?xml version="1.0" encoding="utf-8"?>"#));

        expect![[r#"
            <?xml version="1.0" encoding="utf-8"?>
            <feed xmlns="http://www.w3.org/2005/Atom">
              <id>tag:base.example.com,1970:blah/room/2</id>
              <title>public</title>
              <updated>1970-01-01T00:00:00Z</updated>
              <link rel="self" type="application/atom+xml" href="http://base.example.com/_blah/room/2/feed.atom"/>
              <link rel="next" type="application/atom+xml" href="http://base.example.com/_blah/room/2/feed.atom?skipToken=4&amp;top=2"/>

              <entry>
                <id>tag:base.example.com,1970:blah/msg/5</id>
                <title type="text">b2</title>
                <published>1970-01-01T00:00:00Z</published>
                <updated>1970-01-01T00:00:00Z</updated>
                <author><name>2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12</name></author>
                <content type="html">b2</content>
              </entry>

              <entry>
                <id>tag:base.example.com,1970:blah/msg/4</id>
                <title type="text">b1</title>
                <published>1970-01-01T00:00:00Z</published>
                <updated>1970-01-01T00:00:00Z</updated>
                <author><name>2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12</name></author>
                <content type="html">b1</content>
              </entry>

            </feed>
        "#]].assert_eq(&resp);
    }
}

#[rstest]
#[tokio::test]
async fn last_seen(server: Server) {
    let title = "public room";
    let attrs = RoomAttrs::PUBLIC_READABLE | RoomAttrs::PUBLIC_JOINABLE;
    let member_perm = MemberPermission::ALL;
    let rid = server.create_room(&ALICE, attrs, title).await.unwrap();
    server
        .join_room(rid, &BOB, MemberPermission::MAX_SELF_ADD)
        .await
        .unwrap();

    let alice_chat1 = server.post_chat(rid, &ALICE, "alice1").await.unwrap();
    let alice_chat2 = server.post_chat(rid, &ALICE, "alice2").await.unwrap();

    // 2 new msgs.
    let rooms = server
        .get::<RoomList>("/room?filter=unseen", Some(&auth(&ALICE)))
        .await
        .unwrap();
    assert_eq!(
        rooms,
        RoomList {
            rooms: vec![RoomMetadata {
                rid,
                title: Some(title.into()),
                attrs,
                last_msg: Some(alice_chat2.clone()),
                last_seen_cid: None,
                unseen_cnt: Some(2),
                member_permission: Some(member_perm),
                peer_user: None,
            }],
            skip_token: None,
        }
    );

    let seen = |user: &User, cid: Id| {
        server.request::<NoContent, NoContent>(
            Method::POST,
            &format!("/room/{rid}/msg/{cid}/seen"),
            Some(&auth(user)),
            None,
        )
    };

    // Mark the first one seen.
    seen(&ALICE, alice_chat1.cid).await.unwrap();

    // 1 new msg.
    let rooms = server
        .get::<RoomList>("/room?filter=unseen", Some(&auth(&ALICE)))
        .await
        .unwrap();
    assert_eq!(
        rooms,
        RoomList {
            rooms: vec![RoomMetadata {
                rid,
                title: Some(title.into()),
                attrs,
                last_msg: Some(alice_chat2.clone()),
                last_seen_cid: Some(alice_chat1.cid),
                unseen_cnt: Some(1),
                member_permission: Some(member_perm),
                peer_user: None,
            }],
            skip_token: None,
        }
    );

    // Mark the second one seen. Now there is no new messages.
    seen(&ALICE, alice_chat2.cid).await.unwrap();
    let rooms = server
        .get::<RoomList>("/room?filter=unseen", Some(&auth(&ALICE)))
        .await
        .unwrap();
    assert_eq!(rooms, RoomList::default());

    // Marking a seen message seen is a no-op.
    seen(&ALICE, alice_chat2.cid).await.unwrap();
    let rooms = server
        .get::<RoomList>("/room?filter=unseen", Some(&auth(&ALICE)))
        .await
        .unwrap();
    assert_eq!(rooms, RoomList::default());

    // Cannot see a future msg.
    seen(&ALICE, Id::MAX)
        .await
        .expect_api_err(StatusCode::BAD_REQUEST, "invalid_request");
}

#[rstest]
#[tokio::test]
async fn peer_chat(server: Server) {
    // Bob disallows peer chat.
    server
        .create_peer_chat(&ALICE, &BOB)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "peer_user_not_found");

    // Alice accepts bob.
    let rid = server.create_peer_chat(&BOB, &ALICE).await.unwrap();

    // Room already exists.
    server
        .create_peer_chat(&BOB, &ALICE)
        .await
        .expect_api_err(StatusCode::CONFLICT, "exists");

    // Peer chat room is not public.
    let rooms = server
        .get::<RoomList>("/room?filter=public", None)
        .await
        .unwrap();
    assert_eq!(rooms, RoomList::default());
    server
        .get::<RoomMetadata>(&format!("/room/{rid}"), None)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");

    // Both alice and bob are in the room.
    for (key, peer) in [(&*ALICE, &*BOB), (&*BOB, &*ALICE)] {
        let mut expect_meta = RoomMetadata {
            rid,
            title: None,
            attrs: RoomAttrs::PEER_CHAT,
            last_msg: None,
            last_seen_cid: None,
            unseen_cnt: None,
            member_permission: None,
            peer_user: None,
        };

        let meta = server
            .get::<RoomMetadata>(&format!("/room/{rid}"), Some(&auth(key)))
            .await
            .unwrap();
        assert_eq!(meta, expect_meta);

        expect_meta.member_permission = Some(MemberPermission::MAX_PEER_CHAT);
        expect_meta.peer_user = Some(peer.pubkeys.id_key.clone());
        let rooms = server
            .get::<RoomList>("/room?filter=joined", Some(&auth(key)))
            .await
            .unwrap();
        assert_eq!(
            rooms,
            RoomList {
                rooms: vec![expect_meta],
                skip_token: None
            }
        );
    }
}

#[rstest]
#[case::group(false, true)]
#[case::peer_src(true, false)]
#[case::peer_tgt(true, true)]
#[tokio::test]
async fn delete_room(server: Server, #[case] peer_chat: bool, #[case] alice_delete: bool) {
    let rid;
    if peer_chat {
        rid = server.create_peer_chat(&BOB, &ALICE).await.unwrap()
    } else {
        rid = server
            .create_room(&ALICE, RoomAttrs::PUBLIC_JOINABLE, "public room")
            .await
            .unwrap();
        server
            .join_room(rid, &BOB, MemberPermission::MAX_SELF_ADD)
            .await
            .unwrap();
    }

    // Invalid rid.
    server
        .delete_room(Id::INVALID, &ALICE)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");
    // Not in the room.
    server
        .delete_room(rid, &CAROL)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");
    if !peer_chat {
        // No permission.
        server
            .delete_room(rid, &BOB)
            .await
            .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");
    }

    // Not deleted yet.
    server
        .get::<RoomMetadata>(&format!("/room/{rid}"), Some(&auth(&ALICE)))
        .await
        .unwrap();

    // OK, deleted.
    server
        .delete_room(rid, if alice_delete { &ALICE } else { &BOB })
        .await
        .unwrap();

    // Should be deleted now.
    server
        .get::<RoomMetadata>(&format!("/room/{rid}"), Some(&auth(&ALICE)))
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");

    // Peer found it deleted and cannot delete it again.
    server
        .delete_room(rid, if !alice_delete { &ALICE } else { &BOB })
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");
}

#[rstest]
#[tokio::test]
async fn register_flow(server: Server) {
    let rid = server
        .create_room(
            &ALICE,
            RoomAttrs::PUBLIC_READABLE | RoomAttrs::PUBLIC_JOINABLE,
            "public room",
        )
        .await
        .unwrap();

    // Alice is registered.
    server.get_me(Some(&ALICE)).await.unwrap();

    // Carol is not registered.
    let (challenge_nonce, diff) = server.get_me(Some(&CAROL)).await.unwrap_err().unwrap();
    assert_eq!(diff, REGISTER_DIFFICULTY);

    // Without token.
    let ret2 = server.get_me(None).await.unwrap_err().unwrap();
    assert_eq!(ret2, (challenge_nonce, diff));

    let mut req = UserRegisterPayload {
        id_key: CAROL.pubkeys.id_key.clone(),
        // Invalid values.
        server_url: "http://localhost".parse().unwrap(),
        id_url: "http://com.".parse().unwrap(),
        challenge: Some(UserRegisterChallengeResponse::Pow {
            nonce: challenge_nonce - 1,
        }),
    };
    let register = |req: Signed<UserRegisterPayload>| {
        server
            .request::<_, ()>(Method::POST, "/user/me", None, Some(req))
            .map_ok(|_| {})
    };
    let sign_with_difficulty = |req: &UserRegisterPayload, pass: bool| loop {
        let signed = server.sign(&CAROL, req.clone());
        let mut h = Sha256::new();
        h.update(signed.canonical_signee());
        let h = h.finalize();
        if (h[0] >> (8 - REGISTER_DIFFICULTY) == 0) == pass {
            return signed;
        }
    };
    let register_fast = |req: &UserRegisterPayload| register(server.sign(&CAROL, req.clone()));

    register_fast(&req)
        .await
        .expect_invalid_request("server url mismatch");
    req.server_url = BASE_URL.parse().unwrap();

    // Trailing dot in id_url.
    register_fast(&req)
        .await
        .expect_api_err(StatusCode::FORBIDDEN, "disabled");

    // Test identity server.
    type DynHandler = Box<dyn FnMut() -> BoxFuture<'static, (StatusCode, String)> + Send>;
    type State = Arc<Mutex<DynHandler>>;
    let id_server_handler = {
        let handler = Box::new(|| {
            Box::pin(async move { (StatusCode::NOT_FOUND, "".into()) }) as BoxFuture<_>
        }) as DynHandler;
        let st = Arc::new(Mutex::new(handler)) as State;

        let listener = TcpListener::bind(format!("{LOCALHOST}:0")).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        req.id_url = format!("http://{LOCALHOST}:{port}")
            .parse::<IdUrl>()
            .unwrap();

        let router = axum::Router::new()
            .route(
                UserIdentityDesc::WELL_KNOWN_PATH,
                axum::routing::get(move |state: axum::extract::State<State>| state.lock()()),
            )
            .with_state(st.clone());
        tokio::spawn(axum::serve(listener, router).into_future());
        st
    };
    macro_rules! set_handler {
        ($([$before:stmt])? $h:block) => {
            *id_server_handler.lock() = Box::new(move || {
                $($before)?
                Box::pin(async move $h) as BoxFuture<_>
            }) as DynHandler;
        };
    }

    register_fast(&req)
        .await
        .expect_invalid_request("invalid challenge nonce");
    req.challenge = Some(UserRegisterChallengeResponse::Pow {
        nonce: challenge_nonce,
    });

    register(sign_with_difficulty(&req, false))
        .await
        .expect_invalid_request("hash challenge failed");

    //// Starting here, early validation passed. ////

    // id_url 404
    register(sign_with_difficulty(&req, true))
        .await
        .expect_api_err(StatusCode::UNPROCESSABLE_ENTITY, "fetch_id_description");

    // Timeout
    set_handler! {{
        tokio::time::sleep(Duration::from_secs(2)).await;
        (StatusCode::OK, "".into())
    }}
    let inst = Instant::now();
    register(sign_with_difficulty(&req, true))
        .await
        .expect_api_err(StatusCode::UNPROCESSABLE_ENTITY, "fetch_id_description");
    let elapsed = inst.elapsed();
    assert!(
        elapsed.abs_diff(Duration::from_secs(1)) < TIME_TOLERANCE,
        "unexpected delay: {elapsed:?}",
    );

    // Body too long.
    set_handler! {{
        (StatusCode::OK, " ".repeat(64 << 10)) // 64KiB
    }}
    register(sign_with_difficulty(&req, true))
        .await
        .expect_api_err(StatusCode::UNPROCESSABLE_ENTITY, "fetch_id_description");

    let set_id_desc = |desc: &UserIdentityDesc| {
        let desc = serde_json::to_string(&desc).unwrap();
        set_handler! { [let desc = desc.clone()] {
            (StatusCode::OK, desc.clone())
        }}
    };
    let sign_profile = |url: IdUrl| {
        server.sign(
            &CAROL,
            UserProfile {
                preferred_chat_server_urls: Vec::new(),
                id_urls: vec![url],
            },
        )
    };
    let mut id_desc = {
        // Sign using id_key.
        let act_key = UserActKeyDesc {
            act_key: CAROL.pubkeys.act_key.clone(),
            expire_time: i64::MAX as _,
            comment: "comment".into(),
        }
        .sign_msg(&CAROL.pubkeys.id_key, &CAROL.id_priv)
        .unwrap();
        // Incorrect URL, without port.
        let profile = sign_profile("https://localhost".parse().unwrap());
        UserIdentityDesc {
            id_key: CAROL.pubkeys.id_key.clone(),
            act_keys: vec![act_key],
            profile,
        }
    };

    // id_url mismatch
    set_id_desc(&id_desc);
    register(sign_with_difficulty(&req, true))
        .await
        .expect_api_err(StatusCode::UNPROCESSABLE_ENTITY, "invalid_id_description");

    // Still not registered.
    server.get_me(Some(&CAROL)).await.unwrap_err();
    server
        .join_room(rid, &CAROL, MemberPermission::MAX_SELF_ADD)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "user_not_found");

    // Finally pass.
    id_desc.profile = sign_profile(req.id_url.clone());
    set_id_desc(&id_desc);
    register(sign_with_difficulty(&req, true)).await.unwrap();

    // Registered now.
    server.get_me(Some(&CAROL)).await.unwrap();
    server
        .join_room(rid, &CAROL, MemberPermission::MAX_SELF_ADD)
        .await
        .unwrap();
}

#[rstest]
#[case::disabled(false, true, true, true)]
#[case::no_http(true, false, true, true)]
#[case::no_port(true, true, false, true)]
#[case::no_single_label(true, true, true, false)]
#[tokio::test]
async fn register_config(
    #[case] enabled: bool,
    #[case] allow_http: bool,
    #[case] allow_port: bool,
    #[case] allow_single_label: bool,
) {
    let config = |port| {
        format!(
            r#"
base_url="http://{LOCALHOST}:{port}"
[register]
enable_public = {enabled}
unsafe_allow_id_url_http = {allow_http}
unsafe_allow_id_url_custom_port = {allow_port}
unsafe_allow_id_url_single_label = {allow_single_label}
        "#
        )
    };

    let db_config = blahd::DatabaseConfig {
        in_memory: true,
        ..Default::default()
    };
    let server = server_with(Database::open(&db_config).unwrap(), &config);

    // Report in capabilities.
    let meta = server.get_metadata().await.unwrap();
    assert_eq!(meta.capabilities.allow_public_register, enabled);

    // Returns challenge headers only if registration is enabled.
    let hdrs = server.get_me(Some(&CAROL)).await.unwrap_err();
    if enabled {
        hdrs.unwrap();
    } else {
        assert_eq!(hdrs, None);
    }

    let server_url = format!("http://{}", server.domain());
    let req = server.sign(
        &CAROL,
        UserRegisterPayload {
            id_key: CAROL.pubkeys.id_key.clone(),
            // Unused values.
            id_url: server_url.parse().unwrap(),
            server_url: server_url.parse().unwrap(),
            challenge: None,
        },
    );
    let ret = server
        .request::<_, ()>(Method::POST, "/user/me", None, Some(req))
        .await;
    // Unpermitted due to server restriction.
    ret.expect_api_err(StatusCode::FORBIDDEN, "disabled");
}

#[cfg(feature = "unsafe_use_mock_instant_for_testing")]
#[rstest]
#[tokio::test]
async fn register_nonce() {
    use mock_instant::thread_local::MockClock;

    // Matches the config below.
    const NONCE_PERIOD: Duration = Duration::from_secs(10);

    let config = |_port| {
        format!(
            r#"
base_url="{BASE_URL}"
[register]
enable_public = true
unsafe_allow_id_url_http = true
[register.challenge.pow]
difficulty = 64 # Should fail the challenge if nonce matches.
nonce_rotate_secs = 10
        "#
        )
    };
    let db_config = blahd::DatabaseConfig {
        in_memory: true,
        ..Default::default()
    };
    MockClock::set_time(Duration::ZERO);
    let server = server_with(Database::open(&db_config).unwrap(), &config);
    // Avoid hitting the period boundary.
    MockClock::advance(Duration::from_secs(1));

    let (nonce0, _diff) = server.get_me(Some(&CAROL)).await.unwrap_err().unwrap();

    let register = |nonce: u32, expect_ok| {
        let req = UserRegisterPayload {
            id_key: CAROL.pubkeys.id_key.clone(),
            server_url: BASE_URL.parse().unwrap(),
            id_url: BASE_URL.parse().unwrap(),
            challenge: Some(UserRegisterChallengeResponse::Pow { nonce }),
        }
        .sign_msg(&CAROL.pubkeys.id_key, &CAROL.act_priv)
        .unwrap();
        let expect_err = if expect_ok {
            "hash challenge failed"
        } else {
            "invalid challenge nonce"
        };
        async {
            server
                .request::<_, ()>(Method::POST, "/user/me", None, Some(req))
                .await
                .expect_invalid_request(expect_err);
        }
    };

    // Valid nonce.
    register(nonce0, true).await;

    // After one nonce period, a new nonce is generated.
    MockClock::advance(NONCE_PERIOD);
    let (nonce1, _diff) = server.get_me(Some(&CAROL)).await.unwrap_err().unwrap();
    assert_ne!(nonce0, nonce1);

    // Both nonce are valid yet, because it's in the grace period.
    register(nonce0, true).await;
    register(nonce1, true).await;

    // After one period, another new nonce is generated.
    MockClock::advance(NONCE_PERIOD);
    let (nonce2, _diff) = server.get_me(Some(&CAROL)).await.unwrap_err().unwrap();
    assert_ne!(nonce0, nonce2);
    assert_ne!(nonce1, nonce2);

    // The oldest nonce expired. The last two noncesa re valid.
    register(nonce0, false).await;
    register(nonce1, true).await;
    register(nonce2, true).await;
}

#[rstest]
#[tokio::test]
async fn event(server: Server) {
    let rid1 = server
        .create_room(&ALICE, RoomAttrs::PUBLIC_JOINABLE, "room1")
        .await
        .unwrap();

    {
        let mut ws = server.connect_ws(None).await.unwrap();
        let msg = tokio::time::timeout(WS_CONNECT_TIMEOUT, ws.next())
            .await
            .unwrap();
        assert!(msg.is_none(), "auth should timeout");
    }

    {
        let mut ws = server.connect_ws(Some(&CAROL)).await.unwrap();
        assert!(
            ws.next().await.is_none(),
            "should close unauthorized connection",
        );
    }

    // Ok.
    let mut ws = server.connect_ws(Some(&ALICE)).await.unwrap();
    // TODO: Synchronize with the server so that following msgs will be received.

    // Should receive msgs from self-post.
    {
        let chat = server.post_chat(rid1, &ALICE, "alice1").await.unwrap();
        let got = ws.next().await.unwrap().unwrap();
        assert_eq!(got, ServerEvent::Msg(chat));
    }

    // Should receive msgs from other user.
    {
        server
            .join_room(rid1, &BOB, MemberPermission::MAX_SELF_ADD)
            .await
            .unwrap();
        let chat = server.post_chat(rid1, &BOB, "bob1").await.unwrap();
        let got = ws.next().await.unwrap().unwrap();
        assert_eq!(got, ServerEvent::Msg(chat));
    }

    // Should receive msgs from new room.
    let rid2 = server
        .create_room(&ALICE, RoomAttrs::PUBLIC_JOINABLE, "room2")
        .await
        .unwrap();
    {
        let chat = server.post_chat(rid2, &ALICE, "alice2").await.unwrap();
        let got = ws.next().await.unwrap().unwrap();
        assert_eq!(got, ServerEvent::Msg(chat));
    }

    // Each streams should receive each message once.
    {
        let mut ws2 = server.connect_ws(Some(&ALICE)).await.unwrap();

        let chat = server.post_chat(rid1, &ALICE, "alice1").await.unwrap();
        let got1 = ws.next().await.unwrap().unwrap();
        assert_eq!(got1, ServerEvent::Msg(chat.clone()));
        let got2 = ws2.next().await.unwrap().unwrap();
        assert_eq!(got2, ServerEvent::Msg(chat));
    }
}

#[rstest]
#[tokio::test]
async fn room_member(server: Server) {
    let rid = server
        .create_room(
            &ALICE,
            RoomAttrs::PUBLIC_READABLE | RoomAttrs::PUBLIC_JOINABLE,
            "public",
        )
        .await
        .unwrap();

    // Authentication is required.
    server
        .get::<RoomMemberList>(&format!("/room/{rid}/member"), None)
        .await
        .expect_api_err(StatusCode::UNAUTHORIZED, "unauthorized");

    // Not a room member.
    server
        .get::<RoomMemberList>(&format!("/room/{rid}/member"), Some(&auth(&BOB)))
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");

    server
        .join_room(rid, &BOB, MemberPermission::POST_CHAT)
        .await
        .unwrap();

    // No permission.
    server
        .get::<RoomMemberList>(&format!("/room/{rid}/member"), Some(&auth(&BOB)))
        .await
        .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");

    // OK.
    let got = server
        .get::<RoomMemberList>(&format!("/room/{rid}/member"), Some(&auth(&ALICE)))
        .await
        .unwrap();
    let expect = RoomMemberList {
        members: vec![
            RoomMember {
                id_key: ALICE.pubkeys.id_key.clone(),
                permission: MemberPermission::ALL,
                last_seen_cid: None,
            },
            RoomMember {
                id_key: BOB.pubkeys.id_key.clone(),
                permission: MemberPermission::POST_CHAT,
                last_seen_cid: None,
            },
        ],
        skip_token: None,
    };
    assert_eq!(got, expect);
}

#[rstest]
#[tokio::test]
async fn room_mgmt_remove(server: Server) {
    let rid = server
        .create_room(&ALICE, RoomAttrs::PUBLIC_JOINABLE, "public")
        .await
        .unwrap();
    server
        .join_room(rid, &BOB, MemberPermission::MAX_SELF_ADD)
        .await
        .unwrap();
    // Now bob can access the room.
    server
        .get::<RoomMetadata>(&format!("/room/{rid}"), Some(&auth(&BOB)))
        .await
        .unwrap();

    // No permission.
    server
        .remove_member(rid, &BOB, &ALICE)
        .await
        .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");

    // Invalid act user.
    server
        .remove_member(rid, &CAROL, &BOB)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");

    // Invalid operand user.
    server
        .remove_member(rid, &ALICE, &CAROL)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "member_not_found");

    // OK, removed.
    server.remove_member(rid, &ALICE, &BOB).await.unwrap();

    // Bob cannot access the room now.
    server
        .get::<RoomMetadata>(&format!("/room/{rid}"), Some(&auth(&BOB)))
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");
}

#[rstest]
#[tokio::test]
async fn room_mgmt_perm(server: Server) {
    let rid = server
        .create_room(&ALICE, RoomAttrs::PUBLIC_JOINABLE, "public")
        .await
        .unwrap();
    server
        .join_room(rid, &BOB, MemberPermission::MAX_SELF_ADD)
        .await
        .unwrap();

    let get_bob = || {
        server.get::<RoomMember>(
            &format!("/room/{rid}/member/{}", BOB.pubkeys.id_key),
            Some(&auth(&BOB)),
        )
    };
    // Initial permission.
    assert_eq!(
        get_bob().await.unwrap(),
        RoomMember {
            id_key: BOB.pubkeys.id_key.clone(),
            permission: MemberPermission::MAX_SELF_ADD,
            last_seen_cid: None,
        }
    );

    // OK, Alice grants Bob permission to change permission.
    server
        .update_member_perm(
            rid,
            &ALICE,
            &BOB,
            MemberPermission::POST_CHAT | MemberPermission::UPDATE_MEMBER,
        )
        .await
        .unwrap();
    assert_eq!(
        get_bob().await.unwrap().permission,
        MemberPermission::POST_CHAT | MemberPermission::UPDATE_MEMBER
    );

    // Cannot restrict a member with higher permission.
    server
        .update_member_perm(rid, &BOB, &ALICE, MemberPermission::empty())
        .await
        .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");

    // OK, Bob restrict themself.
    server
        .update_member_perm(rid, &BOB, &BOB, MemberPermission::empty())
        .await
        .unwrap();
    assert_eq!(
        get_bob().await.unwrap().permission,
        MemberPermission::empty(),
    );

    // Cannot self-grant permission.
    server
        .update_member_perm(rid, &BOB, &BOB, MemberPermission::POST_CHAT)
        .await
        .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");

    // Bob cannot chat now.
    server
        .post_chat(rid, &BOB, "no")
        .await
        .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");

    // OK, Alice grants Bob permission.
    server
        .update_member_perm(rid, &ALICE, &BOB, MemberPermission::POST_CHAT)
        .await
        .unwrap();
    assert_eq!(
        get_bob().await.unwrap().permission,
        MemberPermission::POST_CHAT,
    );

    // Bob can chat again.
    server.post_chat(rid, &BOB, "yay").await.unwrap();
}

#[rstest]
#[tokio::test]
async fn get_member_id_desc(server: Server) {
    let rid = server
        .create_room(&ALICE, RoomAttrs::PUBLIC_JOINABLE, "public")
        .await
        .unwrap();

    let get_id_desc = |src_user: &User, tgt_user: &User| {
        server
            .get::<UserIdentityDescResponse<Box<serde_json::value::Value>>>(
                &format!("/room/{rid}/member/{}/identity", tgt_user.pubkeys.id_key),
                Some(&auth(src_user)),
            )
            .map_ok(|desc| desc.identity["user"].as_str().unwrap().to_owned())
    };

    // Current user not in the room.
    get_id_desc(&BOB, &ALICE)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "room_not_found");

    // Target user not in the room.
    get_id_desc(&ALICE, &BOB)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "member_not_found");

    // OK, get self.
    let desc = get_id_desc(&ALICE, &ALICE).await.unwrap();
    assert_eq!(desc, "A");

    server
        .join_room(rid, &BOB, MemberPermission::MAX_SELF_ADD)
        .await
        .unwrap();

    // Ok, get member.
    let desc = get_id_desc(&ALICE, &BOB).await.unwrap();
    assert_eq!(desc, "B");
}
