#![expect(clippy::unwrap_used, reason = "FIXME: random false positive")]
#![expect(clippy::toplevel_ref_arg, reason = "easy to use for fixtures")]
use std::cell::RefCell;
use std::fmt;
use std::future::{Future, IntoFuture};
use std::ops::DerefMut;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::http::HeaderMap;
use blah_types::{
    get_timestamp, AuthPayload, ChatPayload, CreateGroup, CreatePeerChat, CreateRoomPayload, Id,
    MemberPermission, RichText, RoomAdminOp, RoomAdminPayload, RoomAttrs, RoomMetadata,
    ServerPermission, Signed, SignedChatMsg, UserActKeyDesc, UserIdentityDesc, UserKey,
    UserProfile, UserRegisterPayload, WithMsgId, X_BLAH_DIFFICULTY, X_BLAH_NONCE,
};
use blahd::{ApiError, AppState, Database, RoomList, RoomMsgs};
use ed25519_dalek::SigningKey;
use futures_util::future::BoxFuture;
use futures_util::TryFutureExt;
use parking_lot::Mutex;
use rand::rngs::mock::StepRng;
use rand::RngCore;
use reqwest::{header, Method, StatusCode};
use rstest::{fixture, rstest};
use rusqlite::{params, Connection};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use url::Url;

// Register API requires a non-IP hostname.
const LOCALHOST: &str = "localhost";
const REGISTER_DIFFICULTY: u8 = 1;

const TIME_TOLERANCE: Duration = Duration::from_millis(100);

const CONFIG: fn(u16) -> String = |port| {
    format!(
        r#"
base_url="http://{LOCALHOST}:{port}"

[register]
enable_public = true
difficulty = {REGISTER_DIFFICULTY}
request_timeout_secs = 1
unsafe_allow_id_url_http = true
unsafe_allow_id_url_custom_port = true
        "#
    )
};

static ALICE_PRIV: LazyLock<SigningKey> = LazyLock::new(|| SigningKey::from_bytes(&[b'A'; 32]));
static ALICE: LazyLock<UserKey> = LazyLock::new(|| UserKey(ALICE_PRIV.verifying_key().to_bytes()));
static BOB_PRIV: LazyLock<SigningKey> = LazyLock::new(|| SigningKey::from_bytes(&[b'B'; 32]));
static BOB: LazyLock<UserKey> = LazyLock::new(|| UserKey(BOB_PRIV.verifying_key().to_bytes()));
static CAROL_PRIV: LazyLock<SigningKey> = LazyLock::new(|| SigningKey::from_bytes(&[b'C'; 32]));
static CAROL: LazyLock<UserKey> = LazyLock::new(|| UserKey(CAROL_PRIV.verifying_key().to_bytes()));

static CAROL_ACT_PRIV: LazyLock<SigningKey> = LazyLock::new(|| SigningKey::from_bytes(&[b'c'; 32]));

#[fixture]
fn rng() -> impl RngCore {
    rand::rngs::mock::StepRng::new(42, 1)
}

#[derive(Debug, Serialize, Deserialize)]
enum NoContent {}

trait ResultExt {
    fn expect_api_err(self, status: StatusCode, code: &str);
}

impl<T: fmt::Debug> ResultExt for Result<T> {
    #[track_caller]
    fn expect_api_err(self, status: StatusCode, code: &str) {
        let err = self
            .unwrap_err()
            .downcast::<ApiErrorWithHeaders>()
            .unwrap()
            .error;
        assert_eq!(
            (err.status, &*err.code),
            (status, code),
            "unexpecteed API error: {err:?}",
        );
    }
}

#[derive(Debug)]
pub struct ApiErrorWithHeaders {
    error: ApiError,
    headers: HeaderMap,
}

impl fmt::Display for ApiErrorWithHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for ApiErrorWithHeaders {}

#[derive(Debug)]
struct Server {
    port: u16,
    client: reqwest::Client,
    rng: RefCell<StepRng>,
}

impl Server {
    fn url(&self, rhs: impl fmt::Display) -> String {
        format!("http://{}:{}{}", LOCALHOST, self.port, rhs)
    }

    fn rng(&self) -> impl DerefMut<Target = impl RngCore> + use<'_> {
        self.rng.borrow_mut()
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
            let headers = resp.headers().clone();
            let resp_str = resp.text().await?;

            if !status.is_success() {
                #[derive(Deserialize)]
                struct Resp {
                    error: ApiError,
                }
                let Resp { mut error } = serde_json::from_str(&resp_str)?;
                error.status = status;
                Err(ApiErrorWithHeaders { error, headers }.into())
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

    fn create_room(
        &self,
        key: &SigningKey,
        attrs: RoomAttrs,
        title: &str,
    ) -> impl Future<Output = Result<Id>> + use<'_> {
        let req = sign(
            key,
            &mut *self.rng.borrow_mut(),
            CreateRoomPayload::Group(CreateGroup {
                attrs,
                title: title.to_string(),
            }),
        );
        async move {
            Ok(self
                .request(Method::POST, "/room/create", None, Some(&req))
                .await?
                .unwrap())
        }
    }

    fn join_room(
        &self,
        rid: Id,
        key: &SigningKey,
        permission: MemberPermission,
    ) -> impl Future<Output = Result<()>> + use<'_> {
        let req = sign(
            key,
            &mut *self.rng.borrow_mut(),
            RoomAdminPayload {
                room: rid,
                op: RoomAdminOp::AddMember {
                    permission,
                    user: UserKey(key.verifying_key().to_bytes()),
                },
            },
        );
        self.request::<_, NoContent>(Method::POST, &format!("/room/{rid}/admin"), None, Some(req))
            .map_ok(|None| {})
    }

    fn leave_room(&self, rid: Id, key: &SigningKey) -> impl Future<Output = Result<()>> + use<'_> {
        let req = sign(
            key,
            &mut *self.rng.borrow_mut(),
            RoomAdminPayload {
                room: rid,
                op: RoomAdminOp::RemoveMember {
                    user: UserKey(key.verifying_key().to_bytes()),
                },
            },
        );
        self.request::<_, NoContent>(Method::POST, &format!("/room/{rid}/admin"), None, Some(req))
            .map_ok(|None| {})
    }

    fn post_chat(
        &self,
        rid: Id,
        key: &SigningKey,
        text: &str,
    ) -> impl Future<Output = Result<WithMsgId<SignedChatMsg>>> + use<'_> {
        let msg = sign(
            key,
            &mut *self.rng.borrow_mut(),
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
                INSERT INTO `user` (`userkey`, `permission`, `last_fetch_time`, `id_desc`)
                VALUES (?, ?, 0, '{}')
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
            add_user.execute(params![user, perm]).unwrap();
            let uid = conn.last_insert_rowid();
            add_act_key.execute(params![uid, user, i64::MAX]).unwrap();
        }
    }
    let db = Database::from_raw(conn).unwrap();

    // Use std's to avoid async, since we need no name resolution.
    let listener = std::net::TcpListener::bind(format!("{LOCALHOST}:0")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = TcpListener::from_std(listener).unwrap();

    // TODO: Testing config is hard to build because it does have a `Default` impl.
    let config = toml::from_str(&CONFIG(port)).unwrap();
    let st = AppState::new(db, config);
    let router = blahd::router(Arc::new(st));

    tokio::spawn(axum::serve(listener, router).into_future());
    let client = reqwest::ClientBuilder::new().no_proxy().build().unwrap();
    let rng = StepRng::new(24, 1).into();
    Server { port, client, rng }
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

fn sign<T: Serialize>(key: &SigningKey, rng: &mut dyn RngCore, payload: T) -> Signed<T> {
    Signed::sign(key, get_timestamp(), rng, payload).unwrap()
}

fn auth(key: &SigningKey, rng: &mut impl RngCore) -> String {
    serde_json::to_string(&sign(key, rng, AuthPayload {})).unwrap()
}

#[rstest]
#[case::public(true)]
#[case::private(false)]
#[tokio::test]
async fn room_create_get(server: Server, ref mut rng: impl RngCore, #[case] public: bool) {
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
        .create_room(&ALICE_PRIV, room_meta.attrs, title)
        .await
        .unwrap();
    room_meta.rid = rid;

    // Bob has no permission.
    server
        .create_room(&BOB_PRIV, room_meta.attrs, title)
        .await
        .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");

    // Alice can always access it.
    let got_meta = server
        .get::<RoomMetadata>(&format!("/room/{rid}"), Some(&auth(&ALICE_PRIV, rng)))
        .await
        .unwrap();
    assert_eq!(got_meta, room_meta);

    // Bob or public can access it when it is public.
    for auth in [None, Some(auth(&BOB_PRIV, rng))] {
        let resp = server
            .get::<RoomMetadata>(&format!("/room/{rid}"), auth.as_deref())
            .await;
        if public {
            assert_eq!(resp.unwrap(), room_meta);
        } else {
            resp.expect_api_err(StatusCode::NOT_FOUND, "not_found");
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
        .get::<RoomList>("/room?filter=joined", Some(&auth(&ALICE_PRIV, rng)))
        .await
        .unwrap();
    assert_eq!(got_joined, expect_list(true, Some(MemberPermission::ALL)));

    let got_joined = server
        .get::<RoomList>("/room?filter=joined", Some(&auth(&BOB_PRIV, rng)))
        .await
        .unwrap();
    assert_eq!(got_joined, expect_list(false, None));
}

#[rstest]
#[tokio::test]
async fn room_join_leave(server: Server, ref mut rng: impl RngCore) {
    let rid_pub = server
        .create_room(&ALICE_PRIV, RoomAttrs::PUBLIC_JOINABLE, "public room")
        .await
        .unwrap();
    let rid_priv = server
        .create_room(&ALICE_PRIV, RoomAttrs::empty(), "private room")
        .await
        .unwrap();

    let join =
        |rid: Id, key: &SigningKey| server.join_room(rid, key, MemberPermission::MAX_SELF_ADD);

    // Ok.
    join(rid_pub, &BOB_PRIV).await.unwrap();
    // Already joined.
    join(rid_pub, &BOB_PRIV)
        .await
        .expect_api_err(StatusCode::CONFLICT, "exists");
    // Not permitted.
    join(rid_priv, &BOB_PRIV)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");
    // Not exists.
    join(Id::INVALID, &BOB_PRIV)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");
    // Overly high permission.
    server
        .join_room(rid_priv, &BOB_PRIV, MemberPermission::ALL)
        .await
        .expect_api_err(StatusCode::BAD_REQUEST, "deserialization");

    // Bob is joined now.
    assert_eq!(
        server
            .get::<RoomList>("/room?filter=joined", Some(&auth(&BOB_PRIV, rng)))
            .await
            .unwrap()
            .rooms
            .len(),
        1,
    );

    let leave = |rid: Id, key: &SigningKey| server.leave_room(rid, key);

    // Ok.
    leave(rid_pub, &BOB_PRIV).await.unwrap();
    // Already left.
    leave(rid_pub, &BOB_PRIV)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");
    // Unpermitted and not inside.
    leave(rid_priv, &BOB_PRIV)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");
    // Invalid room.
    leave(Id::INVALID, &BOB_PRIV)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");
}

#[rstest]
#[tokio::test]
async fn room_chat_post_read(server: Server, ref mut rng: impl RngCore) {
    let rid_pub = server
        .create_room(
            &ALICE_PRIV,
            RoomAttrs::PUBLIC_READABLE | RoomAttrs::PUBLIC_JOINABLE,
            "public room",
        )
        .await
        .unwrap();
    let rid_priv = server
        .create_room(&ALICE_PRIV, RoomAttrs::empty(), "private room")
        .await
        .unwrap();

    let mut chat = |rid: Id, key: &SigningKey, msg: &str| {
        sign(
            key,
            rng,
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
    let chat1 = chat(rid_pub, &ALICE_PRIV, "one");
    let chat2 = chat(rid_pub, &ALICE_PRIV, "two");
    let cid1 = post(rid_pub, chat1.clone()).await.unwrap();
    let cid2 = post(rid_pub, chat2.clone()).await.unwrap();

    // Duplicated chat.
    post(rid_pub, chat2.clone())
        .await
        .expect_api_err(StatusCode::BAD_REQUEST, "duplicated_nonce");

    // Wrong room.
    post(rid_pub, chat(rid_priv, &ALICE_PRIV, "wrong room"))
        .await
        .expect_api_err(StatusCode::BAD_REQUEST, "invalid_request");

    // Not a member.
    post(rid_pub, chat(rid_pub, &BOB_PRIV, "not a member"))
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");

    // Is a member but without permission.
    server
        .join_room(rid_pub, &BOB_PRIV, MemberPermission::empty())
        .await
        .unwrap();
    post(rid_pub, chat(rid_pub, &BOB_PRIV, "no permission"))
        .await
        .expect_api_err(StatusCode::FORBIDDEN, "permission_denied");

    // Room not exists.
    post(Id::INVALID, chat(Id::INVALID, &ALICE_PRIV, "not permitted"))
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");

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
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");

    // Not a member.
    server
        .get::<RoomMsgs>(
            &format!("/room/{rid_priv}/msg"),
            Some(&auth(&BOB_PRIV, rng)),
        )
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");

    // Ok.
    let msgs = server
        .get::<RoomMsgs>(
            &format!("/room/{rid_priv}/msg"),
            Some(&auth(&ALICE_PRIV, rng)),
        )
        .await
        .unwrap();
    assert_eq!(msgs, RoomMsgs::default());
}

#[rstest]
#[tokio::test]
async fn last_seen(server: Server, ref mut rng: impl RngCore) {
    let title = "public room";
    let attrs = RoomAttrs::PUBLIC_READABLE | RoomAttrs::PUBLIC_JOINABLE;
    let member_perm = MemberPermission::ALL;
    let rid = server.create_room(&ALICE_PRIV, attrs, title).await.unwrap();
    server
        .join_room(rid, &BOB_PRIV, MemberPermission::MAX_SELF_ADD)
        .await
        .unwrap();

    let alice_chat1 = server.post_chat(rid, &ALICE_PRIV, "alice1").await.unwrap();
    let alice_chat2 = server.post_chat(rid, &ALICE_PRIV, "alice2").await.unwrap();

    // 2 new msgs.
    let rooms = server
        .get::<RoomList>("/room?filter=unseen", Some(&auth(&ALICE_PRIV, rng)))
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

    let seen = |key: &SigningKey, cid: Id| {
        server.request::<NoContent, NoContent>(
            Method::POST,
            &format!("/room/{rid}/msg/{cid}/seen"),
            Some(&auth(key, &mut *server.rng.borrow_mut())),
            None,
        )
    };

    // Mark the first one seen.
    seen(&ALICE_PRIV, alice_chat1.cid).await.unwrap();

    // 1 new msg.
    let rooms = server
        .get::<RoomList>("/room?filter=unseen", Some(&auth(&ALICE_PRIV, rng)))
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
    seen(&ALICE_PRIV, alice_chat2.cid).await.unwrap();
    let rooms = server
        .get::<RoomList>("/room?filter=unseen", Some(&auth(&ALICE_PRIV, rng)))
        .await
        .unwrap();
    assert_eq!(rooms, RoomList::default());

    // Marking a seen message seen is a no-op.
    seen(&ALICE_PRIV, alice_chat2.cid).await.unwrap();
    let rooms = server
        .get::<RoomList>("/room?filter=unseen", Some(&auth(&ALICE_PRIV, rng)))
        .await
        .unwrap();
    assert_eq!(rooms, RoomList::default());
}

#[rstest]
#[tokio::test]
async fn peer_chat(server: Server, ref mut rng: impl RngCore) {
    let mut create_chat = |src: &SigningKey, tgt: &UserKey| {
        let req = sign(
            src,
            rng,
            CreateRoomPayload::PeerChat(CreatePeerChat { peer: tgt.clone() }),
        );
        server
            .request::<_, Id>(Method::POST, "/room/create", None, Some(req))
            .map_ok(|resp| resp.unwrap())
    };

    // Bob disallows peer chat.
    create_chat(&ALICE_PRIV, &BOB)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");

    // Alice accepts bob.
    let rid = create_chat(&BOB_PRIV, &ALICE).await.unwrap();

    // Room already exists.
    create_chat(&BOB_PRIV, &ALICE)
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
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");

    // Both alice and bob are in the room.
    for (key, peer) in [(&*ALICE_PRIV, &*BOB), (&*BOB_PRIV, &*ALICE)] {
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
            .get::<RoomMetadata>(&format!("/room/{rid}"), Some(&auth(key, rng)))
            .await
            .unwrap();
        assert_eq!(meta, expect_meta);

        expect_meta.member_permission = Some(MemberPermission::MAX_PEER_CHAT);
        expect_meta.peer_user = Some(peer.clone());
        let rooms = server
            .get::<RoomList>("/room?filter=joined", Some(&auth(key, rng)))
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
#[tokio::test]
async fn register(server: Server) {
    let rid = server
        .create_room(
            &ALICE_PRIV,
            RoomAttrs::PUBLIC_READABLE | RoomAttrs::PUBLIC_JOINABLE,
            "public room",
        )
        .await
        .unwrap();

    let get_me = |user: Option<&SigningKey>| {
        let auth = user.map(|user| auth(user, &mut *server.rng()));
        server
            .request::<(), ()>(Method::GET, "/user/me", auth.as_deref(), None)
            .map_ok(|_| ())
            .map_err(|err| {
                let err = err.downcast::<ApiErrorWithHeaders>().unwrap();
                assert_eq!(err.error.status, StatusCode::NOT_FOUND);
                let challenge_nonce = err.headers[X_BLAH_NONCE]
                    .to_str()
                    .unwrap()
                    .parse::<u32>()
                    .unwrap();
                let difficulty = err.headers[X_BLAH_DIFFICULTY]
                    .to_str()
                    .unwrap()
                    .parse::<u8>()
                    .unwrap();
                (challenge_nonce, difficulty)
            })
    };

    // Alice is registered.
    get_me(Some(&ALICE_PRIV)).await.unwrap();

    // Carol is not registered.
    let (challenge_nonce, diff) = get_me(Some(&CAROL_PRIV)).await.unwrap_err();
    assert_eq!(diff, REGISTER_DIFFICULTY);

    // Without token.
    let ret2 = get_me(None).await.unwrap_err();
    assert_eq!(ret2, (challenge_nonce, diff));

    let mut req = UserRegisterPayload {
        id_key: CAROL.clone(),
        // Fake values.
        server_url: "http://invalid.example.com".parse().unwrap(),
        id_url: "file:///etc/passwd".parse().unwrap(),
        challenge_nonce: challenge_nonce - 1,
    };
    let register = |req: Signed<UserRegisterPayload>| {
        server
            .request::<_, ()>(Method::POST, "/user/me", None, Some(req))
            .map_ok(|_| {})
    };
    let sign_with_difficulty = |req: &UserRegisterPayload, pass: bool| loop {
        let signed = sign(&CAROL_PRIV, &mut *server.rng(), req.clone());
        let mut h = Sha256::new();
        h.update(signed.canonical_signee());
        let h = h.finalize();
        if (h[0] >> (8 - REGISTER_DIFFICULTY) == 0) == pass {
            return signed;
        }
    };
    let register_fast =
        |req: &UserRegisterPayload| register(sign(&CAROL_PRIV, &mut *server.rng(), req.clone()));

    register_fast(&req)
        .await
        .expect_api_err(StatusCode::BAD_REQUEST, "invalid_server_url");
    req.server_url = server.url("").parse().unwrap();

    register_fast(&req)
        .await
        .expect_api_err(StatusCode::BAD_REQUEST, "invalid_id_url");

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
        req.id_url = Url::parse(&format!("http://{LOCALHOST}:{port}")).unwrap();

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
        .expect_api_err(StatusCode::BAD_REQUEST, "invalid_challenge_nonce");
    req.challenge_nonce += 1;

    register(sign_with_difficulty(&req, false))
        .await
        .expect_api_err(StatusCode::BAD_REQUEST, "invalid_challenge_hash");

    //// Starting here, early validation passed. ////

    // id_url 404
    register(sign_with_difficulty(&req, true))
        .await
        .expect_api_err(StatusCode::UNAUTHORIZED, "fetch_id_description");

    // Timeout
    set_handler! {{
        tokio::time::sleep(Duration::from_secs(2)).await;
        (StatusCode::OK, "".into())
    }}
    let inst = Instant::now();
    register(sign_with_difficulty(&req, true))
        .await
        .expect_api_err(StatusCode::UNAUTHORIZED, "fetch_id_description");
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
        .expect_api_err(StatusCode::UNAUTHORIZED, "fetch_id_description");

    let set_id_desc = |desc: &UserIdentityDesc| {
        let desc = serde_json::to_string(&desc).unwrap();
        set_handler! { [let desc = desc.clone()] {
            (StatusCode::OK, desc.clone())
        }}
    };
    let mut id_desc = {
        let act_key = sign(
            &CAROL_PRIV,
            &mut *server.rng(),
            UserActKeyDesc {
                act_key: UserKey(CAROL_ACT_PRIV.verifying_key().to_bytes()),
                expire_time: u64::MAX,
                comment: "comment".into(),
            },
        );
        let profile = sign(
            &CAROL_ACT_PRIV,
            &mut *server.rng(),
            UserProfile {
                preferred_chat_server_urls: Vec::new(),
                id_urls: vec![req.id_url.join("/mismatch").unwrap()],
            },
        );
        UserIdentityDesc {
            id_key: CAROL.clone(),
            act_keys: vec![act_key],
            profile,
        }
    };

    // id_url mismatch
    set_id_desc(&id_desc);
    register(sign_with_difficulty(&req, true))
        .await
        .expect_api_err(StatusCode::UNAUTHORIZED, "invalid_id_description");

    // Still not registered.
    get_me(Some(&CAROL_PRIV)).await.unwrap_err();
    server
        .join_room(rid, &CAROL_PRIV, MemberPermission::MAX_SELF_ADD)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");

    // Finally pass.
    id_desc.profile = sign(
        &CAROL_ACT_PRIV,
        &mut *server.rng(),
        UserProfile {
            preferred_chat_server_urls: Vec::new(),
            id_urls: vec![req.id_url.clone()],
        },
    );
    set_id_desc(&id_desc);
    register(sign_with_difficulty(&req, true)).await.unwrap();

    // Registered now.
    get_me(Some(&CAROL_PRIV)).await.unwrap();
    server
        .join_room(rid, &CAROL_PRIV, MemberPermission::MAX_SELF_ADD)
        .await
        .unwrap();
}
