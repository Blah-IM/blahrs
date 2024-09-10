#![expect(clippy::unwrap_used, reason = "FIXME: random false positive")]
#![expect(clippy::toplevel_ref_arg, reason = "easy to use for fixtures")]
use std::cell::RefCell;
use std::fmt;
use std::future::{Future, IntoFuture};
use std::sync::{Arc, LazyLock};

use anyhow::Result;
use blah_types::{
    get_timestamp, AuthPayload, ChatItem, ChatPayload, CreateGroup, CreatePeerChat,
    CreateRoomPayload, Id, MemberPermission, RichText, RoomAdminOp, RoomAdminPayload, RoomAttrs,
    RoomMember, RoomMemberList, RoomMetadata, ServerPermission, UserKey, WithItemId, WithSig,
};
use blahd::{ApiError, AppState, Database, RoomItems, RoomList};
use ed25519_dalek::SigningKey;
use futures_util::TryFutureExt;
use rand::rngs::mock::StepRng;
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
static BOB: LazyLock<UserKey> = LazyLock::new(|| UserKey(BOB_PRIV.verifying_key().to_bytes()));

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
        let err = self.unwrap_err().downcast::<ApiError>().unwrap();
        assert_eq!(err.status, status);
        assert_eq!(err.code, code);
    }
}

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
                members: RoomMemberList(vec![RoomMember {
                    permission: MemberPermission::ALL,
                    user: UserKey(key.verifying_key().to_bytes()),
                }]),
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
    ) -> impl Future<Output = Result<WithItemId<ChatItem>>> + use<'_> {
        let item = sign(
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
                    &format!("/room/{rid}/item"),
                    None,
                    Some(item.clone()),
                )
                .await?
                .unwrap();
            Ok(WithItemId { cid, item })
        }
    }
}

#[fixture]
fn server() -> Server {
    let _ = tracing_subscriber::fmt::try_init();

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

fn sign<T: Serialize>(key: &SigningKey, rng: &mut dyn RngCore, payload: T) -> WithSig<T> {
    WithSig::sign(key, get_timestamp(), rng, payload).unwrap()
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
        last_item: None,
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
async fn room_item_post_read(server: Server, ref mut rng: impl RngCore) {
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
    let post = |rid: Id, chat: ChatItem| {
        server
            .request::<_, Id>(Method::POST, &format!("/room/{rid}/item"), None, Some(chat))
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

    //// Item listing ////

    let chat1 = WithItemId::new(cid1, chat1);
    let chat2 = WithItemId::new(cid2, chat2);

    // List with default page size.
    let items = server
        .get::<RoomItems>(&format!("/room/{rid_pub}/item"), None)
        .await
        .unwrap();
    assert_eq!(
        items,
        RoomItems {
            items: vec![chat2.clone(), chat1.clone()],
            skip_token: None,
        },
    );

    // List with small page size.
    let items = server
        .get::<RoomItems>(&format!("/room/{rid_pub}/item?top=1"), None)
        .await
        .unwrap();
    assert_eq!(
        items,
        RoomItems {
            items: vec![chat2.clone()],
            skip_token: Some(cid2),
        },
    );

    // Second page.
    let items = server
        .get::<RoomItems>(
            &format!("/room/{rid_pub}/item?skipToken={cid2}&top=1"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        items,
        RoomItems {
            items: vec![chat1.clone()],
            skip_token: Some(cid1),
        },
    );

    // No more.
    let items = server
        .get::<RoomItems>(
            &format!("/room/{rid_pub}/item?skipToken={cid1}&top=1"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(items, RoomItems::default());

    //// Private room ////

    // Access without token.
    server
        .get::<RoomItems>(&format!("/room/{rid_priv}/item"), None)
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");

    // Not a member.
    server
        .get::<RoomItems>(
            &format!("/room/{rid_priv}/item"),
            Some(&auth(&BOB_PRIV, rng)),
        )
        .await
        .expect_api_err(StatusCode::NOT_FOUND, "not_found");

    // Ok.
    let items = server
        .get::<RoomItems>(
            &format!("/room/{rid_priv}/item"),
            Some(&auth(&ALICE_PRIV, rng)),
        )
        .await
        .unwrap();
    assert_eq!(items, RoomItems::default());
}

#[rstest]
#[tokio::test]
async fn last_seen_item(server: Server, ref mut rng: impl RngCore) {
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

    // 2 new items.
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
                last_item: Some(alice_chat2.clone()),
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
            &format!("/room/{rid}/item/{cid}/seen"),
            Some(&auth(key, &mut *server.rng.borrow_mut())),
            None,
        )
    };

    // Mark the first one seen.
    seen(&ALICE_PRIV, alice_chat1.cid).await.unwrap();

    // 1 new item.
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
                last_item: Some(alice_chat2.clone()),
                last_seen_cid: Some(alice_chat1.cid),
                unseen_cnt: Some(1),
                member_permission: Some(member_perm),
                peer_user: None,
            }],
            skip_token: None,
        }
    );

    // Mark the second one seen. Now there is no new items.
    seen(&ALICE_PRIV, alice_chat2.cid).await.unwrap();
    let rooms = server
        .get::<RoomList>("/room?filter=unseen", Some(&auth(&ALICE_PRIV, rng)))
        .await
        .unwrap();
    assert_eq!(rooms, RoomList::default());

    // Marking a seen item seen is a no-op.
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
            last_item: None,
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
