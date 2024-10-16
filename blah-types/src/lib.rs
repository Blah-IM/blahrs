// Re-export of public dependencies.
pub use bitflags;
pub use ed25519_dalek;
pub use url;

pub use crypto::{get_timestamp, PubKey, SignExt, Signed, Signee, UserKey};
pub use msg::Id;

pub mod crypto;
pub mod identity;
pub mod msg;
pub mod server;

#[cfg(feature = "utoipa")]
pub fn openapi() -> utoipa::openapi::OpenApi {
    use utoipa::OpenApi;

    #[derive(OpenApi)]
    #[openapi(components(schemas(
        crypto::Signed::<msg::AuthPayload>,
        crypto::Signed::<msg::ChatPayload>,
        crypto::Signed::<msg::CreateRoomPayload>,
        crypto::Signed::<msg::DeleteRoomPayload>,
        crypto::Signed::<msg::RoomAdminPayload>,
        crypto::Signed::<msg::UserRegisterPayload>,
        identity::UserIdentityDesc,
        identity::UserProfile,
        msg::AuthPayload,
        msg::ChatPayload,
        msg::DeleteRoomPayload,
        msg::RichText,
        msg::RoomAdminPayload,
        msg::UserRegisterPayload,
        server::ClientEvent,
        server::ErrorResponse,
        server::ErrorResponseWithChallenge,
        server::RoomList,
        server::RoomMetadata,
        server::RoomMsgs,
        server::ServerCapabilities,
        server::ServerEvent,
        server::ServerMetadata,
    )))]
    struct ApiDoc;

    ApiDoc::openapi()
}

#[cfg(feature = "utoipa")]
#[test]
#[expect(clippy::print_stdout, reason = "allowed in tests")]
fn test_openapi() {
    let json = crate::openapi().to_pretty_json().unwrap();
    println!("{json}");
}
