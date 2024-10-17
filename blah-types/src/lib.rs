// Re-export of public dependencies.
pub use bitflags;
pub use ed25519_dalek;
pub use url;

pub use crypto::{get_timestamp, PubKey, SignExt, Signed, Signee, UserKey};
pub use msg::Id;

#[cfg(not(feature = "schemars"))]
macro_rules! impl_json_schema_as {
    ($($tt:tt)*) => {};
}

// Workaround: https://github.com/GREsau/schemars/issues/267
#[cfg(feature = "schemars")]
macro_rules! impl_json_schema_as {
    ($ty:ident => $as_ty:ty) => {
        impl schemars::JsonSchema for $ty {
            fn schema_name() -> String {
                stringify!($ty).into()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!(module_path!(), "::", stringify!($ty)).into()
            }

            fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
                gen.subschema_for::<$as_ty>()
            }
        }
    };
}

pub mod crypto;
pub mod identity;
pub mod msg;
pub mod server;
