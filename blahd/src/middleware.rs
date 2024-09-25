use std::backtrace::Backtrace;
use std::convert::Infallible;
use std::fmt;
use std::sync::Arc;

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRef, FromRequest, FromRequestParts, Request};
use axum::http::{header, request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{async_trait, Json};
use blah_types::msg::AuthPayload;
use blah_types::{Signed, UserKey};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::AppState;

macro_rules! define_api_error {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $variant:ident
                    $(= ($status1:expr, $message1:expr))?
                    $(($(;$marker2:tt)? $ty:ty) = ($status2:expr))?
                    ,
            )*
        }
    ) => {
        $(#[$meta])*
        $vis enum $name {
            $($variant $(($ty))?,)*
        }

        impl $name {
            fn to_response_tuple(&self) -> (StatusCode, &'static str, &str) {
                paste::paste! {
                    match self {
                        $(
                            Self::$variant
                                $(=> ($status1, stringify!([<$variant:snake>]), $message1))?
                                $((message) => ($status2, stringify!([<$variant:snake>]), message))?
                                ,
                        )*
                    }
                }
            }
        }

    };
}

define_api_error! {

/// Error response body for json endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ApiError {
    InvalidRequest(Box<str>) = (StatusCode::BAD_REQUEST),
    Unauthorized(&'static str) = (StatusCode::UNAUTHORIZED),
    PermissionDenied(&'static str) = (StatusCode::FORBIDDEN),
    Disabled(&'static str) = (StatusCode::FORBIDDEN),
    UserNotFound = (StatusCode::NOT_FOUND, "the user does not exist"),
    RoomNotFound = (StatusCode::NOT_FOUND, "the room does not exist or the user is not a room member"),
    PeerUserNotFound = (StatusCode::NOT_FOUND, "peer user does not exist or disallows peer chat"),
    Conflict(&'static str) = (StatusCode::CONFLICT),
    Exists(&'static str) = (StatusCode::CONFLICT),
    FetchIdDescription(Box<str>) = (StatusCode::UNPROCESSABLE_ENTITY),
    InvalidIdDescription(Box<str>) = (StatusCode::UNPROCESSABLE_ENTITY),

    ServerError = (StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
    NotImplemented(&'static str) = (StatusCode::NOT_IMPLEMENTED),
}

}

macro_rules! api_ensure {
    ($assertion:expr, $msg:literal $(,)?) => {
        if !$assertion {
            return Err($crate::middleware::ApiError::InvalidRequest($msg.into()));
        }
    };
    ($assertion:expr, $err:expr $(,)?) => {
        if !$assertion {
            return Err($err);
        }
    };
}

/// Response structure mostly follows:
/// <https://learn.microsoft.com/en-us/graph/errors>
/// Only `error/{code,message}` are provided and are always available.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Resp<'a> {
            error: Error<'a>,
        }
        #[derive(Serialize)]
        struct Error<'a> {
            code: &'a str,
            message: &'a str,
        }

        let (status, code, message) = self.to_response_tuple();
        let mut resp = Json(Resp {
            error: Error { code, message },
        })
        .into_response();
        *resp.status_mut() = status;
        resp
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (_, code, message) = self.to_response_tuple();
        write!(f, "({code}) {message}")
    }
}

impl std::error::Error for ApiError {}

// For infallible extractors.
impl From<Infallible> for ApiError {
    fn from(v: Infallible) -> Self {
        match v {}
    }
}

macro_rules! define_from_deser_rejection {
    ($($ty:ty, $name:literal;)*) => {
        $(
            impl From<$ty> for ApiError {
                fn from(rej: $ty) -> Self {
                    ApiError::InvalidRequest(format!(concat!("invalid ", $name, "{}"), rej).into())
                }
            }
        )*
    };
}

define_from_deser_rejection! {
    JsonRejection, "json";
    QueryRejection, "query";
    PathRejection, "path";
}

impl From<rusqlite::Error> for ApiError {
    fn from(err: rusqlite::Error) -> Self {
        tracing::error!(%err, backtrace = %Backtrace::force_capture(), "database error");
        ApiError::ServerError
    }
}

/// Extractor for verified JSON payload.
#[derive(Debug)]
pub struct SignedJson<T>(pub Signed<T>);

#[async_trait]
impl<S, T> FromRequest<S> for SignedJson<T>
where
    S: Send + Sync,
    T: Serialize + DeserializeOwned,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(data) = <Json<Signed<T>> as FromRequest<S>>::from_request(req, state).await?;
        let st = <Arc<AppState>>::from_ref(state);
        st.verify_signed_data(&data)?;
        Ok(Self(data))
    }
}

#[derive(Debug)]
pub enum AuthRejection {
    None,
    Invalid(ApiError),
}

impl From<AuthRejection> for ApiError {
    fn from(rej: AuthRejection) -> Self {
        match rej {
            AuthRejection::None => ApiError::Unauthorized("missing authorization header"),
            AuthRejection::Invalid(err) => err,
        }
    }
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        ApiError::from(self).into_response()
    }
}

pub trait ResultExt {
    fn into_optional(self) -> Result<Option<UserKey>, ApiError>;
}

impl ResultExt for Result<Auth, AuthRejection> {
    fn into_optional(self) -> Result<Option<UserKey>, ApiError> {
        match self {
            Ok(auth) => Ok(Some(auth.0)),
            Err(AuthRejection::None) => Ok(None),
            Err(AuthRejection::Invalid(err)) => Err(err),
        }
    }
}

pub type MaybeAuth = Result<Auth, AuthRejection>;

/// Extractor for verified JSON authorization header.
#[derive(Debug)]
pub struct Auth(pub UserKey);

#[async_trait]
impl<S> FromRequestParts<S> for Auth
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(header::AUTHORIZATION)
            .ok_or(AuthRejection::None)?;

        let st = <Arc<AppState>>::from_ref(state);
        let data =
            serde_json::from_slice::<Signed<AuthPayload>>(auth.as_bytes()).map_err(|_err| {
                AuthRejection::Invalid(ApiError::InvalidRequest(
                    "invalid authorization header".into(),
                ))
            })?;
        st.verify_signed_data(&data)
            .map_err(AuthRejection::Invalid)?;
        Ok(Self(data.signee.user))
    }
}
