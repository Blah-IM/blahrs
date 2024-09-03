use std::fmt;
use std::sync::Arc;

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRef, FromRequest, FromRequestParts, Request};
use axum::http::{header, request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{async_trait, Json};
use blah::types::{AuthPayload, UserKey, WithSig};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::AppState;

/// Error response body for json endpoints.
///
/// Mostly following: <https://learn.microsoft.com/en-us/graph/errors>
#[derive(Debug, Serialize)]
pub struct ApiError {
    #[serde(skip)]
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

macro_rules! error_response {
    ($status:expr, $code:literal, $msg:literal $(, $msg_args:expr)* $(,)?) => {
        $crate::middleware::ApiError {
            status: $status,
            code: $code,
            message: ::std::format!($msg $(, $msg_args)*),
        }
    };
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Resp<'a> {
            error: &'a ApiError,
        }
        let mut resp = Json(Resp { error: &self }).into_response();
        *resp.status_mut() = self.status;
        resp
    }
}

macro_rules! define_from_deser_rejection {
    ($($ty:ty, $name:literal;)*) => {
        $(
            impl From<$ty> for ApiError {
                fn from(rej: $ty) -> Self {
                    error_response!(
                        StatusCode::BAD_REQUEST,
                        "deserialization",
                        "invalid {}: {}",
                        $name,
                        rej,
                    )
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
        tracing::error!(%err, "database error");
        error_response!(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal server error",
        )
    }
}

/// Extractor for verified JSON payload.
#[derive(Debug)]
pub struct SignedJson<T>(pub WithSig<T>);

#[async_trait]
impl<S, T> FromRequest<S> for SignedJson<T>
where
    S: Send + Sync,
    T: Serialize + DeserializeOwned,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(data) = <Json<WithSig<T>> as FromRequest<S>>::from_request(req, state).await?;
        let st = <Arc<AppState>>::from_ref(state);
        st.verify_signed_data(&data)?;
        Ok(Self(data))
    }
}

/// Extractor for optional verified JSON authorization header.
#[derive(Debug)]
pub struct OptionalAuth(pub Option<UserKey>);

#[async_trait]
impl<S> FromRequestParts<S> for OptionalAuth
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Some(auth) = parts.headers.get(header::AUTHORIZATION) else {
            return Ok(Self(None));
        };

        let st = <Arc<AppState>>::from_ref(state);
        let data =
            serde_json::from_slice::<WithSig<AuthPayload>>(auth.as_bytes()).map_err(|err| {
                error_response!(
                    StatusCode::BAD_REQUEST,
                    "deserialization",
                    "invalid authorization header: {err}",
                )
            })?;
        st.verify_signed_data(&data)?;
        Ok(Self(Some(data.signee.user)))
    }
}
