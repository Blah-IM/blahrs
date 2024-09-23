//! Room feed generation.
use std::num::NonZero;
use std::time::{Duration, SystemTime};

use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use blah_types::{SignedChatMsg, WithMsgId};
use serde::{Deserialize, Serialize};
use url::Url;

const JSON_FEED_MIME: &str = "application/feed+json";

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub max_page_len: NonZero<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_page_len: 64.try_into().expect("not zero"),
        }
    }
}

/// Ref: <https://www.jsonfeed.org/version/1.1/>
#[derive(Debug, Serialize)]
#[serde(tag = "version", rename = "https://jsonfeed.org/version/1.1")]
struct JsonFeed {
    title: String,
    feed_url: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_url: Option<Url>,
    items: Vec<JsonFeedItem>,
}

#[derive(Debug, Serialize)]
struct JsonFeedItem {
    id: String,
    content_html: String,
    date_published: String,
    authors: (JsonFeedAuthor,),
    // I don't think there is a need to return other special fields like signatures here.
    // This API is for readers only which cannot recognize them anyway.
    // Our clients should already use the dedicate API (`/room/:rid/msg`).
}

#[derive(Debug, Serialize)]
struct JsonFeedAuthor {
    name: String,
}

pub fn to_json_feed(
    title: String,
    msgs: Vec<WithMsgId<SignedChatMsg>>,
    self_url: Url,
    next_url: Option<Url>,
) -> Response {
    let items = msgs
        .into_iter()
        .map(|WithMsgId { cid, msg }| {
            let time = SystemTime::UNIX_EPOCH + Duration::from_secs(msg.signee.timestamp);
            let author = JsonFeedAuthor {
                // TODO: Retrieve id_url as name.
                name: msg.signee.user.id_key.to_string(),
            };
            JsonFeedItem {
                id: cid.to_string(),
                content_html: msg.signee.payload.rich_text.html().to_string(),
                date_published: humantime::format_rfc3339(time).to_string(),
                authors: (author,),
            }
        })
        .collect::<Vec<_>>();

    let feed = JsonFeed {
        title,
        items,
        feed_url: self_url,
        next_url,
    };

    ([(header::CONTENT_TYPE, JSON_FEED_MIME)], Json(feed)).into_response()
}
