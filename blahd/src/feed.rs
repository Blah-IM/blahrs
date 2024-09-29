//! Room feed generation.
use std::fmt;
use std::num::NonZero;
use std::time::Duration;

use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use blah_types::msg::{SignedChatMsgWithId, WithMsgId};
use blah_types::Id;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::id::timestamp_of_id;

const JSON_FEED_MIME: &str = "application/feed+json";
const ATOM_FEED_MIME: &str = "application/atom+xml";

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

pub struct FeedData {
    pub rid: Id,
    pub title: String,
    pub msgs: Vec<SignedChatMsgWithId>,
    pub self_url: Url,
    pub next_url: Option<Url>,
}

pub trait FeedType {
    fn to_feed_response(data: FeedData) -> Response;
}

fn timestamp_to_rfc3339(timestamp: u64) -> impl fmt::Display {
    // This only for formatting, thus always use the non-mock `SystemTime`.
    humantime::format_rfc3339(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp))
}

/// See:
/// - <https://taguri.org/>
/// - <https://www.rfc-editor.org/rfc/rfc4151>
/// - <https://en.wikipedia.org/wiki/Tag_URI_scheme>
#[derive(Clone, Copy)]
struct TagUri<'a>(&'a Url, &'a str, Id);

impl fmt::Display for TagUri<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(url, typ, id) = *self;
        let domain = url.domain().expect("base_url must have domain");
        let id_time = timestamp_to_rfc3339(timestamp_of_id(id)).to_string();
        // Because github.com also only uses year.
        let id_year = &id_time[..4];
        write!(f, "tag:{domain},{id_year}:blah/{typ}/{id}")
    }
}

/// Ref: <https://www.jsonfeed.org/version/1.1/>
#[derive(Debug, Serialize)]
#[serde(tag = "version", rename = "https://jsonfeed.org/version/1.1")]
pub struct JsonFeed {
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

impl FeedType for JsonFeed {
    fn to_feed_response(data: FeedData) -> Response {
        let FeedData {
            title,
            msgs,
            self_url,
            next_url,
            ..
        } = data;
        let items = msgs
            .into_iter()
            .map(|WithMsgId { cid, msg }| {
                let author = JsonFeedAuthor {
                    // TODO: Retrieve id_url as name.
                    name: msg.signee.user.id_key.to_string(),
                };
                JsonFeedItem {
                    id: TagUri(&self_url, "msg", cid).to_string(),
                    content_html: msg.signee.payload.rich_text.html().to_string(),
                    date_published: timestamp_to_rfc3339(msg.signee.timestamp).to_string(),
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
}

pub struct AtomFeed(FeedData);

// We write XML manually here, because existing crates (`feed-rs` and `atom_syndication`)
// pull in heavy `quick_xml` and `chrono` which overdoes too much.
//
// Ref: <https://validator.w3.org/feed/docs/atom.html>
impl fmt::Display for AtomFeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use html_escape::{encode_quoted_attribute, encode_text};

        let FeedData {
            rid,
            title,
            msgs,
            self_url,
            next_url,
        } = &self.0;

        let room_id = TagUri(self_url, "room", *rid);
        let esc_room_title = encode_text(title.trim());
        // TODO: This should track the latest msg even for non-first page.
        let feed_timestamp =
            timestamp_to_rfc3339(msgs.first().map_or(0, |msg| msg.msg.signee.timestamp));
        let esc_self_url = encode_quoted_attribute(self_url.as_str());

        write!(
            f,
            // NB. XML requires no-newline at start.
            r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>{room_id}</id>
  <title>{esc_room_title}</title>
  <updated>{feed_timestamp}</updated>
  <link rel="self" type="application/atom+xml" href="{esc_self_url}"/>
"#
        )?;
        if let Some(next_url) = &next_url {
            let esc_next_url = encode_quoted_attribute(next_url.as_str());
            // <https://www.rfc-editor.org/rfc/rfc5005>
            writeln!(
                f,
                r#"  <link rel="next" type="application/atom+xml" href="{esc_next_url}"/>"#
            )?;
        }
        // TODO: HTML links.

        for msg in msgs {
            let content = &msg.msg.signee.payload.rich_text;
            let msg_id = TagUri(self_url, "msg", msg.cid);
            let plain_text = content.plain_text().to_string();
            let esc_msg_title =
                encode_text(plain_text.lines().next().unwrap_or("(untitled)").trim());
            let msg_timestamp = timestamp_to_rfc3339(msg.msg.signee.timestamp);
            let author = msg.msg.signee.user.id_key.to_string();
            let content = content.html().to_string();
            let esc_content = encode_text(&content);
            write!(
                f,
                r#"
  <entry>
    <id>{msg_id}</id>
    <title type="text">{esc_msg_title}</title>
    <published>{msg_timestamp}</published>
    <updated>{msg_timestamp}</updated>
    <author><name>{author}</name></author>
    <content type="html">{esc_content}</content>
  </entry>
"#
            )?;
        }

        write!(
            f,
            r#"
</feed>
"#
        )
    }
}

impl FeedType for AtomFeed {
    fn to_feed_response(data: FeedData) -> Response {
        let body = AtomFeed(data).to_string();
        ([(header::CONTENT_TYPE, ATOM_FEED_MIME)], body).into_response()
    }
}
