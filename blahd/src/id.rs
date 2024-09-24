/// Id generation.
/// Ref: https://en.wikipedia.org/wiki/Snowflake_ID
/// FIXME: Currently we assume no more than one request in a single millisecond.
use std::time::SystemTime;

use blah_types::Id;

pub fn timestamp_of_id(id: Id) -> u64 {
    (id.0 as u64 >> 16) / 1000
}

pub trait IdExt {
    fn gen() -> Self;
    fn gen_peer_chat_rid() -> Self;

    fn is_peer_chat(&self) -> bool;
}

impl IdExt for Id {
    fn gen() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after UNIX epoch");
        let timestamp_ms = timestamp.as_millis();
        assert!(
            0 < timestamp_ms && timestamp_ms < (1 << 48),
            "invalid timestamp",
        );
        Id((timestamp_ms as i64) << 16)
    }

    fn gen_peer_chat_rid() -> Self {
        Id(Self::gen().0 | i64::MIN)
    }

    fn is_peer_chat(&self) -> bool {
        self.0 < 0
    }
}
