use std::cell::Cell;

/// Id generation.
/// Ref: https://en.wikipedia.org/wiki/Snowflake_ID
/// FIXME: Handle multi-threaded runtime.
use blah_types::Id;

use crate::utils::SystemTime;

pub fn timestamp_of_id(id: Id) -> u64 {
    (id.0 as u64 >> 16) / 1000
}

pub trait IdExt {
    fn gen_new() -> Self;
    fn gen_new_peer_chat_rid() -> Self;

    fn is_peer_chat(&self) -> bool;
}

thread_local! {
    static LAST_ID: Cell<i64> = const { Cell::new(0) };
}

impl IdExt for Id {
    fn gen_new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after UNIX epoch");
        let timestamp_ms = timestamp.as_millis();
        assert!(timestamp_ms < (1 << 48), "invalid timestamp");
        let timestamp_ms = timestamp_ms as i64;
        let id = timestamp_ms << 16;
        LAST_ID.with(|last_id| {
            let prev = last_id.get();
            if prev >> 16 != timestamp_ms {
                // If not in the same millisecond, use the new timestamp as id.
                last_id.set(id);
                Id(id)
            } else {
                // Otherwise, try to increase the trailing counter.
                assert!(prev < (1 << 16), "id counter overflow");
                last_id.set(prev + 1);
                Id(prev + 1)
            }
        })
    }

    fn gen_new_peer_chat_rid() -> Self {
        Id(Self::gen_new().0 | i64::MIN)
    }

    fn is_peer_chat(&self) -> bool {
        self.0 < 0
    }
}
