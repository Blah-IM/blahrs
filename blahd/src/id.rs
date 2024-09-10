/// Id generation.
/// Ref: https://en.wikipedia.org/wiki/Snowflake_ID
/// FIXME: Currently we assume no more than one request in a single millisecond.
use std::time::SystemTime;

use blah_types::Id;

pub trait IdExt {
    fn gen() -> Self;
}

impl IdExt for Id {
    fn gen() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after UNIX epoch");
        let timestamp_ms = timestamp.as_millis() as i64;
        assert!(timestamp_ms > 0);
        Id(timestamp_ms << 16)
    }
}
