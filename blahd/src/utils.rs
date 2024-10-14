use std::collections::{HashSet, VecDeque};
use std::hash::Hash;
use std::time::Duration;

#[cfg(not(feature = "unsafe_use_mock_instant_for_testing"))]
pub use std::time::{Instant, SystemTime};

#[cfg(feature = "unsafe_use_mock_instant_for_testing")]
pub use mock_instant::thread_local::{Instant, SystemTime};

#[cfg(all(feature = "unsafe_use_mock_instant_for_testing", not(debug_assertions)))]
compile_error!(
    "`unsafe_use_mock_instant_for_testing` feature must not be enabled in release build",
);

#[derive(Debug)]
pub struct ExpiringSet<T> {
    set: HashSet<T>,
    expire_queue: VecDeque<(Instant, T)>,
    expire_delay: Duration,
}

impl<T: Hash + Eq + Clone + Copy> ExpiringSet<T> {
    pub fn new(expire_delay: Duration) -> Self {
        Self {
            set: HashSet::new(),
            expire_queue: VecDeque::new(),
            expire_delay,
        }
    }

    fn maintain(&mut self, now: Instant) {
        while let Some((_, x)) = self
            .expire_queue
            .front()
            .filter(|(deadline, _)| *deadline < now)
        {
            self.set.remove(x);
            self.expire_queue.pop_front();
        }

        // TODO: Reclaim space after instant heavy load.
    }

    pub fn try_insert(&mut self, v: T) -> bool {
        let now = Instant::now();
        self.maintain(now);
        if self.set.insert(v) {
            self.expire_queue.push_back((now + self.expire_delay, v));
            true
        } else {
            false
        }
    }
}
