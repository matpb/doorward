use time::OffsetDateTime;

/// Source of the current time, replaceable in tests.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> OffsetDateTime;
}

/// Reads the UTC system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
