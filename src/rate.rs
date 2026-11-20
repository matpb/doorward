//! The request limiter: one GCRA bucket per class and key, and the open MCP requests per user.
//! Pure logic with no HTTP types. Times are nanoseconds since the Unix epoch.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::config::Limits;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const NANOS_PER_MINUTE: u64 = 60 * NANOS_PER_SECOND;
const CLASSES: usize = 4;

/// The classes of bucket. Each has its own burst and rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    General,
    Oauth,
    Credentials,
    Mcp,
}

/// Who is counted. Addresses are typed, never strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    V4(u32),
    V6(u64),
    User(i64),
}

impl Key {
    /// IPv4: the whole address. IPv6: its first 64 bits. An IPv4-mapped address is IPv4.
    pub fn address(ip: IpAddr) -> Key {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Key::V4(u32::from(v4)),
            IpAddr::V6(v6) => Key::V6((u128::from(v6) >> 64) as u64),
        }
    }
}

/// The burst and rate of one class, as the GCRA spacing and tolerance.
#[derive(Clone, Copy, Debug)]
struct Rule {
    period: u64,
    tau: u64,
}

impl Rule {
    fn new(burst: u64, per_minute: u64) -> Rule {
        let period = (NANOS_PER_MINUTE / per_minute.max(1)).max(1);
        Rule {
            period,
            tau: period.saturating_mul(burst.saturating_sub(1)),
        }
    }
}

#[derive(Default)]
struct State {
    table: HashMap<(Class, Key), u64>,
    ipv6: usize,
    overflow: [u64; CLASSES],
    swept_at: Option<u64>,
    open: HashMap<i64, u64>,
}

/// The limits in use: one table of buckets and the open MCP requests of each user.
pub struct Limiter {
    rules: [Rule; CLASSES],
    table_keys: usize,
    mcp_open: u64,
    state: Mutex<State>,
}

impl Limiter {
    pub fn new(limits: &Limits) -> Limiter {
        Limiter {
            rules: [
                Rule::new(limits.general_burst, limits.general_per_minute),
                Rule::new(limits.oauth_burst, limits.oauth_per_minute),
                Rule::new(limits.credentials_burst, limits.credentials_per_minute),
                Rule::new(limits.mcp_burst, limits.mcp_per_minute),
            ],
            table_keys: usize::try_from(limits.rate_table_keys).unwrap_or(usize::MAX),
            mcp_open: limits.mcp_open,
            state: Mutex::new(State::default()),
        }
    }

    /// Takes one request from the bucket. `Err` gives the seconds to wait, at least 1.
    pub fn take(&self, class: Class, key: Key, now: u64) -> Result<(), u64> {
        let rule = self.rules[class as usize];
        let slot = (class, key);
        let mut state = self.lock();
        if !state.table.contains_key(&slot) && self.is_full(&state, key) {
            sweep_on_insert(&mut state, now);
            if self.is_full(&state, key) {
                let next = judge(rule, state.overflow[class as usize], now)?;
                state.overflow[class as usize] = next;
                return Ok(());
            }
        }
        let stored = state.table.get(&slot).copied().unwrap_or(0);
        let next = judge(rule, stored, now)?;
        if state.table.insert(slot, next).is_none() && matches!(key, Key::V6(_)) {
            state.ipv6 += 1;
        }
        Ok(())
    }

    /// Gives back the last `take` of this bucket.
    pub fn refund(&self, class: Class, key: Key, now: u64) {
        let rule = self.rules[class as usize];
        let slot = (class, key);
        let mut state = self.lock();
        match state.table.get(&slot).copied() {
            Some(stored) => {
                let next = refunded(rule, stored, now);
                if next <= now {
                    state.table.remove(&slot);
                    if matches!(key, Key::V6(_)) {
                        state.ipv6 = state.ipv6.saturating_sub(1);
                    }
                } else {
                    state.table.insert(slot, next);
                }
            }
            None => {
                let stored = state.overflow[class as usize];
                state.overflow[class as usize] = refunded(rule, stored, now);
            }
        }
    }

    /// Drops every entry whose time has passed.
    pub fn sweep(&self, now: u64) {
        let mut state = self.lock();
        sweep_table(&mut state, now);
    }

    pub fn len(&self) -> usize {
        self.lock().table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// One more request of `user` in flight; None when `mcp_open` are already open.
    pub fn open(self: &Arc<Self>, user: i64) -> Option<Open> {
        let mut state = self.lock();
        let count = state.open.entry(user).or_insert(0);
        if *count >= self.mcp_open {
            return None;
        }
        *count += 1;
        Some(Open {
            limiter: Arc::clone(self),
            user,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// True when a new key of `key`'s kind has no room: the table, or the IPv6 half of it.
    fn is_full(&self, state: &State, key: Key) -> bool {
        state.table.len() >= self.table_keys
            || (matches!(key, Key::V6(_)) && state.ipv6 >= self.table_keys / 2)
    }
}

/// One in-flight MCP request; dropping it frees the slot.
pub struct Open {
    limiter: Arc<Limiter>,
    user: i64,
}

impl Drop for Open {
    fn drop(&mut self) {
        let mut state = self.limiter.lock();
        let remaining = state.open.get_mut(&self.user).map(|count| {
            *count = count.saturating_sub(1);
            *count
        });
        if remaining == Some(0) {
            state.open.remove(&self.user);
        }
    }
}

/// The GCRA step: the new arrival time, or the seconds to wait.
fn judge(rule: Rule, stored: u64, now: u64) -> Result<u64, u64> {
    let tat = stored.max(now);
    let ahead = tat.saturating_sub(now);
    if ahead > rule.tau {
        Err(retry_seconds(ahead.saturating_sub(rule.tau)))
    } else {
        Ok(tat.saturating_add(rule.period))
    }
}

/// The arrival time after one request is given back, never before `now`.
fn refunded(rule: Rule, stored: u64, now: u64) -> u64 {
    stored.saturating_sub(rule.period).max(now)
}

/// Sweeps before an insert into a full table, at most once per second of `now`.
fn sweep_on_insert(state: &mut State, now: u64) {
    let due = state
        .swept_at
        .is_none_or(|last| now.saturating_sub(last) >= NANOS_PER_SECOND);
    if due {
        sweep_table(state, now);
    }
}

/// Removes the entries whose arrival time has passed: they count as absent.
fn sweep_table(state: &mut State, now: u64) {
    state.table.retain(|_, stored| *stored > now);
    state.ipv6 = state
        .table
        .keys()
        .filter(|(_, key)| matches!(key, Key::V6(_)))
        .count();
    state.swept_at = Some(now);
}

/// The seconds a wait of `wait` nanoseconds rounds up to, at least 1.
pub fn retry_seconds(wait: u64) -> u64 {
    wait.div_ceil(NANOS_PER_SECOND).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: Class = Class::General;
    const T: u64 = NANOS_PER_SECOND;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    fn build(edit: impl FnOnce(&mut Limits)) -> Limiter {
        let mut limits = Limits::default();
        edit(&mut limits);
        Limiter::new(&limits)
    }

    /// Every class with the same burst and rate per minute.
    fn same(burst: u64, per_minute: u64) -> Limiter {
        build(|l| {
            l.general_burst = burst;
            l.general_per_minute = per_minute;
            l.oauth_burst = burst;
            l.oauth_per_minute = per_minute;
            l.credentials_burst = burst;
            l.credentials_per_minute = per_minute;
            l.mcp_burst = burst;
            l.mcp_per_minute = per_minute;
        })
    }

    #[test]
    fn a_burst_is_allowed_then_limited() {
        let limiter = same(2, 60);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Err(1));
    }

    #[test]
    fn a_burst_of_one_limits_the_second_request() {
        let limiter = same(1, 60);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Err(1));
    }

    #[test]
    fn the_bucket_refills_exactly_one_period_later() {
        let limiter = same(1, 60);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), T - 1), Err(1));
        assert_eq!(limiter.take(G, Key::V4(1), T), Ok(()));
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        assert_eq!(retry_seconds(1), 1);
        assert_eq!(retry_seconds(T), 1);
        assert_eq!(retry_seconds(T + 1), 2);
        assert_eq!(retry_seconds(0), 1);
        let limiter = same(1, 60);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), T - 1), Err(1), "a wait of 1 ns");
        assert_eq!(
            limiter.take(G, Key::V4(1), 0),
            Err(1),
            "a wait of exactly 1 s"
        );
    }

    #[test]
    fn a_refund_gives_back_exactly_one() {
        let limiter = same(2, 60);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Err(1));
        limiter.refund(G, Key::V4(1), 0);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Err(1));
    }

    #[test]
    fn a_refund_never_goes_below_now() {
        let limiter = same(2, 60);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        limiter.refund(G, Key::V4(1), 10 * T);
        assert_eq!(limiter.take(G, Key::V4(1), 10 * T), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 10 * T), Ok(()));
        assert_eq!(
            limiter.take(G, Key::V4(1), 10 * T),
            Err(1),
            "a refund after a long wait gives no more than the burst"
        );
    }

    #[test]
    fn a_refund_of_an_overflow_request_goes_to_the_overflow_bucket() {
        let limiter = build(|l| {
            l.rate_table_keys = 1;
            l.general_burst = 1;
            l.general_per_minute = 60;
        });
        assert_eq!(
            limiter.take(G, Key::V4(1), 0),
            Ok(()),
            "key 1 takes the only place"
        );
        assert_eq!(
            limiter.take(G, Key::V4(2), 0),
            Ok(()),
            "key 2 takes the overflow bucket"
        );
        assert_eq!(
            limiter.take(G, Key::V4(3), 0),
            Err(1),
            "key 3 shares the overflow bucket"
        );
        limiter.refund(G, Key::V4(2), 0);
        assert_eq!(
            limiter.take(G, Key::V4(3), 0),
            Ok(()),
            "the refund gave the overflow request back"
        );
    }

    #[test]
    fn a_refund_that_empties_an_ipv6_entry_frees_its_place() {
        let limiter = build(|l| {
            l.rate_table_keys = 4;
            l.general_burst = 1;
            l.general_per_minute = 60;
        });
        let first = Key::address(ip("2001:db8:1::1"));
        let second = Key::address(ip("2001:db8:2::1"));
        let third = Key::address(ip("2001:db8:3::1"));
        let fourth = Key::address(ip("2001:db8:4::1"));
        let fifth = Key::address(ip("2001:db8:5::1"));
        assert_eq!(limiter.take(G, first, 0), Ok(()));
        assert_eq!(limiter.take(G, second, 0), Ok(()));
        // Sets the sweep time, so the full insert below does not sweep the table.
        limiter.sweep(0);
        limiter.refund(G, first, 0);
        assert_eq!(limiter.len(), 1);
        assert_eq!(limiter.take(G, third, 0), Ok(()));
        assert_eq!(
            limiter.len(),
            2,
            "the refund freed the IPv6 place for the third key"
        );
        assert_eq!(
            limiter.take(G, fourth, 0),
            Ok(()),
            "the IPv6 half is full again, so the fourth key uses the overflow bucket"
        );
        assert_eq!(
            limiter.take(G, fifth, 0),
            Err(1),
            "the overflow bucket is spent"
        );
    }

    #[test]
    fn classes_are_independent() {
        let limiter = same(1, 60);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Err(1));
        assert_eq!(limiter.take(Class::Oauth, Key::V4(1), 0), Ok(()));
    }

    #[test]
    fn keys_are_independent() {
        let limiter = same(1, 60);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Err(1));
        assert_eq!(limiter.take(G, Key::V4(2), 0), Ok(()));
    }

    #[test]
    fn an_ipv6_64_is_one_key_and_a_mapped_address_is_ipv4() {
        let a = Key::address(ip("2001:db8:1::1"));
        assert_eq!(a, Key::address(ip("2001:db8:1::2")));
        assert_ne!(a, Key::address(ip("2001:db8:2::1")));
        assert_eq!(
            Key::address(ip("::ffff:203.0.113.5")),
            Key::address(ip("203.0.113.5"))
        );
        assert_ne!(
            Key::address(ip("203.0.113.5")),
            Key::address(ip("203.0.113.6"))
        );
    }

    #[test]
    fn a_backward_clock_never_unlimits_early_and_never_panics() {
        let limiter = same(1, 60);
        assert_eq!(limiter.take(G, Key::V4(1), 10 * T), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 5 * T), Err(6));
        assert_eq!(limiter.take(G, Key::V4(1), 11 * T), Ok(()));
    }

    #[test]
    fn a_huge_rate_does_not_divide_by_zero() {
        let limiter = same(1, u64::MAX);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Err(1));
        assert_eq!(limiter.take(G, Key::V4(1), 1), Ok(()));
    }

    #[test]
    fn a_full_table_judges_new_keys_against_the_class_overflow_bucket() {
        let limiter = build(|l| {
            l.rate_table_keys = 2;
            l.general_burst = 1;
            l.general_per_minute = 60;
        });
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(2), 0), Ok(()));
        assert_eq!(limiter.len(), 2);
        assert_eq!(
            limiter.take(G, Key::V4(3), 0),
            Ok(()),
            "the overflow bucket"
        );
        assert_eq!(
            limiter.take(G, Key::V4(4), 0),
            Err(1),
            "shared by newcomers"
        );
        assert_eq!(limiter.len(), 2);
        assert_eq!(
            limiter.take(G, Key::V4(1), 0),
            Err(1),
            "a live entry is never evicted"
        );
    }

    #[test]
    fn the_ipv6_half_of_the_table_is_a_limit_of_its_own() {
        let limiter = build(|l| {
            l.rate_table_keys = 4;
            l.general_burst = 1;
            l.general_per_minute = 60;
        });
        let first = Key::address(ip("2001:db8:1::1"));
        let second = Key::address(ip("2001:db8:2::1"));
        let third = Key::address(ip("2001:db8:3::1"));
        assert_eq!(limiter.take(G, first, 0), Ok(()));
        assert_eq!(limiter.take(G, second, 0), Ok(()));
        assert_eq!(limiter.len(), 2);
        assert_eq!(limiter.take(G, third, 0), Ok(()));
        assert_eq!(limiter.len(), 2, "the IPv6 half is full at two keys");
        assert_eq!(limiter.take(G, Key::V4(9), 0), Ok(()));
        assert_eq!(limiter.len(), 3, "the table still has room for IPv4");
    }

    #[test]
    fn a_sweep_makes_room_and_never_drops_a_live_entry() {
        let limiter = build(|l| {
            l.rate_table_keys = 10;
            l.general_burst = 1;
            l.general_per_minute = 60;
        });
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Err(1));
        limiter.sweep(0);
        assert_eq!(
            limiter.take(G, Key::V4(1), 0),
            Err(1),
            "a sweep keeps a limited key limited"
        );
        limiter.sweep(T);
        assert_eq!(limiter.len(), 0);
        assert_eq!(
            limiter.take(G, Key::V4(1), T),
            Ok(()),
            "a swept key is fresh"
        );

        let full = build(|l| {
            l.rate_table_keys = 2;
            l.general_burst = 1;
            l.general_per_minute = 60;
        });
        assert_eq!(full.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(full.take(G, Key::V4(2), 0), Ok(()));
        assert_eq!(full.take(G, Key::V4(3), 2 * T), Ok(()));
        assert_eq!(full.len(), 1, "the full insert swept the expired entries");
    }

    #[test]
    fn the_sweep_on_a_full_insert_runs_at_most_once_a_second() {
        let limiter = build(|l| {
            l.rate_table_keys = 1;
            l.general_burst = 1;
            l.general_per_minute = 6_000_000;
        });
        assert_eq!(limiter.take(G, Key::V4(1), T), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(2), T), Ok(()), "overflow");
        assert_eq!(limiter.take(G, Key::V4(3), T + 20_000), Ok(()), "overflow");
        assert_eq!(
            limiter.take(G, Key::V4(4), T + 20_000),
            Err(1),
            "no second sweep within a second, so the overflow bucket is still shared"
        );
        assert_eq!(limiter.take(G, Key::V4(5), T + 1_000_000_001), Ok(()));
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn open_requests_are_capped_per_user_and_freed_on_drop() {
        let limiter = Arc::new(build(|l| l.mcp_open = 2));
        let first = limiter.open(1).expect("first open request");
        let second = limiter.open(1);
        assert!(second.is_some(), "second open request");
        assert!(limiter.open(1).is_none(), "third is over the cap");
        let other = limiter.open(2);
        assert!(other.is_some(), "another user is unaffected");
        drop(first);
        assert!(limiter.open(1).is_some(), "dropping one frees its slot");
    }

    #[test]
    fn len_counts_the_keys_in_the_table() {
        let limiter = same(1, 60);
        assert_eq!(limiter.len(), 0);
        assert_eq!(limiter.take(G, Key::V4(1), 0), Ok(()));
        assert_eq!(limiter.take(G, Key::V4(1), 0), Err(1));
        assert_eq!(limiter.take(G, Key::V4(2), 0), Ok(()));
        assert_eq!(limiter.len(), 2);
    }
}
