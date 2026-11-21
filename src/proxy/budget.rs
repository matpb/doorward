//! The process-wide budget of upstream bytes held in memory: one permit per 4096 bytes, and a share of
//! it that one signed-in user may hold at once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Bytes covered by one permit.
const UNIT: usize = 4096;

/// The bytes of upstream answers that may be held at once, over all requests, and the share of one user.
#[derive(Clone)]
pub struct Budget {
    semaphore: Arc<Semaphore>,
    /// The permits one user may hold at once.
    share: usize,
    /// The permits each signed-in user holds; an entry exists only while its user holds some.
    users: Arc<Mutex<HashMap<i64, usize>>>,
}

impl Budget {
    /// A budget of `bytes`, of which one user may hold `share`; both are rounded up to whole permits.
    pub fn new(bytes: u64, share: u64) -> Self {
        Budget {
            semaphore: Arc::new(Semaphore::new(permits_of(bytes))),
            share: permits_of(share),
            users: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// A reservation that holds nothing yet, for `user`'s work; None for the gateway's own work, which only
    /// the budget bounds.
    pub fn reservation(&self, user: Option<i64>) -> Reservation {
        Reservation {
            budget: self.clone(),
            user,
            permits: None,
        }
    }

    fn users(&self) -> MutexGuard<'_, HashMap<i64, usize>> {
        self.users.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The permits that cover `bytes`, at most the semaphore's maximum.
fn permits_of(bytes: u64) -> usize {
    usize::try_from(bytes.div_ceil(UNIT as u64))
        .unwrap_or(Semaphore::MAX_PERMITS)
        .min(Semaphore::MAX_PERMITS)
}

/// The permits one request holds for the bytes it has in memory; they return to the budget on drop.
pub struct Reservation {
    budget: Budget,
    user: Option<i64>,
    permits: Option<OwnedSemaphorePermit>,
}

impl Reservation {
    /// Makes the reservation cover exactly `bytes`, growing or shrinking. A growth must fit the user's share
    /// and the budget; False when either refuses it, and then nothing changes.
    pub fn set(&mut self, bytes: usize) -> bool {
        let wanted = bytes.div_ceil(UNIT);
        let held = self.held();
        if wanted > held {
            let growth = wanted - held;
            let Ok(count) = u32::try_from(growth) else {
                return false;
            };
            if !self.add_to_user(growth) {
                return false;
            }
            let Ok(more) = Arc::clone(&self.budget.semaphore).try_acquire_many_owned(count) else {
                self.take_from_user(growth);
                return false;
            };
            match self.permits.as_mut() {
                Some(permits) => permits.merge(more),
                None => self.permits = Some(more),
            }
        } else if wanted < held {
            if let Some(permits) = self.permits.as_mut() {
                // The split returns its permits to the budget when it is dropped here.
                drop(permits.split(held - wanted));
            }
            self.take_from_user(held - wanted);
        }
        true
    }

    fn held(&self) -> usize {
        self.permits
            .as_ref()
            .map_or(0, OwnedSemaphorePermit::num_permits)
    }

    /// Adds `permits` to the user's total when the total stays within the share.
    fn add_to_user(&self, permits: usize) -> bool {
        let Some(user) = self.user else {
            return true;
        };
        let mut users = self.budget.users();
        let total = users.get(&user).copied().unwrap_or(0);
        if total.saturating_add(permits) > self.budget.share {
            return false;
        }
        users.insert(user, total + permits);
        true
    }

    /// Takes `permits` off the user's total, and removes the user's entry when nothing is left.
    fn take_from_user(&self, permits: usize) {
        let Some(user) = self.user else {
            return;
        };
        let mut users = self.budget.users();
        let total = users
            .get(&user)
            .copied()
            .unwrap_or(0)
            .saturating_sub(permits);
        if total == 0 {
            users.remove(&user);
        } else {
            users.insert(user, total);
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let held = self.held();
        self.take_from_user(held);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A budget of `permits` permits, every one of them within one user's share.
    fn budget(permits: u64) -> Budget {
        Budget::new(permits * UNIT as u64, permits * UNIT as u64)
    }

    /// A budget of `permits` permits in which one user may hold `share` permits.
    fn budget_shared(permits: u64, share: u64) -> Budget {
        Budget::new(permits * UNIT as u64, share * UNIT as u64)
    }

    fn available(budget: &Budget) -> usize {
        budget.semaphore.available_permits()
    }

    fn users(budget: &Budget) -> HashMap<i64, usize> {
        budget.users.lock().expect("users").clone()
    }

    #[test]
    fn set_grows_and_shrinks() {
        let budget = budget(16);
        let mut held = budget.reservation(None);
        assert!(held.set(2 * UNIT));
        assert_eq!(available(&budget), 14);
        assert!(held.set(16 * UNIT));
        assert_eq!(available(&budget), 0);
        assert!(held.set(UNIT));
        assert_eq!(available(&budget), 15);
    }

    #[test]
    fn a_second_reservation_is_refused_while_the_first_holds_the_budget() {
        let budget = budget(4);
        let mut first = budget.reservation(None);
        assert!(first.set(4 * UNIT));
        let mut second = budget.reservation(None);
        assert!(
            !second.set(1),
            "the budget is held by the first reservation"
        );
        drop(first);
        assert!(second.set(1), "the first reservation released the budget");
        assert_eq!(available(&budget), 3);
    }

    #[test]
    fn set_zero_releases_everything() {
        let budget = budget(16);
        let mut held = budget.reservation(None);
        assert!(held.set(8 * UNIT));
        assert_eq!(available(&budget), 8);
        assert!(held.set(0));
        assert_eq!(available(&budget), 16);
    }

    #[test]
    fn one_byte_takes_one_permit() {
        let budget = budget(16);
        let mut held = budget.reservation(None);
        assert!(held.set(1));
        assert_eq!(available(&budget), 15);
        assert!(held.set(UNIT), "one whole permit covers 4096 bytes");
        assert_eq!(available(&budget), 15);
        assert!(held.set(UNIT + 1));
        assert_eq!(available(&budget), 14);
    }

    #[test]
    fn a_budget_rounds_up_to_whole_permits() {
        assert_eq!(available(&Budget::new(4 * UNIT as u64 + 1, UNIT as u64)), 5);
        assert_eq!(available(&Budget::new(0, 0)), 0);
    }

    #[test]
    fn a_refused_set_leaves_the_reservation_unchanged() {
        let budget = budget(4);
        let mut held = budget.reservation(None);
        assert!(held.set(2 * UNIT));
        let mut other = budget.reservation(None);
        assert!(other.set(2 * UNIT));
        assert_eq!(available(&budget), 0);
        assert!(!held.set(3 * UNIT));
        assert_eq!(available(&budget), 0, "a refused growth takes nothing");
        drop(other);
        assert!(held.set(2 * UNIT));
        assert_eq!(
            available(&budget),
            2,
            "the reservation still holds two permits"
        );
    }

    #[test]
    fn a_user_at_its_share_is_refused_while_another_user_and_the_gateway_still_grow() {
        let budget = budget_shared(16, 4);
        let mut first = budget.reservation(Some(1));
        assert!(first.set(4 * UNIT));
        let mut again = budget.reservation(Some(1));
        assert!(!again.set(UNIT), "user 1 is at its share of four permits");
        let mut second = budget.reservation(Some(2));
        assert!(second.set(UNIT), "user 2 has a share of its own");
        let mut gateway = budget.reservation(None);
        assert!(
            gateway.set(UNIT),
            "the gateway's own work is bound by the global budget only"
        );
        assert_eq!(available(&budget), 10);
        assert_eq!(users(&budget), HashMap::from([(1, 4), (2, 1)]));
    }

    #[test]
    fn dropping_a_users_last_reservation_removes_the_user_and_lets_it_grow_again() {
        let budget = budget_shared(16, 4);
        let mut first = budget.reservation(Some(1));
        assert!(first.set(4 * UNIT));
        drop(first);
        assert!(users(&budget).is_empty(), "the entry goes at zero");
        let mut next = budget.reservation(Some(1));
        assert!(next.set(4 * UNIT), "user 1 may grow again");
    }

    #[test]
    fn a_refused_set_leaves_the_user_total_and_the_global_count_unchanged() {
        let budget = budget_shared(16, 3);
        let mut held = budget.reservation(Some(1));
        assert!(held.set(2 * UNIT));
        let mut over_share = budget.reservation(Some(1));
        assert!(!over_share.set(2 * UNIT), "two more would pass the share");
        assert_eq!(users(&budget), HashMap::from([(1, 2)]));
        assert_eq!(available(&budget), 14);

        let budget = budget_shared(4, 8);
        let mut first = budget.reservation(Some(1));
        assert!(first.set(3 * UNIT));
        let mut second = budget.reservation(Some(2));
        assert!(
            !second.set(2 * UNIT),
            "only one permit is left in the budget"
        );
        assert_eq!(users(&budget), HashMap::from([(1, 3)]));
        assert_eq!(available(&budget), 1);
    }

    #[test]
    fn shrinking_lowers_the_user_total() {
        let budget = budget_shared(16, 8);
        let mut held = budget.reservation(Some(1));
        assert!(held.set(4 * UNIT));
        assert!(held.set(UNIT));
        assert_eq!(users(&budget), HashMap::from([(1, 1)]));
        assert!(held.set(0));
        assert!(users(&budget).is_empty());
    }
}
