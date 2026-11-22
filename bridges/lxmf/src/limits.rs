//! How much the website may ask the bridge to send to addresses it names.
//!
//! The website checks an address before it uses it, but a leaked secret or a bug there must not make
//! the bridge send to the whole network. So, in any hour, each named address gets at most a few
//! messages, and only so many different addresses get any. What is remembered is bounded: an address
//! is forgotten an hour after its last message, and there are never more than `max_addresses` of them.

use std::collections::{HashMap, VecDeque};

use crate::config::Hash;

/// The length of the window the limits count in, in seconds.
pub const WINDOW_SECONDS: u64 = 3600;
/// The most refused addresses remembered, so that each is logged once an hour.
const MAX_LOGGED: usize = 1000;

/// Which limit was hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// This address has had its messages for the hour.
    Address,
    /// This is a new address, and the hour's different addresses are used up.
    Addresses,
}

/// Whether the refusal should be logged now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Log {
    /// This address was logged already within the hour.
    Quiet,
    /// The first refusal of this address within the hour.
    Line,
    /// Too many refused addresses to keep track of: say so once an hour instead.
    Overflow,
}

/// A refused request: for how long, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limited {
    pub scope: Scope,
    /// Seconds until a retry can succeed (at least 1).
    pub retry_after: u64,
    pub log: Log,
}

/// The messages sent to named addresses in the last hour.
#[derive(Debug)]
pub struct Limits {
    per_address: usize,
    max_addresses: usize,
    /// For each address, the times (unix seconds, oldest first) of its messages within the window.
    sent: HashMap<Hash, VecDeque<u64>>,
    /// Refused addresses, to the second they were logged at.
    logged: HashMap<Hash, u64>,
    overflow_logged: Option<u64>,
}

impl Limits {
    pub fn new(per_address: usize, max_addresses: usize) -> Self {
        Self { per_address, max_addresses, sent: HashMap::new(), logged: HashMap::new(), overflow_logged: None }
    }

    /// Whether a message to `to` may go at `now`. It does not count it: call [`Limits::record`] once
    /// the message is really taken, so a refusal for another reason costs nothing.
    pub fn check(&mut self, to: Hash, now: u64) -> Result<(), Limited> {
        self.forget_old(now);
        let in_an_hour = |time: u64| time.saturating_add(WINDOW_SECONDS).saturating_sub(now).max(1);
        match self.sent.get(&to) {
            Some(times) if times.len() >= self.per_address => {
                let retry_after = times.front().map_or(1, |oldest| in_an_hour(*oldest));
                Err(self.limited(Scope::Address, to, retry_after, now))
            }
            Some(_) => Ok(()),
            None if self.sent.len() >= self.max_addresses => {
                // Room comes back when the address whose last message is oldest is forgotten.
                let retry_after = self.sent.values().filter_map(|times| times.back()).map(|last| in_an_hour(*last)).min().unwrap_or(1);
                Err(self.limited(Scope::Addresses, to, retry_after, now))
            }
            None => Ok(()),
        }
    }

    /// Counts a message to `to` sent at `now`.
    pub fn record(&mut self, to: Hash, now: u64) {
        self.sent.entry(to).or_default().push_back(now);
    }

    /// How many addresses are remembered.
    pub fn len(&self) -> usize {
        self.sent.len() + self.logged.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sent.is_empty() && self.logged.is_empty()
    }

    fn forget_old(&mut self, now: u64) {
        let fresh = |time: &u64| time.saturating_add(WINDOW_SECONDS) > now;
        self.sent.retain(|_, times| {
            while times.front().is_some_and(|time| !fresh(time)) {
                times.pop_front();
            }
            !times.is_empty()
        });
        self.logged.retain(|_, time| fresh(time));
        if self.overflow_logged.is_some_and(|time| !fresh(&time)) {
            self.overflow_logged = None;
        }
    }

    fn limited(&mut self, scope: Scope, to: Hash, retry_after: u64, now: u64) -> Limited {
        let log = if self.logged.contains_key(&to) {
            Log::Quiet
        } else if self.logged.len() < MAX_LOGGED {
            self.logged.insert(to, now);
            Log::Line
        } else if self.overflow_logged.is_none() {
            self.overflow_logged = Some(now);
            Log::Overflow
        } else {
            Log::Quiet
        };
        Limited { scope, retry_after, log }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn address(n: u32) -> Hash {
        let mut hash = [0u8; 16];
        hash[..4].copy_from_slice(&n.to_le_bytes());
        hash
    }

    fn take(limits: &mut Limits, to: Hash, now: u64) -> Result<(), Limited> {
        limits.check(to, now)?;
        limits.record(to, now);
        Ok(())
    }

    #[test]
    fn an_address_gets_its_messages_and_then_waits_for_the_oldest_to_age_out() {
        let mut limits = Limits::new(3, 10);
        for i in 0..3 {
            assert_eq!(take(&mut limits, address(1), NOW + i * 10), Ok(()));
        }
        let refused = take(&mut limits, address(1), NOW + 100).unwrap_err();
        assert_eq!((refused.scope, refused.retry_after), (Scope::Address, WINDOW_SECONDS - 100));
        // Other addresses are not affected.
        assert_eq!(take(&mut limits, address(2), NOW + 100), Ok(()));
        // An hour after the oldest, one more is allowed.
        assert!(take(&mut limits, address(1), NOW + WINDOW_SECONDS - 1).is_err());
        assert_eq!(take(&mut limits, address(1), NOW + WINDOW_SECONDS), Ok(()));
    }

    #[test]
    fn only_so_many_different_addresses_are_served_an_hour() {
        let mut limits = Limits::new(5, 2);
        assert_eq!(take(&mut limits, address(1), NOW), Ok(()));
        assert_eq!(take(&mut limits, address(2), NOW + 30), Ok(()));
        let refused = take(&mut limits, address(3), NOW + 60).unwrap_err();
        // The first address to be forgotten is the one last written to earliest.
        assert_eq!((refused.scope, refused.retry_after), (Scope::Addresses, WINDOW_SECONDS - 60));
        // The addresses already served still get theirs.
        assert_eq!(take(&mut limits, address(1), NOW + 60), Ok(()));
        assert_eq!(take(&mut limits, address(3), NOW + WINDOW_SECONDS + 30), Ok(()));
    }

    #[test]
    fn a_refusal_is_logged_once_per_address_an_hour() {
        let mut limits = Limits::new(1, 1);
        assert_eq!(take(&mut limits, address(1), NOW), Ok(()));
        let logs: Vec<Log> = (1..=3).map(|i| take(&mut limits, address(1), NOW + i).unwrap_err().log).collect();
        assert_eq!(logs, [Log::Line, Log::Quiet, Log::Quiet]);
        // Another address is its own line.
        assert_eq!(take(&mut limits, address(2), NOW + 5).unwrap_err().log, Log::Line);
        // An hour on the address is let through and, later, refused and logged again.
        assert_eq!(take(&mut limits, address(1), NOW + WINDOW_SECONDS + 1), Ok(()));
        assert_eq!(take(&mut limits, address(1), NOW + WINDOW_SECONDS + 2).unwrap_err().log, Log::Line);
    }

    #[test]
    fn what_is_remembered_is_bounded() {
        let mut limits = Limits::new(1, 1);
        assert_eq!(take(&mut limits, address(0), NOW), Ok(()));
        let mut lines = 0;
        let mut overflows = 0;
        for i in 1..5000 {
            match take(&mut limits, address(i), NOW + 1).unwrap_err().log {
                Log::Line => lines += 1,
                Log::Overflow => overflows += 1,
                Log::Quiet => {}
            }
        }
        assert_eq!((lines, overflows), (MAX_LOGGED, 1));
        assert!(limits.len() <= 1 + MAX_LOGGED);
        // Everything is forgotten an hour later.
        assert_eq!(take(&mut limits, address(1), NOW + WINDOW_SECONDS + 2), Ok(()));
        assert_eq!(limits.len(), 1);
        assert!(!limits.is_empty());
    }

    #[test]
    fn a_check_that_is_not_recorded_costs_nothing() {
        let mut limits = Limits::new(1, 1);
        assert_eq!(limits.check(address(1), NOW), Ok(()));
        assert_eq!(limits.check(address(1), NOW), Ok(()));
        assert!(limits.is_empty());
    }
}
