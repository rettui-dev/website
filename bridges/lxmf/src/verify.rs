//! Who sent a request, and when: the signature and the time the website puts on every alert.
//!
//! The website signs `<timestamp>.<body>` with HMAC-SHA256 and sends the time in `X-Rettui-Timestamp`
//! (unix seconds) and the result in `X-Rettui-Signature: sha256=<hex>`. Both are checked before the
//! body is looked at as anything but bytes.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// How far in the future a timestamp may be: clocks differ a little.
pub const MAX_FUTURE_SECONDS: u64 = 60;
/// The most signatures remembered for the replay check.
const MAX_REMEMBERED: usize = 10_000;

/// Why a request is not let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// A header is missing, or not what it should look like.
    Malformed,
    Stale,
    Future,
    BadSignature,
    /// The same signed request came before.
    Replay,
    /// Too many requests remembered to take another.
    Busy,
}

/// The timestamp header as a number of seconds, if it is a plain number of up to 12 digits.
fn parse_timestamp(header: &str) -> Option<u64> {
    if header.is_empty() || header.len() > 12 || !header.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    header.parse().ok()
}

/// Checks the timestamp against `now`: no older than `max_age` seconds, no more than
/// [`MAX_FUTURE_SECONDS`] ahead.
pub fn check_timestamp(header: &str, now: u64, max_age: u64) -> Result<u64, Reject> {
    let timestamp = parse_timestamp(header).ok_or(Reject::Malformed)?;
    if timestamp > now.saturating_add(MAX_FUTURE_SECONDS) {
        Err(Reject::Future)
    } else if now.saturating_sub(timestamp) > max_age {
        Err(Reject::Stale)
    } else {
        Ok(timestamp)
    }
}

/// The bytes of a signature header, which must be `sha256=` and 64 hex digits. This needs no
/// secret, so it can be checked before the body is waited for.
pub fn parse_signature(header: &str) -> Result<[u8; 32], Reject> {
    let wanted = header.strip_prefix("sha256=").ok_or(Reject::Malformed)?;
    hex::decode(wanted).ok().and_then(|bytes| bytes.try_into().ok()).ok_or(Reject::Malformed)
}

/// Checks the signature of `<timestamp header>.<body>` in constant time. Returns the signature's
/// bytes, for the replay check.
pub fn check_signature(secret: &[u8], timestamp: &str, body: &[u8], header: &str) -> Result<[u8; 32], Reject> {
    let given = parse_signature(header)?;
    // `verify_slice` compares in constant time.
    mac_of(secret, timestamp, body).verify_slice(&given).map_err(|_| Reject::BadSignature)?;
    Ok(given)
}

/// Signed requests seen lately, so a captured one cannot be sent again while its time still holds.
#[derive(Debug, Default)]
pub struct Replay {
    /// (timestamp, signature) to the second after which the timestamp is stale anyway.
    seen: HashMap<(u64, [u8; 32]), u64>,
}

impl Replay {
    /// Remembers a verified request, unless it was seen before.
    pub fn insert(&mut self, timestamp: u64, signature: [u8; 32], now: u64, max_age: u64) -> Result<(), Reject> {
        self.seen.retain(|_, expires| *expires >= now);
        if self.seen.contains_key(&(timestamp, signature)) {
            return Err(Reject::Replay);
        }
        if self.seen.len() >= MAX_REMEMBERED {
            return Err(Reject::Busy);
        }
        self.seen.insert((timestamp, signature), timestamp.saturating_add(max_age));
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

fn mac_of(secret: &[u8], timestamp: &str, body: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes a key of any length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac
}

/// The signature header for a body, as the website makes it.
pub fn sign(secret: &[u8], timestamp: &str, body: &[u8]) -> String {
    format!("sha256={}", hex::encode(mac_of(secret, timestamp, body).finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdefghij";
    const BODY: &[u8] = br#"{"event":"down","message":"Front is down."}"#;

    #[test]
    fn a_signature_made_by_the_website_is_accepted() {
        // From Node: crypto.createHmac('sha256', secret).update('1700000000.' + body).digest('hex').
        let header = "sha256=5efa4a1e48c1a62c373904c9fd299370d4d4c9a6f0f6ccb17bd83edbfa32938e";
        assert!(check_signature(SECRET, "1700000000", BODY, header).is_ok());
        assert_eq!(sign(SECRET, "1700000000", BODY), header);
    }

    #[test]
    fn a_wrong_secret_a_changed_body_or_a_changed_time_is_refused() {
        let header = sign(SECRET, "1700000000", BODY);
        assert!(check_signature(SECRET, "1700000000", BODY, &header).is_ok());
        assert_eq!(check_signature(b"another secret 123456", "1700000000", BODY, &header), Err(Reject::BadSignature));
        assert_eq!(
            check_signature(SECRET, "1700000000", br#"{"event":"down","message":"Front is up."}"#, &header),
            Err(Reject::BadSignature)
        );
        assert_eq!(check_signature(SECRET, "1700000001", BODY, &header), Err(Reject::BadSignature));
        assert_eq!(check_signature(SECRET, "1700000000", b"", &header), Err(Reject::BadSignature));
    }

    #[test]
    fn a_signature_header_that_is_not_one_is_malformed() {
        let good = sign(SECRET, "1", BODY);
        for bad in ["", "sha256=", "sha256=zz", &good[7..], &format!("sha1={}", &good[7..]), &format!("{good}00"), &good[..good.len() - 2]]
        {
            assert_eq!(check_signature(SECRET, "1", BODY, bad), Err(Reject::Malformed), "{bad:?}");
        }
        // Capital letters are the same number.
        assert!(check_signature(SECRET, "1", BODY, &format!("sha256={}", good[7..].to_uppercase())).is_ok());
    }

    #[test]
    fn the_time_must_be_recent_and_not_ahead() {
        let now = 1_700_000_000;
        assert_eq!(check_timestamp("1700000000", now, 300), Ok(now));
        assert_eq!(check_timestamp("1699999700", now, 300), Ok(now - 300));
        assert_eq!(check_timestamp("1699999699", now, 300), Err(Reject::Stale));
        assert_eq!(check_timestamp("1700000060", now, 300), Ok(now + 60));
        assert_eq!(check_timestamp("1700000061", now, 300), Err(Reject::Future));
        assert_eq!(check_timestamp("0", now, 300), Err(Reject::Stale));
    }

    #[test]
    fn a_timestamp_that_is_not_plain_digits_is_malformed() {
        for bad in ["", "-1", "+1", "1.5", "1e9", " 1", "1 ", "0x10", "9999999999999", "abc"] {
            assert_eq!(check_timestamp(bad, 1_700_000_000, 300), Err(Reject::Malformed), "{bad:?}");
        }
        assert_eq!(check_timestamp("999999999999", u64::MAX, 300), Err(Reject::Stale));
    }

    #[test]
    fn the_same_signed_request_is_taken_once() {
        let mut replay = Replay::default();
        let (now, signature) = (1_700_000_000, [7u8; 32]);
        assert!(replay.is_empty());
        assert_eq!(replay.insert(now, signature, now, 300), Ok(()));
        assert_eq!(replay.insert(now, signature, now + 10, 300), Err(Reject::Replay));
        // Another time, or another signature, is another request.
        assert_eq!(replay.insert(now + 1, signature, now + 10, 300), Ok(()));
        assert_eq!(replay.insert(now, [8u8; 32], now + 10, 300), Ok(()));
        assert_eq!(replay.len(), 3);
        // Once its time is stale it is forgotten (and refused as stale before it gets here).
        assert_eq!(replay.insert(now + 5, [9u8; 32], now + 302, 300), Ok(()));
        assert_eq!(replay.len(), 1);
    }

    #[test]
    fn the_replay_memory_is_bounded() {
        let mut replay = Replay::default();
        let now = 1_700_000_000;
        for i in 0..MAX_REMEMBERED {
            let mut signature = [0u8; 32];
            signature[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert_eq!(replay.insert(now, signature, now, 300), Ok(()));
        }
        assert_eq!(replay.insert(now, [255u8; 32], now, 300), Err(Reject::Busy));
        // The same request is still known to be a replay, and room comes back as they age out.
        assert_eq!(replay.insert(now, [0u8; 32], now, 300), Err(Reject::Replay));
        assert_eq!(replay.insert(now + 301, [255u8; 32], now + 301, 300), Ok(()));
        assert_eq!(replay.len(), 1);
    }
}
