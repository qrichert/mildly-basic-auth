//! Bounded, shared allowances for unauthenticated password submissions.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use lru::LruCache;

use crate::client_ip::normalize_ip;

/// Bound memory even when clients rotate addresses. Eviction grants a
/// fresh burst; distributed guessing requires protection at the edge.
const MAX_CLIENT_BUCKETS: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

/// One allowance per resolved client, shared across middleware clones.
/// State is local to the application and disappears when it restarts.
#[derive(Clone)]
pub(crate) struct LoginThrottle {
    rate: f64,
    burst: u32,
    buckets: Arc<Mutex<LruCache<ClientKey, TokenBucket>>>,
}

impl LoginThrottle {
    /// Build from settings validated by `Config`: positive finite rate,
    /// a one-token wait below `2^64` seconds, and positive `u32` burst.
    pub(crate) fn new(rate: f64, burst: u32) -> Self {
        Self {
            rate,
            burst,
            buckets: Arc::new(Mutex::new(LruCache::new(MAX_CLIENT_BUCKETS))),
        }
    }

    /// Reserve before checking a password; return retry seconds if
    /// empty. The lock covers synchronous accounting, not verification.
    pub(crate) fn reserve(&self, key: ClientKey) -> Result<(), u64> {
        // A broken accounting invariant must not silently grant access.
        let mut buckets = self.buckets.lock().expect("login throttle lock poisoned");
        // Sample under the lock so queued requests cannot move a
        // bucket's refill timestamp backwards.
        let now = Instant::now();
        let bucket = buckets.get_or_insert_mut(key, || TokenBucket::new(now, self.burst));
        bucket.reserve(now, self.rate, self.burst)
    }

    /// Clear the entire allowance after an admitted successful login.
    /// Reservations before this reset are cleared; later ones receive a
    /// fresh burst. Use the same lock as reservation to fix that order.
    pub(crate) fn clear(&self, key: ClientKey) {
        _ = self
            .buckets
            .lock()
            .expect("login throttle lock poisoned")
            .pop(&key);
    }
}

/// IPv4 addresses, IPv6 /64 networks, or one unresolved identity.
/// Unknown clients share a bucket instead of receiving unlimited tries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ClientKey {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Unknown,
}

impl From<Option<IpAddr>> for ClientKey {
    /// Group IPv6 hosts by /64 so rotating host addresses cannot
    /// provide fresh attempts. For example, `2001:db8:1:2::3` becomes
    /// `2001:db8:1:2::`; `::ffff:192.0.2.4` becomes IPv4 `192.0.2.4`.
    fn from(ip: Option<IpAddr>) -> Self {
        match ip.map(normalize_ip) {
            Some(IpAddr::V4(ip)) => Self::Ipv4(ip),
            Some(IpAddr::V6(ip)) => {
                let segments = ip.segments();
                Self::Ipv6(Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    0,
                    0,
                    0,
                    0,
                ))
            }
            None => Self::Unknown,
        }
    }
}

/// Refilled on access; no timer or background cleanup needed.
struct TokenBucket {
    available: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(now: Instant, burst: u32) -> Self {
        Self {
            available: f64::from(burst),
            last_refill: now,
        }
    }

    /// Refill and consume one token, retaining fractional credit on
    /// denial so early retries do not postpone the next admission.
    fn reserve(&mut self, now: Instant, rate: f64, burst: u32) -> Result<(), u64> {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        // Finite positive settings and monotonic time cannot produce
        // `NaN`. A large refill may overflow to infinity; capping it
        // here keeps the stored count finite. Every `u32` fits exactly.
        self.available = (self.available + elapsed * rate).min(f64::from(burst));
        self.last_refill = now;
        if self.available >= 1.0 {
            self.available -= 1.0;
            return Ok(());
        }

        let seconds = ((1.0 - self.available) / rate).ceil().max(1.0);
        // Config validation bounds the largest possible wait below
        // `2^64`. Rounding up and the minimum of one make this a
        // positive, integral value representable by `u64`.
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let retry_after = seconds as u64;
        Err(retry_after)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::time::Duration;

    use super::*;

    #[test]
    fn full_bucket_admits_exactly_the_default_burst() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(now, 10);

        for _ in 0..10 {
            assert_eq!(bucket.reserve(now, 1.0, 10), Ok(()));
        }
        assert_eq!(bucket.reserve(now, 1.0, 10), Err(1));
    }

    #[test]
    fn retry_seconds_round_up_partial_refill() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(now, 1);
        assert_eq!(bucket.reserve(now, 0.25, 1), Ok(()));

        assert_eq!(
            bucket.reserve(now + Duration::from_millis(1500), 0.25, 1),
            Err(3)
        );
    }

    #[test]
    fn repeated_denials_preserve_fractional_credit() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(now, 1);
        assert_eq!(bucket.reserve(now, 1.0, 1), Ok(()));

        for milliseconds in [250, 500, 750] {
            assert_eq!(
                bucket.reserve(now + Duration::from_millis(milliseconds), 1.0, 1),
                Err(1)
            );
        }
        assert_eq!(bucket.reserve(now + Duration::from_secs(1), 1.0, 1), Ok(()));
    }

    #[test]
    fn refill_restores_multiple_tokens() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(now, 3);
        for _ in 0..3 {
            assert_eq!(bucket.reserve(now, 2.0, 3), Ok(()));
        }

        let later = now + Duration::from_secs(1);
        assert_eq!(bucket.reserve(later, 2.0, 3), Ok(()));
        assert_eq!(bucket.reserve(later, 2.0, 3), Ok(()));
        assert_eq!(bucket.reserve(later, 2.0, 3), Err(1));
    }

    #[test]
    fn idle_refill_cannot_exceed_burst() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(now, 2);
        let later = now + Duration::from_secs(1000);

        assert_eq!(bucket.reserve(later, 1.0, 2), Ok(()));
        assert_eq!(bucket.reserve(later, 1.0, 2), Ok(()));
        assert_eq!(bucket.reserve(later, 1.0, 2), Err(1));
    }

    #[test]
    fn overflowing_refill_remains_bounded() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(now, 1);
        assert_eq!(bucket.reserve(now, f64::MAX, 1), Ok(()));
        let later = now + Duration::from_secs(2);

        assert_eq!(bucket.reserve(later, f64::MAX, 1), Ok(()));
        assert_eq!(bucket.reserve(later, f64::MAX, 1), Err(1));
    }

    #[test]
    fn maximum_burst_still_consumes_one_token() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(now, u32::MAX);

        assert_eq!(bucket.reserve(now, 1.0, u32::MAX), Ok(()));
        // Every `u32` fits exactly, including the consumed token.
        assert_eq!(bucket.available, f64::from(u32::MAX - 1));
    }

    #[test]
    fn smallest_accepted_rate_returns_representable_retry() {
        let now = Instant::now();
        // The exact reciprocal of `2^64` is too small; the next higher
        // float yields the longest representable configured wait.
        let rate = (1.0_f64 / 18_446_744_073_709_551_616.0).next_up();
        let mut bucket = TokenBucket::new(now, 1);
        assert_eq!(bucket.reserve(now, rate, 1), Ok(()));

        assert_eq!(
            bucket.reserve(now, rate, 1),
            Err(18_446_744_073_709_547_520)
        );
    }

    #[test]
    fn clearing_a_client_grants_a_fresh_burst() {
        let throttle = LoginThrottle::new(0.000_001, 2);
        let client = key("192.0.2.1");
        assert_eq!(throttle.reserve(client), Ok(()));
        assert_eq!(throttle.reserve(client), Ok(()));
        assert!(throttle.reserve(client).is_err());

        throttle.clear(client);

        assert_eq!(throttle.reserve(client), Ok(()));
        assert_eq!(throttle.reserve(client), Ok(()));
        assert!(throttle.reserve(client).is_err());
    }

    #[test]
    fn clearing_one_client_does_not_reset_another() {
        let throttle = LoginThrottle::new(0.000_001, 1);
        let first = key("192.0.2.1");
        let second = key("192.0.2.2");
        assert_eq!(throttle.reserve(first), Ok(()));
        assert_eq!(throttle.reserve(second), Ok(()));

        throttle.clear(first);

        assert!(throttle.reserve(second).is_err());
    }

    #[test]
    fn concurrent_clones_cannot_exceed_burst() {
        let throttle = LoginThrottle::new(0.000_001, 10);
        let barrier = Arc::new(Barrier::new(32));
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let throttle = throttle.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    throttle.reserve(ClientKey::Unknown).is_ok()
                })
            })
            .collect();

        let admitted = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 10);
    }

    #[test]
    fn cache_never_exceeds_its_capacity() {
        let throttle = LoginThrottle::new(0.000_001, 1);
        for address in 0..=10_000_u32 {
            let client = ClientKey::Ipv4(Ipv4Addr::from(address));
            assert_eq!(throttle.reserve(client), Ok(()));
        }

        assert_eq!(throttle.buckets.lock().unwrap().len(), 10_000);
    }

    #[test]
    fn denied_access_keeps_a_client_recently_used() {
        let throttle = small_cache();
        let first = key("192.0.2.1");
        let second = key("192.0.2.2");
        assert_eq!(throttle.reserve(first), Ok(()));
        assert_eq!(throttle.reserve(second), Ok(()));
        assert!(throttle.reserve(first).is_err());
        assert_eq!(throttle.reserve(key("192.0.2.3")), Ok(()));

        let buckets = throttle.buckets.lock().unwrap();
        assert!(buckets.peek(&first).is_some());
        assert!(buckets.peek(&second).is_none());
    }

    #[test]
    fn evicted_clients_receive_a_fresh_burst() {
        let throttle = small_cache();
        let first = key("192.0.2.1");
        assert_eq!(throttle.reserve(first), Ok(()));
        assert_eq!(throttle.reserve(key("192.0.2.2")), Ok(()));
        assert_eq!(throttle.reserve(key("192.0.2.3")), Ok(()));

        assert_eq!(throttle.reserve(first), Ok(()));
    }

    #[test]
    fn mapped_ipv4_uses_the_same_key_as_ipv4() {
        assert_eq!(key("::ffff:192.0.2.1"), key("192.0.2.1"));
        assert_ne!(key("192.0.2.1"), key("192.0.2.2"));
    }

    #[test]
    fn ipv6_hosts_in_the_same_subnet_share_a_key() {
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff::ffff"));
    }

    #[test]
    fn different_ipv6_subnets_have_independent_keys() {
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
    }

    #[test]
    fn unknown_identity_cannot_collide_with_an_address() {
        assert_eq!(ClientKey::from(None), ClientKey::Unknown);
        assert_ne!(ClientKey::from(None), key("0.0.0.0"));
        assert_ne!(ClientKey::from(None), key("::"));
    }

    fn key(ip: &str) -> ClientKey {
        ClientKey::from(Some(ip.parse().unwrap()))
    }

    fn small_cache() -> LoginThrottle {
        LoginThrottle {
            rate: 0.000_001,
            burst: 1,
            buckets: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(2).unwrap()))),
        }
    }
}
