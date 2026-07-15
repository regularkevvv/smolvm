//! Synthetic DNS for hostname-preserving proxy egress.

use crate::dns;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const POOL_FIRST: u32 = u32::from_be_bytes([198, 18, 0, 1]);
const POOL_LAST: u32 = u32::from_be_bytes([198, 19, 255, 254]);
pub const DEFAULT_VIRTUAL_DNS_CAPACITY: usize = 4096;
pub const DEFAULT_VIRTUAL_DNS_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct VirtualDns {
    inner: Arc<Mutex<State>>,
    capacity: usize,
    ttl: Duration,
}

#[derive(Debug)]
struct State {
    next: u32,
    by_ip: HashMap<Ipv4Addr, Entry>,
    by_host: HashMap<String, Ipv4Addr>,
}

#[derive(Clone, Debug)]
struct Entry {
    hostname: String,
    expires_at: Instant,
}

impl Default for VirtualDns {
    fn default() -> Self {
        Self::new(DEFAULT_VIRTUAL_DNS_CAPACITY, DEFAULT_VIRTUAL_DNS_TTL)
    }
}

impl VirtualDns {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                next: POOL_FIRST,
                by_ip: HashMap::new(),
                by_host: HashMap::new(),
            })),
            capacity,
            ttl,
        }
    }

    pub fn allocate(&self, hostname: &str) -> Option<Ipv4Addr> {
        self.allocate_at(hostname, Instant::now())
    }

    pub fn resolve(&self, ip: Ipv4Addr) -> Option<String> {
        self.resolve_at(ip, Instant::now())
    }

    /// Whether an address belongs to the synthetic 198.18.0.0/15 pool.
    pub fn contains(ip: Ipv4Addr) -> bool {
        let value = u32::from(ip);
        (POOL_FIRST..=POOL_LAST).contains(&value)
    }

    fn allocate_at(&self, hostname: &str, now: Instant) -> Option<Ipv4Addr> {
        let hostname = dns::normalize_hostname(hostname)?;
        let mut state = self.inner.lock().ok()?;
        prune(&mut state, now);
        if let Some(ip) = state.by_host.get(&hostname).copied() {
            if let Some(entry) = state.by_ip.get_mut(&ip) {
                entry.expires_at = now + self.ttl;
            }
            return Some(ip);
        }
        if self.capacity == 0 || state.by_ip.len() >= self.capacity {
            return None;
        }

        let pool_size = POOL_LAST - POOL_FIRST + 1;
        for _ in 0..pool_size {
            let candidate = state.next;
            state.next = if candidate == POOL_LAST {
                POOL_FIRST
            } else {
                candidate + 1
            };
            let ip = Ipv4Addr::from(candidate);
            if state.by_ip.contains_key(&ip) {
                continue;
            }
            state.by_host.insert(hostname.clone(), ip);
            state.by_ip.insert(
                ip,
                Entry {
                    hostname,
                    expires_at: now + self.ttl,
                },
            );
            return Some(ip);
        }
        None
    }

    fn resolve_at(&self, ip: Ipv4Addr, now: Instant) -> Option<String> {
        let mut state = self.inner.lock().ok()?;
        prune(&mut state, now);
        state.by_ip.get(&ip).map(|entry| entry.hostname.clone())
    }

    #[cfg(test)]
    fn force_next(&self, ip: Ipv4Addr) {
        self.inner.lock().unwrap().next = u32::from(ip);
    }
}

fn prune(state: &mut State, now: Instant) {
    state.by_ip.retain(|_, entry| entry.expires_at > now);
    state.by_host.retain(|_, ip| state.by_ip.contains_key(ip));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_is_stable_bounded_and_expires() {
        let dns = VirtualDns::new(2, Duration::from_secs(5));
        let now = Instant::now();
        let first = dns.allocate_at("One.Example.", now).unwrap();
        assert_eq!(dns.allocate_at("one.example", now), Some(first));
        let second = dns.allocate_at("two.example", now).unwrap();
        assert_ne!(first, second);
        assert!(dns.allocate_at("three.example", now).is_none());
        assert_eq!(dns.resolve_at(first, now).as_deref(), Some("one.example"));
        assert!(dns
            .resolve_at(first, now + Duration::from_secs(6))
            .is_none());
        assert!(dns
            .allocate_at("three.example", now + Duration::from_secs(6))
            .is_some());
    }

    #[test]
    fn allocation_skips_collisions_and_wraps_the_pool() {
        let dns = VirtualDns::new(4, Duration::from_secs(60));
        dns.force_next(Ipv4Addr::from(POOL_LAST));
        let last = dns.allocate("last.example").unwrap();
        assert_eq!(u32::from(last), POOL_LAST);
        let first = dns.allocate("first.example").unwrap();
        assert_eq!(u32::from(first), POOL_FIRST);
        dns.force_next(last);
        let skipped = dns.allocate("skip.example").unwrap();
        assert_ne!(skipped, last);
        assert_ne!(skipped, first);
    }
}
