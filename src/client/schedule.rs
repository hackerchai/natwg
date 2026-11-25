//! Client DNS and keepalive deadlines, driven by observations from one device.
use super::Options;
use std::time::Duration;
use tokio::time::Instant;

pub(super) struct Lookups {
    pub at: Instant,
    pub failure: Option<Instant>,
    retry: Duration,
    txt: bool,
    healthy: Duration,
    first: Duration,
}

impl Lookups {
    pub fn new(txt: bool, options: &Options) -> Self {
        Self {
            at: Instant::now(),
            failure: None,
            retry: options.retry_every,
            txt,
            healthy: if txt {
                options.txt_every
            } else {
                options.lookup_every
            },
            first: options.retry_every,
        }
    }

    /// Only the first signal in an outage can bypass the retry deadline.
    pub fn failed(&mut self, now: Instant) {
        if self.txt && self.failure.is_none() {
            self.failure = Some(now);
            self.at = now;
            self.retry = self.first;
        }
    }

    pub fn recovered(&mut self, now: Instant) {
        if self.failure.take().is_some() {
            self.at = now + self.healthy;
            self.retry = self.first;
        }
    }

    pub fn looked_up(&mut self, now: Instant, has_endpoint: bool, dns_ok: bool) {
        if !has_endpoint || (self.txt && (!dns_ok || self.failure.is_some())) {
            self.at = now + self.retry;
            self.retry = (self.retry * 2).min(self.healthy.min(Duration::from_secs(60)));
        } else {
            self.at = now + self.healthy;
            self.retry = self.first;
        }
    }
}

/// The fast check belongs to the build. Moving the endpoint starts a new
/// handshake observation without restarting the fast timer.
pub(super) struct Handshake {
    first_success: bool,
    pointed_at: Instant,
    greeted: bool,
    last_retry: Option<Instant>,
}

impl Handshake {
    pub fn new(building: Instant) -> Self {
        Self {
            first_success: false,
            pointed_at: building,
            greeted: false,
            last_retry: None,
        }
    }

    pub fn moved(&mut self, now: Instant) {
        self.pointed_at = now;
        self.greeted = false;
        self.last_retry = None;
    }

    pub fn interval(&self) -> Duration {
        Duration::from_secs(if self.first_success { 10 } else { 1 })
    }

    pub fn retried(&mut self, at: Instant, dns: &mut Lookups) {
        if at >= self.pointed_at {
            self.last_retry = Some(at);
            dns.failed(at);
        }
    }

    /// Return true on the first completed handshake with this endpoint.
    pub fn sample(
        &mut self,
        now: Instant,
        ago: Option<Duration>,
        keepalive: u16,
        dns: &mut Lookups,
    ) -> bool {
        let waiting = now - self.pointed_at;
        let success = !self.greeted && ago.is_some_and(|age| age <= waiting);
        self.greeted |= success;
        // gotatun can date a rapid first handshake just before the first
        // DNS point. Any authenticated session on this build ends fast checks.
        self.first_success |= ago.is_some();
        let stale = keepalive > 0
            && ago.unwrap_or(waiting).min(waiting)
                > Duration::from_secs(crate::status::handshake_stale_after(keepalive));
        if stale {
            dns.failed(now);
        } else if dns
            .failure
            .is_some_and(|since| ago.is_some_and(|age| age <= now - since))
            || (keepalive == 0
                && self
                    .last_retry
                    .is_none_or(|at| now - at >= super::Initiation::RETRY_WINDOW))
        {
            dns.recovered(now);
        }
        success
    }
}

pub(super) struct Keepalive {
    pub configured: u16,
    pub effective: u16,
    idle_limit: Option<Duration>,
    last_traffic: Instant,
}

impl Keepalive {
    pub fn new(seconds: u16, idle_limit: Option<Duration>) -> Self {
        Self {
            configured: seconds,
            effective: seconds,
            idle_limit,
            last_traffic: Instant::now(),
        }
    }

    pub fn update(&mut self, now: Instant, traffic: bool) -> Option<u16> {
        let limit = self.idle_limit?;
        if traffic {
            self.last_traffic = now;
        }
        let wanted = if now - self.last_traffic >= limit {
            0
        } else {
            self.configured
        };
        (wanted != self.effective).then(|| {
            self.effective = wanted;
            wanted
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn startup_and_dns_failures_back_off_without_losing_the_last_endpoint() {
        let now = Instant::now();
        for txt in [true, false] {
            let mut dns = Lookups::new(txt, &Options::default());
            for expected in [5, 10, 20, 40, 60, 60] {
                dns.looked_up(now, false, false);
                assert_eq!(dns.at - now, secs(expected));
            }
            dns.looked_up(now, true, true);
            assert_eq!(dns.at - now, secs(if txt { 600 } else { 60 }));
            dns.looked_up(now, true, false);
            assert_eq!(dns.at - now, secs(if txt { 5 } else { 60 }));
        }
    }

    #[test]
    fn repeated_failure_signals_cannot_bypass_backoff_or_accelerate_a_records() {
        let now = Instant::now();
        for txt in [true, false] {
            let mut dns = Lookups::new(txt, &Options::default());
            dns.looked_up(now, true, true);
            let failed = now + secs(15);
            dns.failed(failed);
            if !txt {
                assert_eq!(dns.at, now + secs(60));
                assert_eq!(dns.failure, None);
                continue;
            }
            assert_eq!(dns.at, failed);
            for pause in [5, 10, 20, 40, 60] {
                let looked = dns.at;
                dns.looked_up(looked, true, true); // valid but unchanged TXT
                dns.failed(looked + secs(1));
                assert_eq!(dns.at, looked + secs(pause));
            }
            dns.recovered(dns.at);
            assert_eq!(dns.failure, None);
            let failed_again = now + secs(350);
            dns.failed(failed_again);
            assert_eq!(dns.at, failed_again);
            dns.looked_up(failed_again, true, true);
            assert_eq!(dns.at, failed_again + secs(5));
        }
    }

    #[test]
    fn one_fast_phase_per_build_even_if_the_peer_moves_or_its_session_expires() {
        let start = Instant::now();
        let mut dns = Lookups::new(true, &Options::default());
        let mut hs = Handshake::new(start);
        assert_eq!(hs.interval(), secs(1));
        hs.moved(start + secs(3));
        // The first ever session, backdated by gotatun before point().
        hs.sample(start + secs(4), Some(secs(2)), 25, &mut dns);
        assert_eq!(hs.interval(), secs(10));
        hs.moved(start + secs(15));
        hs.sample(start + secs(16), None, 25, &mut dns);
        assert_eq!(hs.interval(), secs(10));
        assert!(hs.sample(start + secs(24), Some(secs(3)), 25, &mut dns));
        hs.sample(start + secs(300), Some(secs(279)), 25, &mut dns);
        assert_eq!(dns.at, start + secs(300));
        assert_eq!(hs.interval(), secs(10));
    }

    #[test]
    fn idle_without_keepalive_needs_a_real_retry_to_trigger_recovery() {
        let now = Instant::now();
        let mut dns = Lookups::new(true, &Options::default());
        let mut hs = Handshake::new(now);
        dns.looked_up(now, true, true);
        hs.sample(now + secs(500), Some(secs(499)), 0, &mut dns);
        assert_eq!(dns.at, now + secs(600));
        let retry = now + secs(510);
        hs.retried(retry, &mut dns);
        assert_eq!(dns.at, retry);
        dns.looked_up(retry, true, true);
        hs.sample(retry + secs(3), Some(secs(501)), 0, &mut dns);
        assert_eq!(dns.at, retry + secs(5));
        hs.sample(retry + secs(20), Some(secs(518)), 0, &mut dns);
        assert_eq!(dns.failure, None); // WireGuard stopped trying
        let retry = now + secs(550);
        hs.retried(retry, &mut dns);
        hs.sample(retry + secs(2), Some(secs(1)), 0, &mut dns);
        assert_eq!(dns.failure, None); // authenticated again
    }

    #[test]
    fn pause_resumes_only_on_inner_traffic_and_respects_disabled_keepalives() {
        let mut ka = Keepalive::new(25, Some(secs(60)));
        let start = ka.last_traffic;
        assert_eq!(ka.update(start + secs(59), false), None);
        assert_eq!(ka.update(start + secs(60), false), Some(0));
        assert_eq!(ka.update(start + secs(90), false), None);
        assert_eq!(ka.update(start + secs(100), true), Some(25));
        assert_eq!(ka.update(start + secs(155), true), None);
        assert_eq!(ka.update(start + secs(200), false), None);
        let mut disabled = Keepalive::new(0, Some(secs(60)));
        assert_eq!(disabled.update(start + secs(100), true), None);
        let mut default = Keepalive::new(25, None);
        assert_eq!(default.update(start + secs(600), false), None);
    }
}
