//! Kernel notifications are hints. Always re-read the preferred physical
//! uplink and local networks before acting, including after a lost message.
use socket2::{Domain, Socket, Type};
use std::{future, io, os::fd::AsRawFd, time::Duration};
use tokio::{
    io::unix::AsyncFd,
    time::{Instant, Interval, MissedTickBehavior},
};

pub(super) struct Monitor {
    socket: Option<AsyncFd<Socket>>,
    fallback: Interval,
    read_after: Instant,
}

impl Monitor {
    pub fn new(period: Duration) -> Self {
        let now = Instant::now();
        let mut fallback = tokio::time::interval_at(now + period, period);
        fallback.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self {
            socket: open(),
            fallback,
            read_after: now,
        }
    }

    pub fn refresh(&mut self) {
        self.fallback.reset_immediately();
    }

    /// Cancellation-safe. A burst of route/address/link messages needs one
    /// snapshot. Bound the work per read so a route storm cannot starve timers.
    pub async fn changed(&mut self) {
        tokio::select! {
            _ = self.fallback.tick() => {
                if self.socket.is_none() {
                    self.socket = open();
                }
            }
            result = async {
                let Some(socket) = &self.socket else { return future::pending().await };
                tokio::time::sleep_until(self.read_after).await;
                loop {
                    let mut ready = socket.readable().await?;
                    match ready.try_io(|fd| drain(fd.get_ref())) {
                        Ok(Ok(true)) => return Ok(()),
                        Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => return Ok(()),
                        Ok(Err(e)) => return Err(e),
                        _ => (),
                    }
                }
            } => {
                if let Err(e) = result {
                    tracing::warn!("route notifications stopped: {e}; using fallback");
                    self.socket = None;
                }
                self.read_after = Instant::now() + Duration::from_millis(200);
            }
        }
    }
}

fn open() -> Option<AsyncFd<Socket>> {
    subscribe()
        // The socket is nonblocking and owned by AsyncFd until deregistration.
        .and_then(|socket| {
            unsafe { AsyncFd::register_with_interest(socket, tokio::io::Interest::READABLE) }
                .map_err(io::Error::from)
        })
        .map_err(|e| {
            tracing::warn!("cannot subscribe to route changes: {e}; using fallback");
        })
        .ok()
}

#[cfg(target_os = "linux")]
fn subscribe() -> io::Result<Socket> {
    let socket = Socket::new(
        Domain::from(libc::AF_NETLINK),
        Type::RAW,
        Some(socket2::Protocol::from(libc::NETLINK_ROUTE)),
    )?;
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as _;
    addr.nl_groups = (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV4_ROUTE) as _;
    let res = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            std::ptr::from_ref(&addr).cast(),
            size_of_val(&addr) as _,
        )
    };
    if res == -1 {
        return Err(io::Error::last_os_error());
    }
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(target_os = "macos")]
fn subscribe() -> io::Result<Socket> {
    let socket = Socket::new(Domain::from(libc::PF_ROUTE), Type::RAW, None)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn drain(socket: &Socket) -> io::Result<bool> {
    let mut changed = false;
    let mut buf = [0; 8192];
    for _ in 0..64 {
        let n = unsafe { libc::recv(socket.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if changed && e.kind() == io::ErrorKind::WouldBlock {
                break;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        changed |= relevant(&buf[..n as usize]);
    }
    Ok(changed)
}

// Only link, IPv4 address and IPv4 route multicasts are subscribed.
#[cfg(target_os = "linux")]
fn relevant(_: &[u8]) -> bool {
    true
}

#[cfg(target_os = "macos")]
fn relevant(msg: &[u8]) -> bool {
    let [_, _, version, kind, ..] = msg else {
        return false;
    };
    if i32::from(*version) != libc::RTM_VERSION {
        return false;
    }
    match i32::from(*kind) {
        libc::RTM_NEWADDR | libc::RTM_DELADDR | libc::RTM_IFINFO | libc::RTM_IFINFO2 => true,
        libc::RTM_ADD | libc::RTM_DELETE | libc::RTM_CHANGE => {
            // rt_msghdr.rtm_flags. Ignore ARP and cloned host routes, which
            // can follow ordinary traffic on an otherwise unchanged uplink.
            let Some(flags) = msg.get(8..12) else {
                return false;
            };
            i32::from_ne_bytes(flags.try_into().unwrap()) & (libc::RTF_LLINFO | libc::RTF_WASCLONED)
                == 0
        }
        _ => false,
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn route_edits_and_interface_changes_wake_the_client_but_host_cache_and_get_do_not() {
        for (kind, flags, accepted) in [
            (libc::RTM_ADD, 0, true),
            (libc::RTM_DELETE, 0, true),
            (libc::RTM_CHANGE, 0, true),
            (libc::RTM_NEWADDR, 0, true),
            (libc::RTM_DELADDR, 0, true),
            (libc::RTM_IFINFO, 0, true),
            (libc::RTM_GET, 0, false),
            (libc::RTM_ADD, libc::RTF_LLINFO, false),
            (libc::RTM_DELETE, libc::RTF_WASCLONED, false),
        ] {
            let mut msg = [0; 12];
            msg[2] = libc::RTM_VERSION as u8;
            msg[3] = kind as u8;
            msg[8..].copy_from_slice(&flags.to_ne_bytes());
            assert_eq!(relevant(&msg), accepted);
        }
    }

    #[test]
    fn native_route_get_is_visible_but_does_not_signal_an_uplink_change() {
        // Ask the kernel about loopback. This emits RTM_GET on PF_ROUTE
        // without adding or removing an address, route or interface.
        let socket = subscribe().unwrap();
        let mut child = std::process::Command::new("/sbin/route")
            .args(["-n", "get", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        assert!(child.wait().unwrap().success());
        let mut msg = [std::mem::MaybeUninit::uninit(); 8192];
        while let Ok(n) = socket.recv(&mut msg) {
            // recv initialized the first n bytes.
            let data = unsafe { std::slice::from_raw_parts(msg.as_ptr().cast::<u8>(), n) };
            if n >= 20
                && i32::from(data[3]) == libc::RTM_GET
                && i32::from_ne_bytes(data[16..20].try_into().unwrap()) == pid
            {
                assert!(!relevant(data));
                return;
            }
        }
        panic!("the PF_ROUTE listener did not receive the loopback RTM_GET");
    }
}

#[cfg(test)]
mod fallback_tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn fallback_fires_after_sixty_seconds_without_route_notifications() {
        let period = super::super::Options::default().watch_every;
        let mut monitor = Monitor::new(period);
        // Keep this deterministic on hosts with route activity.
        monitor.socket = None;
        let before = Instant::now();
        monitor.changed().await;
        assert_eq!(Instant::now() - before, Duration::from_secs(60));
    }
}
