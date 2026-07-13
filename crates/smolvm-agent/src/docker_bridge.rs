//! Guest-side Docker socket bridge.
//!
//! The inverse of the SSH agent bridge: instead of the guest dialing *out* to a
//! host socket, the guest *listens* on the [`ports::DOCKER`] vsock port and, for
//! each connection the host opens, proxies bytes to the in-guest Docker daemon
//! socket ([`GUEST_DOCKER_SOCK`]). libkrun exposes the host end as a Unix socket
//! in the VM's data dir, so a host-side client reaches the guest's dockerd with
//! `DOCKER_HOST=unix://…` — the same direction as the agent control channel.
//!
//! Enabled by [`guest_env::DOCKER_SOCKET`]. The bridge starts at agent boot even
//! before dockerd is up: a host connection that arrives while the daemon socket
//! is absent simply fails to connect and is dropped (the host docker client then
//! reports the usual "is the docker daemon running?"), and succeeds once dockerd
//! is listening — no start-order coupling.

use smolvm_protocol::{guest_env, ports};
use std::io;
use std::thread;

/// In-guest path of the Docker daemon's Unix socket (dockerd's default).
pub const GUEST_DOCKER_SOCK: &str = "/var/run/docker.sock";

/// Whether the Docker socket bridge is enabled for this launch.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::DOCKER_SOCKET).as_deref() == Ok(guest_env::VALUE_ON)
}

/// Start the guest-side Docker socket bridge in a background thread.
pub fn start() {
    thread::Builder::new()
        .name("docker-bridge-guest".into())
        .spawn(|| {
            if let Err(e) = run_bridge() {
                tracing::warn!(error = %e, "guest Docker socket bridge stopped");
            }
        })
        .ok();
}

fn run_bridge() -> io::Result<()> {
    let listener = crate::vsock::VsockListener::bind(ports::DOCKER)?;
    tracing::info!(
        vsock_port = ports::DOCKER,
        guest_socket = GUEST_DOCKER_SOCK,
        "guest Docker socket bridge listening"
    );

    loop {
        let host_conn = match listener.accept() {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "Docker bridge accept error");
                // A bad listener fd is terminal; anything else is per-connection.
                if e.kind() == io::ErrorKind::InvalidInput {
                    return Err(e);
                }
                continue;
            }
        };
        thread::Builder::new()
            .name("docker-bridge-fwd".into())
            .spawn(move || {
                if let Err(e) = relay_to_daemon(host_conn) {
                    tracing::debug!(error = %e, "Docker bridge relay ended");
                }
            })
            .ok();
    }
}

/// Relay one host connection (arriving over vsock) to the in-guest Docker
/// daemon socket, forwarding bytes in both directions with independent
/// half-close: when one side closes its write half, its FIN is mirrored to the
/// peer while the other direction keeps flowing until it closes too.
///
/// Docker connections are frequently long-lived and idle (`docker logs -f`,
/// `docker events`, hijacked `exec`/`build` streams), so — unlike the SSH agent
/// relay — this blocks on `poll` indefinitely and only exits once both
/// directions have closed. Honoring half-close is required for hijacked attach
/// streams (`docker run`/`exec` with no stdin), which close their write half
/// before the daemon has finished streaming output.
#[cfg(target_os = "linux")]
fn relay_to_daemon(host_conn: crate::vsock::VsockStream) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    let mut host = host_conn;
    let mut daemon = UnixStream::connect(GUEST_DOCKER_SOCK)?;

    let host_fd = host.as_raw_fd();
    let daemon_fd = daemon.as_raw_fd();

    let mut buf = [0u8; 65536];

    // Track each direction independently so a half-close is mirrored, not
    // treated as a full teardown. A hijacked Docker attach (`docker run`/`exec`
    // with no stdin) half-closes its write side right after `101 UPGRADED`, so
    // host→daemon hits EOF while the daemon is still streaming output back.
    // Tearing the whole relay down there silently drops that output — instead we
    // forward the FIN to the peer and keep pumping the other direction until it
    // closes too.
    let mut host_read_open = true;
    let mut daemon_read_open = true;

    while host_read_open || daemon_read_open {
        let mut poll_fds = [
            libc::pollfd {
                // A negative fd is ignored by poll(), so a closed read side
                // stops waking the loop while the other direction drains.
                fd: if host_read_open { host_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if daemon_read_open { daemon_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // Block until an open side is readable/closed (no idle timeout).
        let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        // host → daemon
        if host_read_open
            && poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            let n = io::Read::read(&mut host, &mut buf)?;
            if n == 0 {
                // Host closed its write half: deliver EOF to the daemon so it
                // finishes the request, but keep relaying daemon→host.
                host_read_open = false;
                let _ = daemon.shutdown(std::net::Shutdown::Write);
            } else {
                io::Write::write_all(&mut daemon, &buf[..n])?;
            }
        }

        // daemon → host
        if daemon_read_open
            && poll_fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            let n = io::Read::read(&mut daemon, &mut buf)?;
            if n == 0 {
                // Daemon closed its write half: deliver EOF to the host over
                // vsock, but keep relaying host→daemon.
                daemon_read_open = false;
                // SAFETY: host_fd is the valid, open fd owned by `host`.
                unsafe { libc::shutdown(host_fd, libc::SHUT_WR) };
            } else {
                io::Write::write_all(&mut host, &buf[..n])?;
            }
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn relay_to_daemon(_host_conn: crate::vsock::VsockStream) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Docker socket bridge only supported on Linux guests",
    ))
}
