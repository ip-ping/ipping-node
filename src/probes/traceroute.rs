//! One traceroute probe: an ICMP echo request with a chosen TTL, and whoever answers.
//!
//! Linux only, and without privileges: an unprivileged ICMP "ping socket" (the same thing `ping`
//! uses, governed by `net.ipv4.ping_group_range`) with `IP_RECVERR` turned on. A router that drops
//! the packet because its TTL ran out sends back an ICMP "time exceeded"; the kernel hands that to
//! the socket's *error queue* together with the router's address, so no raw socket is needed. If the
//! packet reaches the destination, the echo reply arrives as normal data.
//!
//! Each probe is its own socket, so answers can never be mixed up between probes. The wait is a
//! blocking `poll(2)` and runs on tokio's blocking pool.

use std::net::IpAddr;
use std::time::Duration;

use crate::protocol::error_code;

/// What came back for one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopOutcome {
    /// A router (or the destination) answered.
    Reply {
        from: IpAddr,
        rtt: Duration,
        /// The destination itself answered with an echo reply.
        reached: bool,
        /// A router said the destination cannot be reached; probing further is pointless.
        terminal: bool,
    },
    /// Nothing answered in time. Routers that stay silent are normal.
    Timeout,
    /// The probe could not be sent; the value is a protocol error code.
    Failed(&'static str),
}

/// Can this host send traceroute probes over this IP version?
pub fn available(v6: bool) -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::socket(v6).is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = v6;
        false
    }
}

/// Send one echo request to `ip` with this TTL and wait for an answer. Blocks the calling thread.
pub fn probe(ip: IpAddr, ttl: u8, seq: u16, timeout: Duration) -> HopOutcome {
    #[cfg(target_os = "linux")]
    {
        linux::probe(ip, ttl, seq, timeout)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ip, ttl, seq, timeout);
        HopOutcome::Failed(error_code::UNSUPPORTED_KIND)
    }
}

#[cfg(target_os = "linux")]
// `cmsg_len` is a `usize` on glibc but a `u32` on musl, so the casts below are needed on one of them.
#[allow(clippy::unnecessary_cast)]
mod linux {
    use std::io;
    use std::mem::{MaybeUninit, size_of, zeroed};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    use super::{HopOutcome, error_code};

    // From <linux/errqueue.h>, which the libc crate does not export.
    const SO_EE_ORIGIN_LOCAL: u8 = 1;
    const SO_EE_ORIGIN_ICMP: u8 = 2;
    const SO_EE_ORIGIN_ICMP6: u8 = 3;
    const ICMP_DEST_UNREACH: u8 = 3;
    const ICMP_TIME_EXCEEDED: u8 = 11;
    const ICMP6_DST_UNREACH: u8 = 1;
    const ICMP6_TIME_EXCEEDED: u8 = 3;

    const ECHO_REQUEST_V4: u8 = 8;
    const ECHO_REPLY_V4: u8 = 0;
    const ECHO_REQUEST_V6: u8 = 128;
    const ECHO_REPLY_V6: u8 = 129;

    /// Same size as the node's ping payload: 8 bytes of ICMP header and 56 bytes of data.
    const PACKET_LEN: usize = 8 + 56;

    fn code_for(error: &io::Error) -> &'static str {
        match error.raw_os_error() {
            Some(libc::EACCES | libc::EPERM) => error_code::PERMISSION_DENIED,
            Some(libc::ENETUNREACH) => error_code::NETWORK_UNREACHABLE,
            Some(libc::EHOSTUNREACH) => error_code::HOST_UNREACHABLE,
            Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT) => error_code::UNSUPPORTED_FAMILY,
            _ => error_code::INTERNAL_ERROR,
        }
    }

    /// A ping socket that reports ICMP errors through its error queue.
    pub fn socket(v6: bool) -> io::Result<Socket> {
        let (domain, protocol) = if v6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(protocol))?;
        let (level, name) = if v6 {
            (libc::SOL_IPV6, libc::IPV6_RECVERR)
        } else {
            (libc::SOL_IP, libc::IP_RECVERR)
        };
        let on: libc::c_int = 1;
        // SAFETY: the descriptor is a live socket owned by `socket`, and the pointer and length
        // describe one `c_int` that outlives the call.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                (&raw const on).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        socket.set_nonblocking(true)?;
        Ok(socket)
    }

    pub fn probe(ip: IpAddr, ttl: u8, seq: u16, timeout: Duration) -> HopOutcome {
        let v6 = ip.is_ipv6();
        let socket = match socket(v6) {
            Ok(socket) => socket,
            Err(error) => return HopOutcome::Failed(code_for(&error)),
        };
        let set_ttl = if v6 {
            socket.set_unicast_hops_v6(u32::from(ttl))
        } else {
            socket.set_ttl_v4(u32::from(ttl))
        };
        if let Err(error) = set_ttl {
            return HopOutcome::Failed(code_for(&error));
        }
        if let Err(error) = socket.connect(&SockAddr::from(SocketAddr::new(ip, 0))) {
            return HopOutcome::Failed(code_for(&error));
        }

        // The kernel fills in the identifier and the checksum of a ping socket's packets.
        let mut packet = [0x69u8; PACKET_LEN];
        packet[..6].fill(0);
        packet[0] = if v6 { ECHO_REQUEST_V6 } else { ECHO_REQUEST_V4 };
        packet[6..8].copy_from_slice(&seq.to_be_bytes());
        let sent = Instant::now();
        if let Err(error) = socket.send(&packet) {
            return HopOutcome::Failed(code_for(&error));
        }

        let deadline = sent + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return HopOutcome::Timeout;
            }
            let mut fd = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN | libc::POLLERR,
                revents: 0,
            };
            // Round up, so a wait never ends a millisecond early and busy-loops.
            let wait_ms = i32::try_from(remaining.as_millis() + 1).unwrap_or(i32::MAX);
            // SAFETY: `fd` is one valid `pollfd` and the count says so.
            let ready = unsafe { libc::poll(&raw mut fd, 1, wait_ms) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return HopOutcome::Failed(code_for(&error));
            }
            if ready == 0 {
                return HopOutcome::Timeout;
            }
            let elapsed = sent.elapsed();

            if fd.revents & libc::POLLERR != 0 {
                match read_error(&socket, v6) {
                    QueueEntry::Hop { from, terminal } => {
                        return HopOutcome::Reply {
                            from,
                            rtt: elapsed,
                            reached: false,
                            terminal,
                        };
                    }
                    QueueEntry::Failed(code) => return HopOutcome::Failed(code),
                    QueueEntry::Nothing => {}
                }
            }
            if fd.revents & libc::POLLIN != 0 {
                let mut buffer = [MaybeUninit::<u8>::uninit(); 512];
                match socket.recv(&mut buffer) {
                    Ok(n) => {
                        // SAFETY: `recv` initialised the first `n` bytes.
                        let data =
                            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), n) };
                        let reply = if v6 { ECHO_REPLY_V6 } else { ECHO_REPLY_V4 };
                        if data.len() >= 8 && data[0] == reply && data[6..8] == seq.to_be_bytes() {
                            return HopOutcome::Reply {
                                from: ip,
                                rtt: elapsed,
                                reached: true,
                                terminal: false,
                            };
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return HopOutcome::Failed(code_for(&error)),
                }
            }
        }
    }

    enum QueueEntry {
        /// An ICMP error from this router.
        Hop { from: IpAddr, terminal: bool },
        /// The kernel itself could not send (no route, not permitted).
        Failed(&'static str),
        /// Something that says nothing about the path.
        Nothing,
    }

    /// Take one entry off the socket's error queue.
    fn read_error(socket: &Socket, v6: bool) -> QueueEntry {
        let mut data = [0u8; 576];
        // 512 bytes, 8-byte aligned, as `cmsghdr` requires.
        let mut control = [0u64; 64];
        // SAFETY: both are plain C structs for which all-zero is a valid (empty) value.
        let mut name: libc::sockaddr_storage = unsafe { zeroed() };
        let mut message: libc::msghdr = unsafe { zeroed() };
        let mut vector = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        message.msg_name = (&raw mut name).cast();
        message.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        message.msg_iov = &raw mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control) as _;

        // SAFETY: `message` points at buffers that live for the whole call and whose sizes it states.
        let received = unsafe {
            libc::recvmsg(
                socket.as_raw_fd(),
                &raw mut message,
                libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
            )
        };
        if received < 0 {
            return QueueEntry::Nothing; // EAGAIN: someone already took it
        }

        let (level, kind) = if v6 {
            (libc::SOL_IPV6, libc::IPV6_RECVERR)
        } else {
            (libc::SOL_IP, libc::IP_RECVERR)
        };
        // SAFETY: the kernel filled `message`; the CMSG_* helpers only walk the control buffer it
        // describes, and every read below stays inside the `cmsg_len` it reports.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&raw const message);
            while !header.is_null() {
                let cmsg = &*header;
                let needed = libc::CMSG_LEN(
                    (size_of::<libc::sock_extended_err>() + size_of::<libc::sockaddr_in>()) as u32,
                ) as usize;
                if cmsg.cmsg_level == level
                    && cmsg.cmsg_type == kind
                    && cmsg.cmsg_len as usize >= needed
                {
                    let payload = libc::CMSG_DATA(header);
                    let error: libc::sock_extended_err = std::ptr::read_unaligned(payload.cast());
                    let offender = payload.add(size_of::<libc::sock_extended_err>());
                    return classify(&error, read_address(offender, cmsg, payload), v6);
                }
                header = libc::CMSG_NXTHDR(&raw const message, header);
            }
        }
        QueueEntry::Nothing
    }

    /// The router's address, which follows the `sock_extended_err` in the control message.
    ///
    /// # Safety
    /// `offender` must point inside the control message `cmsg`, whose data starts at `payload`.
    unsafe fn read_address(
        offender: *const u8,
        cmsg: &libc::cmsghdr,
        payload: *const u8,
    ) -> Option<IpAddr> {
        // SAFETY: the caller guarantees `offender` is within the message; the length check below
        // keeps every read inside it.
        unsafe {
            let available = (cmsg.cmsg_len as usize)
                .saturating_sub(libc::CMSG_LEN(0) as usize)
                .saturating_sub(offender.offset_from(payload) as usize);
            let family: libc::sa_family_t = std::ptr::read_unaligned(offender.cast());
            match i32::from(family) {
                libc::AF_INET if available >= size_of::<libc::sockaddr_in>() => {
                    let address: libc::sockaddr_in = std::ptr::read_unaligned(offender.cast());
                    Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                        address.sin_addr.s_addr,
                    ))))
                }
                libc::AF_INET6 if available >= size_of::<libc::sockaddr_in6>() => {
                    let address: libc::sockaddr_in6 = std::ptr::read_unaligned(offender.cast());
                    Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
                }
                _ => None,
            }
        }
    }

    fn classify(error: &libc::sock_extended_err, from: Option<IpAddr>, v6: bool) -> QueueEntry {
        match error.ee_origin {
            SO_EE_ORIGIN_ICMP | SO_EE_ORIGIN_ICMP6 => {
                let Some(from) = from else {
                    return QueueEntry::Nothing;
                };
                let (time_exceeded, unreachable) = if v6 {
                    (ICMP6_TIME_EXCEEDED, ICMP6_DST_UNREACH)
                } else {
                    (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACH)
                };
                if error.ee_type == time_exceeded {
                    QueueEntry::Hop {
                        from,
                        terminal: false,
                    }
                } else if error.ee_type == unreachable {
                    QueueEntry::Hop {
                        from,
                        terminal: true,
                    }
                } else {
                    QueueEntry::Nothing
                }
            }
            SO_EE_ORIGIN_LOCAL => {
                QueueEntry::Failed(match i32::try_from(error.ee_errno).unwrap_or(0) {
                    libc::EACCES | libc::EPERM => error_code::PERMISSION_DENIED,
                    libc::ENETUNREACH => error_code::NETWORK_UNREACHABLE,
                    libc::EHOSTUNREACH => error_code::HOST_UNREACHABLE,
                    _ => error_code::INTERNAL_ERROR,
                })
            }
            _ => QueueEntry::Nothing,
        }
    }
}
