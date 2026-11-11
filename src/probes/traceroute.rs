//! One traceroute probe: an ICMP echo request with a chosen TTL, and whoever answers.
//!
//! Linux only, and without privileges: an unprivileged ICMP "ping socket" (the same thing `ping`
//! uses, governed by `net.ipv4.ping_group_range`) with `IP_RECVERR` turned on. A router that drops
//! the packet because its TTL ran out sends back an ICMP "time exceeded"; the kernel hands that to
//! the socket's *error queue* together with the router's address, so no raw socket is needed. If the
//! packet reaches the destination, the echo reply arrives as normal data.
//!
//! Where the host does not let this user have ping sockets (a container whose `ping_group_range`
//! cannot be changed, an LXC for one) but the node holds `CAP_NET_RAW`, which is what the installer
//! falls back to for ping, a **raw ICMP socket** does the same job: the probe is built by hand with a
//! random identifier, and every ICMP message that arrives is looked at until one answers it (an echo
//! reply, or a time exceeded / unreachable that quotes our packet).
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

/// Can this host send traceroute probes over this IP version, with a ping socket or a raw one?
pub fn available(v6: bool) -> bool {
    unprivileged_available(v6) || raw_available(v6)
}

/// Can this user open an unprivileged ICMP socket that reports errors (`net.ipv4.ping_group_range`)?
pub fn unprivileged_available(v6: bool) -> bool {
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

/// Can this process open a raw ICMP socket (it holds `CAP_NET_RAW`)?
pub fn raw_available(v6: bool) -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::raw_socket(v6).is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = v6;
        false
    }
}

/// Why this host offers no traceroute, in a sentence an operator can act on, or `None` when it does.
pub fn why_unavailable() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if available(false) || available(true) {
            return None;
        }
        let ping = linux::socket(false).err().map(|e| e.to_string());
        let raw = linux::raw_socket(false).err().map(|e| e.to_string());
        Some(format!(
            "no ICMP socket is allowed for this user: an unprivileged one needs its group inside \
             net.ipv4.ping_group_range ({}), a raw one needs CAP_NET_RAW ({})",
            ping.unwrap_or_default(),
            raw.unwrap_or_default()
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some("traceroute needs Linux".to_owned())
    }
}

/// The same probe through a raw ICMP socket, whatever `ping_group_range` says: for where a ping socket
/// is refused, and for tests. Needs `CAP_NET_RAW`. Blocks the calling thread.
pub fn probe_raw(ip: IpAddr, ttl: u8, seq: u16, timeout: Duration) -> HopOutcome {
    #[cfg(target_os = "linux")]
    {
        linux::probe_raw(ip, ttl, seq, timeout)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ip, ttl, seq, timeout);
        HopOutcome::Failed(error_code::UNSUPPORTED_KIND)
    }
}

/// Send one echo request to `ip` with this TTL and wait for an answer: through an unprivileged ICMP
/// socket, or through a raw one where the first is refused. Blocks the calling thread.
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
        match socket(ip.is_ipv6()) {
            Ok(socket) => probe_on(&socket, ip, ttl, seq, timeout),
            // The host does not let this user have ping sockets: a raw socket may still be allowed.
            Err(error) if is_denied(&error) => probe_raw(ip, ttl, seq, timeout),
            Err(error) => HopOutcome::Failed(code_for(&error)),
        }
    }

    fn is_denied(error: &io::Error) -> bool {
        matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM))
    }

    fn probe_on(socket: &Socket, ip: IpAddr, ttl: u8, seq: u16, timeout: Duration) -> HopOutcome {
        let v6 = ip.is_ipv6();
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
                match read_error(socket, v6) {
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

    // ---- Through a raw ICMP socket (CAP_NET_RAW) -------------------------------------------------

    // From <linux/icmp.h> and <linux/icmpv6.h>: the receive filters of raw ICMP sockets, which are not
    // in the libc crate. A set bit in the mask means "drop this type".
    const SOL_RAW: libc::c_int = 255;
    const ICMP_FILTER: libc::c_int = 1;
    const SOL_ICMPV6: libc::c_int = 58;
    const ICMPV6_FILTER: libc::c_int = 1;

    /// A raw ICMP socket for this IP version. Needs `CAP_NET_RAW`.
    pub fn raw_socket(v6: bool) -> io::Result<Socket> {
        let (domain, protocol) = if v6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let socket = Socket::new(domain, Type::RAW, Some(protocol))?;
        // A raw socket is handed every ICMP message the host receives; only the three kinds that can
        // answer a probe are wanted. Not being able to say so is no reason to give up: the answers
        // are matched one by one anyway.
        if v6 {
            let mut mask = [u32::MAX; 8];
            for kind in [ICMP6_DST_UNREACH, ICMP6_TIME_EXCEEDED, ECHO_REPLY_V6] {
                mask[usize::from(kind >> 5)] &= !(1u32 << (kind & 31));
            }
            set_option(&socket, SOL_ICMPV6, ICMPV6_FILTER, &mask);
        } else {
            let wanted =
                (1u32 << ECHO_REPLY_V4) | (1 << ICMP_DEST_UNREACH) | (1 << ICMP_TIME_EXCEEDED);
            set_option(&socket, SOL_RAW, ICMP_FILTER, &!wanted);
        }
        socket.set_nonblocking(true)?;
        Ok(socket)
    }

    fn set_option<T>(socket: &Socket, level: libc::c_int, name: libc::c_int, value: &T) {
        // SAFETY: the descriptor is a live socket owned by `socket`, and the pointer and length
        // describe one `T` that outlives the call. The result is ignored on purpose (see the caller).
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                std::ptr::from_ref(value).cast(),
                size_of::<T>() as libc::socklen_t,
            );
        }
    }

    /// The Internet checksum (RFC 1071) of `data`.
    fn checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = data
            .chunks(2)
            .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !u16::try_from(sum).unwrap_or(0xffff)
    }

    /// What an ICMP message that reached a raw socket says about our probe.
    #[derive(Debug, PartialEq, Eq)]
    enum Answer {
        /// The destination's echo reply.
        Reached,
        /// A router's time exceeded, or (`terminal`) its "unreachable".
        Hop { terminal: bool },
    }

    /// Does `data`, as `recv` gave it, answer the probe with this identifier and sequence number?
    /// On IPv4 `data` is the whole IP packet; on IPv6 it is the ICMPv6 message alone. An error message
    /// quotes the start of the packet it is about, which is where our identifier is found. Anything
    /// else (someone else's ping, a different probe of ours) is `None`.
    fn answer(v6: bool, data: &[u8], ident: u16, seq: u16) -> Option<Answer> {
        let icmp = if v6 {
            data
        } else {
            data.get(usize::from(*data.first()? & 0x0f) * 4..)?
        };
        let (request, reply, time_exceeded, unreachable) = if v6 {
            (
                ECHO_REQUEST_V6,
                ECHO_REPLY_V6,
                ICMP6_TIME_EXCEEDED,
                ICMP6_DST_UNREACH,
            )
        } else {
            (
                ECHO_REQUEST_V4,
                ECHO_REPLY_V4,
                ICMP_TIME_EXCEEDED,
                ICMP_DEST_UNREACH,
            )
        };
        let ours = |echo: &[u8], kind: u8| {
            echo.len() >= 8
                && echo[0] == kind
                && echo[4..6] == ident.to_be_bytes()
                && echo[6..8] == seq.to_be_bytes()
        };
        let kind = *icmp.first()?;
        if kind == reply {
            return ours(icmp, reply).then_some(Answer::Reached);
        }
        if kind != time_exceeded && kind != unreachable {
            return None;
        }
        // 8 bytes of error header, then the packet that caused it.
        let quoted = icmp.get(8..)?;
        let echo = if v6 {
            // A fixed 40-byte header: our own probe carries no extension headers.
            quoted.get(40..)?
        } else {
            let header = usize::from(*quoted.first()? & 0x0f) * 4;
            quoted.get(header..)?
        };
        ours(echo, request).then_some(Answer::Hop {
            terminal: kind == unreachable,
        })
    }

    /// Wait until `fd` can be read or `wait` has passed: `Ok(true)` when it can.
    fn readable(fd: i32, wait: Duration) -> io::Result<bool> {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // Round up, so a wait never ends a millisecond early and busy-loops.
        let wait_ms = i32::try_from(wait.as_millis() + 1).unwrap_or(i32::MAX);
        // SAFETY: `poll` is one valid `pollfd` and the count says so.
        let ready = unsafe { libc::poll(&raw mut poll, 1, wait_ms) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(error)
            };
        }
        Ok(ready > 0)
    }

    pub fn probe_raw(ip: IpAddr, ttl: u8, seq: u16, timeout: Duration) -> HopOutcome {
        let v6 = ip.is_ipv6();
        let socket = match raw_socket(v6) {
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

        // Ours to fill in, unlike a ping socket's: the identifier tells our probe from everyone
        // else's ICMP, so it is random for each probe. The kernel adds the checksum of an ICMPv6
        // message on a raw socket, but not of an ICMPv4 one.
        let ident: u16 = rand::random();
        let mut packet = [0x69u8; PACKET_LEN];
        packet[..8].fill(0);
        packet[0] = if v6 { ECHO_REQUEST_V6 } else { ECHO_REQUEST_V4 };
        packet[4..6].copy_from_slice(&ident.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());
        if !v6 {
            let sum = checksum(&packet);
            packet[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        // `send_to`, not `connect`: a connected raw socket only receives from that address, and the
        // routers' errors come from other ones.
        let sent = Instant::now();
        if let Err(error) = socket.send_to(&packet, &SockAddr::from(SocketAddr::new(ip, 0))) {
            return HopOutcome::Failed(code_for(&error));
        }

        let deadline = sent + timeout;
        let mut buffer = [MaybeUninit::<u8>::uninit(); 1500];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return HopOutcome::Timeout;
            }
            match readable(socket.as_raw_fd(), remaining) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => return HopOutcome::Failed(code_for(&error)),
            }
            let elapsed = sent.elapsed();
            // Everything that arrived is looked at, and only the answer to this probe ends the wait.
            loop {
                let (n, from) = match socket.recv_from(&mut buffer) {
                    Ok(received) => received,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return HopOutcome::Failed(code_for(&error)),
                };
                // SAFETY: `recv_from` initialised the first `n` bytes.
                let data = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), n) };
                match answer(v6, data, ident, seq) {
                    Some(Answer::Reached) => {
                        return HopOutcome::Reply {
                            from: ip,
                            rtt: elapsed,
                            reached: true,
                            terminal: false,
                        };
                    }
                    Some(Answer::Hop { terminal }) => {
                        if let Some(router) = from.as_socket() {
                            return HopOutcome::Reply {
                                from: router.ip(),
                                rtt: elapsed,
                                reached: false,
                                terminal,
                            };
                        }
                    }
                    None => {}
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const IDENT: u16 = 0xbeef;
        const SEQ: u16 = 7;

        /// An echo request as we send it (ICMPv4 or ICMPv6), with this identifier.
        fn request(v6: bool, ident: u16, seq: u16) -> Vec<u8> {
            let mut packet = vec![0x69u8; PACKET_LEN];
            packet[..8].fill(0);
            packet[0] = if v6 { ECHO_REQUEST_V6 } else { ECHO_REQUEST_V4 };
            packet[4..6].copy_from_slice(&ident.to_be_bytes());
            packet[6..8].copy_from_slice(&seq.to_be_bytes());
            packet
        }

        /// The IPv4 packet a router sends: its own 20-byte header, the ICMP error, and the start of ours.
        fn v4_error(kind: u8, ident: u16, seq: u16) -> Vec<u8> {
            let mut packet = vec![
                0x45, 0, 0, 56, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 9,
            ];
            packet.extend([kind, 0, 0, 0, 0, 0, 0, 0]);
            let mut quoted = vec![
                0x45, 0, 0, 84, 0, 0, 0, 0, 1, 1, 0, 0, 10, 0, 0, 9, 8, 8, 8, 8,
            ];
            quoted.extend(&request(false, ident, seq)[..8]);
            packet.extend(quoted);
            packet
        }

        fn v6_error(kind: u8, ident: u16, seq: u16) -> Vec<u8> {
            let mut message = vec![kind, 0, 0, 0, 0, 0, 0, 0];
            let mut quoted = vec![0u8; 40];
            quoted[0] = 0x60;
            quoted[6] = 58;
            message.extend(quoted);
            message.extend(&request(true, ident, seq)[..8]);
            message
        }

        #[test]
        fn the_checksum_is_rfc_1071s() {
            // The worked example of RFC 1071, section 3: the sum is 0xddf2, so the checksum is 0x220d.
            assert_eq!(
                checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
                0x220d
            );
            // With the checksum in place the whole thing sums to zero.
            let mut packet = request(false, IDENT, SEQ);
            let sum = checksum(&packet);
            packet[2..4].copy_from_slice(&sum.to_be_bytes());
            assert_eq!(checksum(&packet), 0);
        }

        #[test]
        fn an_echo_reply_to_this_probe_is_the_destination() {
            let mut v4 = vec![
                0x45, 0, 0, 84, 0, 0, 0, 0, 64, 1, 0, 0, 8, 8, 8, 8, 10, 0, 0, 9,
            ];
            let mut reply = request(false, IDENT, SEQ);
            reply[0] = ECHO_REPLY_V4;
            v4.extend(&reply);
            assert_eq!(answer(false, &v4, IDENT, SEQ), Some(Answer::Reached));
            assert_eq!(
                answer(false, &v4, IDENT ^ 1, SEQ),
                None,
                "someone else's ping"
            );
            assert_eq!(
                answer(false, &v4, IDENT, SEQ + 1),
                None,
                "another probe of ours"
            );

            let mut v6 = request(true, IDENT, SEQ);
            v6[0] = ECHO_REPLY_V6;
            assert_eq!(answer(true, &v6, IDENT, SEQ), Some(Answer::Reached));
            assert_eq!(answer(true, &v6, IDENT, SEQ + 1), None);
        }

        #[test]
        fn a_router_that_quotes_this_probe_is_a_hop() {
            assert_eq!(
                answer(false, &v4_error(ICMP_TIME_EXCEEDED, IDENT, SEQ), IDENT, SEQ),
                Some(Answer::Hop { terminal: false })
            );
            assert_eq!(
                answer(false, &v4_error(ICMP_DEST_UNREACH, IDENT, SEQ), IDENT, SEQ),
                Some(Answer::Hop { terminal: true })
            );
            assert_eq!(
                answer(true, &v6_error(ICMP6_TIME_EXCEEDED, IDENT, SEQ), IDENT, SEQ),
                Some(Answer::Hop { terminal: false })
            );
            assert_eq!(
                answer(true, &v6_error(ICMP6_DST_UNREACH, IDENT, SEQ), IDENT, SEQ),
                Some(Answer::Hop { terminal: true })
            );
        }

        #[test]
        fn an_error_about_another_packet_is_not_an_answer() {
            assert_eq!(
                answer(
                    false,
                    &v4_error(ICMP_TIME_EXCEEDED, IDENT ^ 1, SEQ),
                    IDENT,
                    SEQ
                ),
                None
            );
            assert_eq!(
                answer(
                    false,
                    &v4_error(ICMP_TIME_EXCEEDED, IDENT, SEQ + 1),
                    IDENT,
                    SEQ
                ),
                None
            );
            assert_eq!(
                answer(
                    true,
                    &v6_error(ICMP6_TIME_EXCEEDED, IDENT ^ 1, SEQ),
                    IDENT,
                    SEQ
                ),
                None
            );
            // Neither an error nor a reply: a redirect, or someone's echo request.
            assert_eq!(answer(false, &v4_error(5, IDENT, SEQ), IDENT, SEQ), None);
            let mut ping = vec![
                0x45, 0, 0, 84, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 9, 8, 8, 8, 8,
            ];
            ping.extend(request(false, IDENT, SEQ));
            assert_eq!(
                answer(false, &ping, IDENT, SEQ),
                None,
                "an echo request is not an answer"
            );
        }

        #[test]
        fn truncated_or_empty_data_is_not_an_answer() {
            for length in 0..v4_error(ICMP_TIME_EXCEEDED, IDENT, SEQ).len() {
                let data = &v4_error(ICMP_TIME_EXCEEDED, IDENT, SEQ)[..length];
                assert_eq!(answer(false, data, IDENT, SEQ), None, "{length} bytes");
            }
            for length in 0..v6_error(ICMP6_TIME_EXCEEDED, IDENT, SEQ).len() {
                let data = &v6_error(ICMP6_TIME_EXCEEDED, IDENT, SEQ)[..length];
                assert_eq!(answer(true, data, IDENT, SEQ), None, "{length} bytes");
            }
            // A header length that points past the data.
            assert_eq!(answer(false, &[0x4f, 0, 0], IDENT, SEQ), None);
        }
    }
}
