//! ICMP echo through the `surge-ping` crate.
//!
//! Unprivileged ping sockets (`SOCK_DGRAM`, governed by the `net.ipv4.ping_group_range` sysctl on
//! Linux) are tried first so the node needs no extra privileges; a raw socket, which needs
//! `CAP_NET_RAW`, is the fallback.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use socket2::Type as SocketType;
use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence, SurgeError};

use super::{ConnectOutcome, EchoOutcome, Prober, failure_code, tcp};
use crate::protocol::{Capabilities, error_code};

/// Fixed payload: 56 bytes, like the classic `ping`. Never configurable.
const PAYLOAD: [u8; 56] = [0x69; 56];

pub struct IcmpProber {
    v4: Option<Client>,
    v6: Option<Client>,
}

fn client_for(kind: ICMP) -> Option<Client> {
    for socket_type in [SocketType::DGRAM, SocketType::RAW] {
        let config = Config::builder()
            .kind(kind)
            .sock_type_hint(socket_type)
            .build();
        match Client::new(&config) {
            Ok(client) => return Some(client),
            Err(error) => tracing::debug!(?kind, ?socket_type, %error, "ICMP socket unavailable"),
        }
    }
    None
}

/// Does this host have a route to the public internet over this IP version? Connecting a UDP
/// socket performs the route lookup without sending a packet.
fn has_route(v6: bool) -> bool {
    let (bind, probe): (SocketAddr, SocketAddr) = if v6 {
        (
            "[::]:0".parse().unwrap(),
            "[2001:4860:4860::8888]:53".parse().unwrap(),
        )
    } else {
        ("0.0.0.0:0".parse().unwrap(), "8.8.8.8:53".parse().unwrap())
    };
    UdpSocket::bind(bind)
        .and_then(|socket| socket.connect(probe))
        .is_ok()
}

impl IcmpProber {
    pub fn new() -> Self {
        Self {
            v4: client_for(ICMP::V4),
            v6: client_for(ICMP::V6),
        }
    }

    /// What this node can actually do, checked rather than assumed: the sockets can be opened
    /// *and* there is a route for that IP version.
    pub fn capabilities(&self) -> Capabilities {
        Capabilities {
            // TCP needs nothing special; ping needs an ICMP socket.
            kinds: if self.v4.is_some() || self.v6.is_some() {
                vec!["ping".into(), "tcp".into()]
            } else {
                vec!["tcp".into()]
            },
            ipv4: self.v4.is_some() && has_route(false),
            ipv6: self.v6.is_some() && has_route(true),
        }
    }

    pub fn has_any_socket(&self) -> bool {
        self.v4.is_some() || self.v6.is_some()
    }
}

impl Default for IcmpProber {
    fn default() -> Self {
        Self::new()
    }
}

impl Prober for IcmpProber {
    async fn echo(&self, ip: IpAddr, ident: u16, seq: u16, timeout: Duration) -> EchoOutcome {
        let client = match ip {
            IpAddr::V4(_) => self.v4.as_ref(),
            IpAddr::V6(_) => self.v6.as_ref(),
        };
        let Some(client) = client else {
            return EchoOutcome::Failed(error_code::PERMISSION_DENIED);
        };
        let mut pinger = client.pinger(ip, PingIdentifier(ident)).await;
        pinger.timeout(timeout);
        match pinger.ping(PingSequence(seq), &PAYLOAD).await {
            Ok((_packet, rtt)) => EchoOutcome::Reply(rtt),
            Err(SurgeError::Timeout { .. }) => EchoOutcome::Timeout,
            Err(SurgeError::IOError(error)) => EchoOutcome::Failed(failure_code(&error)),
            Err(error) => {
                tracing::debug!(%error, "echo failed");
                EchoOutcome::Failed(error_code::INTERNAL_ERROR)
            }
        }
    }

    async fn connect(&self, addr: std::net::SocketAddr, timeout: Duration) -> ConnectOutcome {
        tcp::connect_once(addr, timeout).await
    }
}
