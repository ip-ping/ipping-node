//! The real prober: what this host can actually do, assembled from the individual probes.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::dns::{self, DnsOutcome, DnsRequest};
use super::http::{HttpClient, HttpOutcome, HttpRequest};
use super::icmp::IcmpProber;
use super::tls::{TlsOutcome, TlsRequest};
use super::traceroute::{self, HopOutcome};
use super::{ConnectOutcome, EchoOutcome, Prober, tcp};
use crate::protocol::Capabilities;

pub struct SystemProber {
    icmp: IcmpProber,
    http: HttpClient,
}

impl SystemProber {
    pub fn new() -> Self {
        Self {
            icmp: IcmpProber::new(),
            http: HttpClient::new(),
        }
    }

    /// What this node can do, checked rather than assumed. TCP, HTTP and DNS need nothing special;
    /// ping needs an ICMP socket.
    pub fn capabilities(&self) -> Capabilities {
        let mut capabilities = self.icmp.capabilities();
        capabilities.kinds.push("tcp".into());
        capabilities.kinds.push("http".into());
        capabilities.kinds.push("tls".into());
        capabilities.kinds.push("dns".into());
        if traceroute::available(false) || traceroute::available(true) {
            capabilities.kinds.push("traceroute".into());
        }
        capabilities
    }

    pub fn has_any_socket(&self) -> bool {
        self.icmp.has_any_socket()
    }
}

impl Default for SystemProber {
    fn default() -> Self {
        Self::new()
    }
}

impl Prober for SystemProber {
    async fn echo(&self, ip: IpAddr, ident: u16, seq: u16, timeout: Duration) -> EchoOutcome {
        self.icmp.echo(ip, ident, seq, timeout).await
    }

    async fn connect(&self, addr: SocketAddr, timeout: Duration) -> ConnectOutcome {
        tcp::connect_once(addr, timeout).await
    }

    async fn hop(&self, ip: IpAddr, ttl: u8, seq: u16, timeout: Duration) -> HopOutcome {
        // The wait is a blocking poll(2), so it runs on the blocking pool.
        tokio::task::spawn_blocking(move || traceroute::probe(ip, ttl, seq, timeout))
            .await
            .unwrap_or(HopOutcome::Failed(
                crate::protocol::error_code::INTERNAL_ERROR,
            ))
    }

    async fn dns_query(&self, request: DnsRequest) -> DnsOutcome {
        match (&request.doh, request.resolver) {
            (Some(target), dns::Resolver::Server(ip)) => {
                super::doh::query(
                    &self.http,
                    ip,
                    443,
                    target,
                    &request.name,
                    request.record_type,
                    request.timeout,
                )
                .await
            }
            _ => dns::lookup(&request).await,
        }
    }

    async fn http_once(&self, request: HttpRequest) -> HttpOutcome {
        self.http.fetch(&request).await
    }

    async fn tls_once(&self, request: TlsRequest) -> TlsOutcome {
        self.http.handshake(&request).await
    }
}
