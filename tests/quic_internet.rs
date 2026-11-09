//! The QUIC handshake against real HTTP/3 servers. Needs the internet, so it is ignored by default:
//!
//!   cargo test --test quic_internet -- --ignored --nocapture

use std::net::ToSocketAddrs;
use std::time::Duration;

use ipping_node::probes::http::HttpClient;
use ipping_node::probes::tls::{TlsOutcome, TlsRequest};

async fn quic(host: &str) -> TlsOutcome {
    let ip = (host, 443).to_socket_addrs().unwrap().next().unwrap().ip();
    HttpClient::new()
        .quic_handshake(&TlsRequest {
            ip,
            port: 443,
            server_name: host.into(),
            timeout: Duration::from_secs(6),
            quic: true,
        })
        .await
}

#[tokio::test]
#[ignore = "needs the internet"]
async fn servers_that_speak_http3_are_reached_and_described() {
    // Only Cloudflare: from the development network Google's QUIC endpoints never answered, and neither did an
    // independent client (aioquic), so that is the network and not this client. Cloudflare answers every time.
    for host in ["www.cloudflare.com"] {
        let outcome = quic(host).await;
        let TlsOutcome::Handshake(found) = outcome else {
            panic!("{host}: no QUIC handshake: {outcome:?}");
        };
        println!(
            "{host:<20} verified={} alpn={:?} handshake={:?} issuer={} names={} chain={}",
            found.info.verified,
            found.alpn,
            found.handshake,
            found.info.issuer.as_deref().unwrap_or("?"),
            found.names.len(),
            found.chain
        );
        assert!(found.info.verified, "{host}: {:?}", found.info.verify_error);
        assert_eq!(found.alpn.as_deref(), Some("h3"), "{host}");
    }
}

/// What a server that does not offer HTTP/3 looks like (printed, not asserted: who offers it changes).
#[tokio::test]
#[ignore = "needs the internet"]
async fn a_server_without_http3_is_a_timeout_or_an_error() {
    let outcome = quic("github.com").await;
    println!("github.com: {outcome:?}");
    assert!(!matches!(outcome, TlsOutcome::Handshake(ref f) if f.alpn.as_deref() != Some("h3")));
}

/// Not an assertion: how often each host answers, to tell a flaky path from a broken client.
#[tokio::test]
#[ignore = "needs the internet"]
async fn how_often_each_host_answers() {
    for host in [
        "www.cloudflare.com",
        "www.google.com",
        "cloudflare-dns.com",
        "dns.google",
    ] {
        let mut line = String::new();
        for _ in 0..4 {
            line.push(match quic(host).await {
                TlsOutcome::Handshake(found) if found.alpn.as_deref() == Some("h3") => 'H',
                TlsOutcome::Handshake(_) => 'h',
                TlsOutcome::Timeout => 't',
                TlsOutcome::Failed { .. } => 'F',
            });
        }
        println!("{host:<20} {line}");
    }
}
