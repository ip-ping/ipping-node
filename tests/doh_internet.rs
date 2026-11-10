//! DNS over HTTPS against the three real public resolvers. Needs the internet, so it is ignored by default:
//!
//!   cargo test --test doh_internet -- --ignored --nocapture

use std::time::Duration;

use ipping_node::probes::dns::{DnsOutcome, RecordType};
use ipping_node::probes::doh::{DohTarget, query};
use ipping_node::probes::http::HttpClient;

#[tokio::test]
#[ignore = "needs the internet"]
async fn the_public_resolvers_answer_over_https() {
    let client = HttpClient::new();
    for (ip, host) in [
        ("1.1.1.1", "cloudflare-dns.com"),
        ("8.8.8.8", "dns.google"),
        ("9.9.9.9", "dns.quad9.net"),
    ] {
        let target = DohTarget {
            host: host.into(),
            path: "/dns-query".into(),
        };
        for record_type in [RecordType::A, RecordType::Txt] {
            let outcome = query(
                &client,
                ip.parse().unwrap(),
                443,
                &target,
                "example.com",
                record_type,
                Duration::from_secs(8),
            )
            .await;
            let DnsOutcome::Answer(answer) = outcome else {
                panic!("{host} {record_type:?}: {outcome:?}");
            };
            println!(
                "{host:<20} {record_type:?}: {} in {:?}, {} record(s), first: {}",
                answer.rcode_name(),
                answer.rtt,
                answer.records.len(),
                answer.records.first().map_or("-", |r| r.data.as_str())
            );
            assert_eq!(answer.rcode, 0, "{host}");
            assert!(!answer.records.is_empty(), "{host} {record_type:?}");
        }
        // a name that does not exist is an answer, as over UDP
        let DnsOutcome::Answer(missing) = query(
            &client,
            ip.parse().unwrap(),
            443,
            &target,
            "this-name-does-not-exist.invalid",
            RecordType::A,
            Duration::from_secs(8),
        )
        .await
        else {
            panic!("{host}: no answer for a missing name");
        };
        assert_eq!(missing.rcode_name(), "NXDOMAIN", "{host}");
    }
}

/// Quad9 answers DNS over HTTPS only over HTTP/2 (`505 HTTP Version Not Supported ... requires HTTP/2`). The node
/// offers `h2` and speaks it when the server picks it, so a resolver that needs it is no different from the others.
/// If this fails with a protocol error, Quad9 or the HTTP/2 client has changed.
#[tokio::test]
#[ignore = "needs the internet"]
async fn quad9_is_asked_over_http2() {
    let target = DohTarget {
        host: "dns.quad9.net".into(),
        path: "/dns-query".into(),
    };
    let outcome = query(
        &HttpClient::new(),
        "9.9.9.9".parse().unwrap(),
        443,
        &target,
        "example.com",
        RecordType::A,
        Duration::from_secs(8),
    )
    .await;
    let DnsOutcome::Answer(answer) = outcome else {
        panic!("quad9: {outcome:?}");
    };
    assert_eq!(answer.rcode, 0);
    assert!(!answer.records.is_empty());
}
