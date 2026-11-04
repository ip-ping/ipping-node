//! Real ICMP against the loopback interface. Skipped (not failed) on hosts that do not allow
//! this process to open ping sockets, such as some CI sandboxes.

use std::net::IpAddr;
use std::time::Duration;

use ipping_node::probes::icmp::IcmpProber;
use ipping_node::probes::{EchoOutcome, Prober};

#[tokio::test]
async fn loopback_echo_gets_a_reply() {
    let prober = IcmpProber::new();
    if !prober.has_any_socket() {
        eprintln!("skipped: this host does not allow ICMP sockets for this user");
        return;
    }
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    match prober.echo(ip, 0x1234, 1, Duration::from_secs(2)).await {
        EchoOutcome::Reply(rtt) => assert!(rtt < Duration::from_secs(1), "{rtt:?}"),
        other => panic!("expected a reply from loopback, got {other:?}"),
    }
}

#[tokio::test]
async fn capabilities_are_derived_from_what_the_host_can_do() {
    let prober = IcmpProber::new();
    let caps = prober.capabilities();
    assert_eq!(caps.kinds.is_empty(), !prober.has_any_socket());
    eprintln!("detected: {caps:?}");
}
