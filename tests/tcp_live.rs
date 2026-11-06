//! Real TCP against the loopback interface.

use std::time::Duration;

use ipping_node::probes::ConnectOutcome;
use ipping_node::probes::tcp::connect_once;
use tokio::net::TcpListener;

#[tokio::test]
async fn an_open_port_connects_and_a_closed_one_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let open = listener.local_addr().unwrap();

    match connect_once(open, Duration::from_secs(2)).await {
        ConnectOutcome::Connected(rtt) => assert!(rtt < Duration::from_secs(1), "{rtt:?}"),
        other => panic!("expected a connection, got {other:?}"),
    }

    // Closing the listener frees the port; nothing accepts on it any more.
    drop(listener);
    match connect_once(open, Duration::from_secs(2)).await {
        ConnectOutcome::Refused(rtt) => assert!(rtt < Duration::from_secs(1), "{rtt:?}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn ipv6_works_the_same_over_the_loopback_interface() {
    // Skipped where the host has no IPv6 loopback.
    let Ok(listener) = TcpListener::bind("[::1]:0").await else {
        eprintln!("skipped: no IPv6 loopback on this host");
        return;
    };
    let open = listener.local_addr().unwrap();
    assert!(matches!(
        connect_once(open, Duration::from_secs(2)).await,
        ConnectOutcome::Connected(_)
    ));
    drop(listener);
    assert!(matches!(
        connect_once(open, Duration::from_secs(2)).await,
        ConnectOutcome::Refused(_)
    ));
}
