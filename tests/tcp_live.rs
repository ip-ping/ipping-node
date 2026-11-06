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
