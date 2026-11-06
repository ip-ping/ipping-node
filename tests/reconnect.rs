//! How quickly the node comes back, depending on why the connection was refused.
//!
//! A fake backend answers the WebSocket upgrade with an HTTP error and counts the attempts.
//! After every real backend update the proxy in front of it answers 502 for a while; the node must
//! keep trying at the normal pace then, and only back off for a minute when the credential itself
//! is refused (401 or 403).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ipping_node::connection::{self, Settings};
use ipping_node::policy::Policy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

async fn attempts_in(answer: &'static str, window: Duration) -> usize {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(
                    format!("HTTP/1.1 {answer}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await;
        }
    });

    let shutdown = CancellationToken::new();
    let node = tokio::spawn(connection::run(
        Settings {
            server: format!("http://127.0.0.1:{port}"),
            credential: "not-a-real-credential".into(),
            max_concurrent_tasks: 1,
            policy: Policy::public_only(),
        },
        shutdown.clone(),
    ));
    tokio::time::sleep(window).await;
    shutdown.cancel();
    let _ = node.await;
    count.load(Ordering::SeqCst)
}

#[tokio::test]
async fn a_restarting_backend_is_retried_within_seconds() {
    // The first attempt is immediate and the next follows after about a second.
    for answer in [
        "502 Bad Gateway",
        "503 Service Unavailable",
        "504 Gateway Timeout",
    ] {
        let attempts = attempts_in(answer, Duration::from_millis(2600)).await;
        assert!(
            attempts >= 2,
            "{answer}: only {attempts} attempt(s) in 2.6 s"
        );
    }
}

#[tokio::test]
async fn a_refused_credential_is_not_hammered() {
    for answer in ["401 Unauthorized", "403 Forbidden"] {
        let attempts = attempts_in(answer, Duration::from_millis(2600)).await;
        assert_eq!(
            attempts, 1,
            "{answer}: the node should wait a minute before trying again"
        );
    }
}
