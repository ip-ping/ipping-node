//! The real HTTP client against servers on the loopback interface: plain, TLS with a test CA, and
//! deliberately broken ones.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipping_node::probes::http::{HttpClient, HttpOutcome, HttpRequest};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType, date_time_ymd,
};
use rustls::RootCertStore;
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

struct Server {
    port: u16,
    /// Everything the client sent after the handshake.
    received: Arc<Mutex<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl Server {
    async fn finish(self) -> Vec<u8> {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
        self.received.lock().unwrap().clone()
    }
}

/// Answers one connection with `reply`, then closes. `None` means "say nothing and wait".
async fn serve(tls: Option<TlsAcceptor>, reply: Option<Vec<u8>>) -> Server {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        async fn talk<S: AsyncReadExt + AsyncWriteExt + Unpin>(
            mut stream: S,
            reply: Option<Vec<u8>>,
            captured: Arc<Mutex<Vec<u8>>>,
        ) {
            let mut buffer = [0u8; 4096];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        let mut seen = captured.lock().unwrap();
                        seen.extend_from_slice(&buffer[..n]);
                        if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            match reply {
                Some(bytes) => {
                    let _ = stream.write_all(&bytes).await;
                    let _ = stream.shutdown().await;
                }
                None => tokio::time::sleep(Duration::from_secs(30)).await,
            }
        }
        match tls {
            Some(acceptor) => {
                if let Ok(stream) = acceptor.accept(stream).await {
                    talk(stream, reply, captured).await;
                }
            }
            None => talk(stream, reply, captured).await,
        }
    });
    Server {
        port,
        received,
        task,
    }
}

fn request(port: u16, tls_name: Option<&str>) -> HttpRequest {
    HttpRequest {
        ip: LOOPBACK,
        port,
        tls_name: tls_name.map(str::to_owned),
        host_header: "h.test".into(),
        path: "/p?x=1".into(),
        timeout: Duration::from_secs(5),
    }
}

const OK: &[u8] =
    b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";

// --- plain HTTP ------------------------------------------------------------------------------

#[tokio::test]
async fn a_plain_request_is_sent_as_documented_and_the_head_is_measured() {
    let server = serve(
        None,
        Some(b"HTTP/1.1 301 Moved\r\nServer: ng\xe9inx\r\nLocation: https://www.example.com/x\r\n\r\n".to_vec()),
    )
    .await;
    let outcome = HttpClient::new().fetch(&request(server.port, None)).await;
    let HttpOutcome::Response(response) = outcome else {
        panic!("expected a response, got {outcome:?}");
    };
    assert_eq!(response.status, 301);
    assert_eq!(response.version, "HTTP/1.1");
    assert_eq!(
        response.location.as_deref(),
        Some("https://www.example.com/x")
    );
    assert_eq!(
        response.server.as_deref(),
        Some("ng?inx"),
        "bytes outside printable ASCII are replaced"
    );
    assert!(response.tls.is_none());
    assert!(response.connect < Duration::from_secs(1) && response.ttfb < Duration::from_secs(1));

    let sent = String::from_utf8(server.finish().await).unwrap();
    assert!(
        sent.starts_with("GET /p?x=1 HTTP/1.1\r\nHost: h.test\r\n"),
        "{sent}"
    );
    assert!(sent.contains("\r\nConnection: close\r\n"));
    assert!(sent.contains("\r\nUser-Agent: ipping-node/"));
    assert!(sent.ends_with("\r\n\r\n"), "no body is sent");
}

#[tokio::test]
async fn broken_servers_are_reported_not_trusted() {
    let huge = {
        let mut bytes = b"HTTP/1.1 200 OK\r\n".to_vec();
        bytes.extend(
            std::iter::repeat_n(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n", 800).flatten(),
        );
        bytes
    };
    let cases: Vec<(&str, Option<Vec<u8>>, &str)> = vec![
        (
            "not HTTP",
            Some(b"SSH-2.0-OpenSSH_9.6\r\n\r\n".to_vec()),
            "protocol_error",
        ),
        ("huge head", Some(huge), "protocol_error"),
        (
            "bad status",
            Some(b"HTTP/1.1 999 Nope\r\n\r\n".to_vec()),
            "protocol_error",
        ),
        (
            "endless redirect target",
            Some(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: /{}\r\n\r\n",
                    "a".repeat(5000)
                )
                .into_bytes(),
            ),
            "protocol_error",
        ),
        ("hangs up", Some(Vec::new()), "connection_reset"),
    ];
    for (name, reply, code) in cases {
        let server = serve(None, reply).await;
        match HttpClient::new().fetch(&request(server.port, None)).await {
            HttpOutcome::Failed(failure) => assert_eq!(failure.code, code, "{name}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn silence_is_a_timeout_and_a_closed_port_is_a_refusal() {
    let server = serve(None, None).await;
    let mut slow = request(server.port, None);
    slow.timeout = Duration::from_millis(300);
    assert_eq!(HttpClient::new().fetch(&slow).await, HttpOutcome::Timeout);

    let closed = {
        let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    };
    match HttpClient::new().fetch(&request(closed, None)).await {
        HttpOutcome::Failed(failure) => assert_eq!(failure.code, "connection_refused"),
        other => panic!("{other:?}"),
    }
}

// --- TLS -------------------------------------------------------------------------------------

struct Pki {
    ca: Issuer<'static, KeyPair>,
    ca_der: rustls::pki_types::CertificateDer<'static>,
}

impl Pki {
    fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        let cert = params.clone().self_signed(&key).unwrap();
        Self {
            ca_der: cert.der().clone(),
            ca: Issuer::new(params, key),
        }
    }

    fn client(&self) -> HttpClient {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_der.clone()).unwrap();
        HttpClient::with_roots(roots)
    }

    /// A server that presents a certificate for these names, valid in the given years.
    async fn serve(&self, names: &[&str], ips: &[IpAddr], years: (i32, i32)) -> Server {
        let mut params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .unwrap();
        for ip in ips {
            params.subject_alt_names.push(SanType::IpAddress(*ip));
        }
        params
            .distinguished_name
            .push(DnType::CommonName, names.first().copied().unwrap_or("ip"));
        params.not_before = date_time_ymd(years.0, 1, 1);
        params.not_after = date_time_ymd(years.1, 1, 1);
        let key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&key, &self.ca).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            ring_provider::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
        serve(Some(TlsAcceptor::from(Arc::new(config))), Some(OK.to_vec())).await
    }
}

#[tokio::test]
async fn a_trusted_certificate_is_verified_and_described() {
    let pki = Pki::new();
    let server = pki.serve(&["example.test"], &[], (2024, 2099)).await;
    // The address is pinned; the name is what the certificate is checked against.
    let outcome = pki
        .client()
        .fetch(&request(server.port, Some("example.test")))
        .await;
    let HttpOutcome::Response(response) = outcome else {
        panic!("expected a response, got {outcome:?}");
    };
    assert_eq!(response.status, 200);
    let tls = response.tls.expect("a TLS handshake happened");
    assert!(tls.info.verified && tls.info.verify_error.is_none());
    assert_eq!(tls.info.version.as_deref(), Some("TLSv1.3"));
    assert!(
        tls.info
            .subject
            .as_deref()
            .unwrap()
            .contains("example.test")
    );
    assert!(tls.info.issuer.as_deref().unwrap().contains("Test CA"));
    assert!(
        tls.info
            .not_after
            .as_deref()
            .unwrap()
            .starts_with("2099-01-01")
    );
    assert!(tls.elapsed > Duration::ZERO);
    let sent = String::from_utf8(server.finish().await).unwrap();
    assert!(
        sent.starts_with("GET /p?x=1 HTTP/1.1\r\nHost: h.test\r\n"),
        "{sent}"
    );
}

#[tokio::test]
async fn an_address_certificate_is_checked_against_the_address() {
    let pki = Pki::new();
    let server = pki.serve(&[], &[LOOPBACK], (2024, 2099)).await;
    match pki
        .client()
        .fetch(&request(server.port, Some("127.0.0.1")))
        .await
    {
        HttpOutcome::Response(response) => assert!(response.tls.unwrap().info.verified),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn certificates_that_do_not_verify_are_described_but_nothing_is_sent_to_them() {
    let pki = Pki::new();
    let cases = [
        (
            "expired",
            pki.serve(&["example.test"], &[], (2015, 2016)).await,
            "example.test",
            "expired",
        ),
        (
            "wrong name",
            pki.serve(&["example.test"], &[], (2024, 2099)).await,
            "other.test",
            "not valid for this name",
        ),
    ];
    for (name, server, presented, reason) in cases {
        let outcome = pki
            .client()
            .fetch(&request(server.port, Some(presented)))
            .await;
        let HttpOutcome::Failed(failure) = outcome else {
            panic!("{name}: expected a failure, got {outcome:?}");
        };
        assert_eq!(failure.code, "tls_certificate_invalid", "{name}");
        assert!(
            failure.message.contains(reason),
            "{name}: {}",
            failure.message
        );
        let tls = failure.tls.expect("the certificate is still reported");
        assert!(!tls.info.verified, "{name}");
        assert!(
            tls.info
                .subject
                .as_deref()
                .unwrap()
                .contains("example.test"),
            "{name}"
        );
        assert!(failure.connect.is_some(), "{name}");
        assert!(
            server.finish().await.is_empty(),
            "{name}: no request may be sent over an unauthenticated connection"
        );
    }

    // Signed by an authority this node does not trust (the Mozilla roots do not include the test CA).
    let server = pki.serve(&["example.test"], &[], (2024, 2099)).await;
    match HttpClient::new()
        .fetch(&request(server.port, Some("example.test")))
        .await
    {
        HttpOutcome::Failed(failure) => {
            assert_eq!(failure.code, "tls_certificate_invalid");
            assert!(
                failure.message.contains("unknown authority"),
                "{}",
                failure.message
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn speaking_tls_to_a_plain_server_is_a_tls_error() {
    let pki = Pki::new();
    // A plain-HTTP server answers the TLS hello with an error page at once, as real ones do.
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = [0u8; 512];
        let _ = stream.read(&mut hello).await;
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await;
    });
    match pki
        .client()
        .fetch(&request(port, Some("example.test")))
        .await
    {
        HttpOutcome::Failed(failure) => assert_eq!(failure.code, "tls_error", "{failure:?}"),
        other => panic!("{other:?}"),
    }
}

// --- the whole thing: runner + real client --------------------------------------------------

mod end_to_end {
    use ipping_node::policy::Policy;
    use ipping_node::probes::system::SystemProber;
    use ipping_node::protocol::{Capabilities, ClientFrame, ServerFrame};
    use ipping_node::resolve::Resolve;
    use ipping_node::runner::Runner;
    use serde_json::json;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::*;

    struct NoDns;
    impl Resolve for NoDns {
        async fn lookup(&self, _: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(vec![])
        }
    }
    fn task(port: u16, max_redirects: u8) -> ipping_node::protocol::Task {
        let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(30);
        let frame = json!({
            "type": "task", "task_id": "t", "attempt_id": "a", "kind": "http",
            "target": {"ip": "127.0.0.1", "port": port},
            "options": {"timeout_ms": 5000, "scheme": "http", "path": "/start",
                        "max_redirects": max_redirects},
            "expires_at": expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
        });
        match serde_json::from_value(frame).unwrap() {
            ServerFrame::Task(task) => task,
            other => panic!("{other:?}"),
        }
    }

    async fn run(policy: Policy, task: ipping_node::protocol::Task) -> Vec<ClientFrame> {
        let capabilities = Capabilities {
            kinds: vec!["http".into()],
            ipv4: true,
            ipv6: true,
        };
        let runner = Runner::new(
            Arc::new(SystemProber::new()),
            Arc::new(NoDns),
            policy,
            capabilities,
        );
        let (tx, mut rx) = mpsc::channel(16);
        runner.run(task, tx, CancellationToken::new()).await;
        let mut frames = vec![];
        while let Ok(frame) = rx.try_recv() {
            frames.push(frame);
        }
        frames
    }

    #[tokio::test]
    async fn a_redirect_chain_is_followed_over_real_sockets() {
        let last = serve(None, Some(OK.to_vec())).await;
        let first = serve(
            None,
            Some(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/final?x=1\r\n\r\n",
                    last.port
                )
                .into_bytes(),
            ),
        )
        .await;
        let frames = run(Policy::permissive_for_tests(), task(first.port, 3)).await;
        let Some(ClientFrame::Sample {
            status,
            rtt_us,
            detail,
            ..
        }) = frames
            .iter()
            .find(|f| matches!(f, ClientFrame::Sample { .. }))
        else {
            panic!("no sample in {frames:?}")
        };
        assert_eq!(*status, ipping_node::protocol::SampleStatus::Ok);
        assert!(rtt_us.unwrap() > 0);
        let detail = detail.as_ref().unwrap();
        assert_eq!(detail["status_code"], 200);
        assert_eq!(detail["final_path"], "/final");
        assert_eq!(detail["redirects"][0]["followed"], true);
        assert!(!detail.to_string().contains("x=1"));
        assert!(
            String::from_utf8(last.finish().await)
                .unwrap()
                .starts_with("GET /final?x=1 ")
        );
    }

    #[tokio::test]
    async fn the_production_policy_never_touches_loopback() {
        // Port 8080 is on the allowlist, so it is the address that gets the task refused.
        let frames = run(Policy::public_only(), task(8080, 0)).await;
        assert_eq!(frames.len(), 2, "{frames:?}"); // ack, then a refusal
        let Some(ClientFrame::TaskResult { error_code, .. }) = frames.last() else {
            panic!("{frames:?}")
        };
        assert_eq!(error_code.as_deref(), Some("blocked_by_policy"));

        // A port outside the list is refused before anything else.
        let frames = run(Policy::public_only(), task(9200, 0)).await;
        assert_eq!(frames.len(), 1, "{frames:?}");
    }
}
