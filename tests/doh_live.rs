//! DNS over HTTPS against a real HTTPS server on loopback with a test CA: the query that goes out, the answer that
//! comes back (plain and chunked), and everything that must not work.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipping_node::probes::dns::{DnsOutcome, RecordType};
use ipping_node::probes::doh::{DohTarget, query};
use ipping_node::probes::http::HttpClient;
use ipping_node::protocol::error_code;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, date_time_ymd};
use rustls::RootCertStore;
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[derive(Clone, Copy)]
enum Reply {
    Answer { chunked: bool },
    Status(u16),
    WrongType,
    Garbage,
    Silent,
}

struct Server {
    port: u16,
    /// The request head the client sent.
    received: Arc<Mutex<String>>,
    task: JoinHandle<()>,
}

impl Server {
    async fn finish(self) -> String {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
        self.received.lock().unwrap().clone()
    }
}

fn base64url_decode(text: &str) -> Vec<u8> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        other => panic!("not base64url: {other}"),
    };
    let mut out = vec![];
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.bytes() {
        buffer = (buffer << 6) | u32::from(value(c));
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

/// The DNS reply to a query: same id and question, one A record, 192.0.2.55.
fn dns_answer(query: &[u8]) -> Vec<u8> {
    let mut end = 12;
    while query[end] != 0 {
        end += usize::from(query[end]) + 1;
    }
    let question = &query[12..end + 5];
    let mut reply = vec![query[0], query[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    reply.extend_from_slice(question);
    reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, 55]);
    reply
}

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

    async fn serve(&self, reply: Reply) -> Server {
        let mut params = CertificateParams::new(vec!["doh.test".to_owned()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "doh.test");
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2099, 1, 1);
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
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(String::new()));
        let captured = received.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let mut head = vec![];
            let mut buffer = [0u8; 2048];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => head.extend_from_slice(&buffer[..n]),
                }
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            *captured.lock().unwrap() = text.clone();
            let query = text
                .lines()
                .next()
                .and_then(|l| l.split("?dns=").nth(1))
                .and_then(|l| l.split(' ').next())
                .map(base64url_decode)
                .unwrap_or_default();
            let response: Vec<u8> = match reply {
                Reply::Answer { chunked: false } => {
                    let body = dns_answer(&query);
                    let mut r = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    r.extend_from_slice(&body);
                    r
                }
                Reply::Answer { chunked: true } => {
                    let body = dns_answer(&query);
                    let (a, b) = body.split_at(body.len() / 2);
                    let mut r = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        .to_vec();
                    for part in [a, b] {
                        r.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                        r.extend_from_slice(part);
                        r.extend_from_slice(b"\r\n");
                    }
                    r.extend_from_slice(b"0\r\n\r\n");
                    r
                }
                Reply::Status(code) => format!(
                    "HTTP/1.1 {code} Nope\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno"
                )
                .into_bytes(),
                Reply::WrongType => b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 6\r\nConnection: close\r\n\r\n<html>".to_vec(),
                Reply::Garbage => b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot a dns".to_vec(),
                Reply::Silent => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    return;
                }
            };
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        });
        Server {
            port,
            received,
            task,
        }
    }
}

fn target() -> DohTarget {
    DohTarget {
        host: "doh.test".into(),
        path: "/dns-query".into(),
    }
}

async fn ask(client: &HttpClient, port: u16) -> DnsOutcome {
    query(
        client,
        LOOPBACK,
        port,
        &target(),
        "www.example.com",
        RecordType::A,
        Duration::from_secs(5),
    )
    .await
}

#[tokio::test]
async fn a_question_goes_out_as_a_get_and_the_answer_is_read() {
    let pki = Pki::new();
    for chunked in [false, true] {
        let server = pki.serve(Reply::Answer { chunked }).await;
        let DnsOutcome::Answer(answer) = ask(&pki.client(), server.port).await else {
            panic!("expected an answer (chunked: {chunked})");
        };
        assert_eq!(answer.rcode, 0);
        assert_eq!(answer.records.len(), 1, "chunked: {chunked}");
        assert_eq!(answer.records[0].data, "192.0.2.55");
        assert_eq!(
            answer.records[0].address,
            Some("192.0.2.55".parse().unwrap())
        );
        assert!(!answer.via_tcp);
        assert!(answer.rtt > Duration::ZERO);

        let request = server.finish().await;
        let first = request.lines().next().unwrap();
        assert!(first.starts_with("GET /dns-query?dns="), "{first}");
        assert!(first.ends_with(" HTTP/1.1"), "{first}");
        assert!(
            request.contains("\r\nHost: doh.test\r\n"),
            "the certificate name is the Host: {request}"
        );
        assert!(
            request.contains("\r\nAccept: application/dns-message\r\n"),
            "{request}"
        );
        // the query in the URL is a DNS message with id 0 asking for www.example.com A
        let encoded = first
            .split("?dns=")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap();
        let message = base64url_decode(encoded);
        assert_eq!(&message[..2], &[0, 0], "id 0, as RFC 8484 recommends");
        assert!(
            message.windows(3).any(|w| w == b"www"),
            "the name is in the question"
        );
    }
}

#[tokio::test]
async fn an_error_status_a_wrong_content_type_or_garbage_is_a_protocol_error() {
    let pki = Pki::new();
    for reply in [
        Reply::Status(503),
        Reply::Status(404),
        Reply::WrongType,
        Reply::Garbage,
    ] {
        let server = pki.serve(reply).await;
        assert_eq!(
            ask(&pki.client(), server.port).await,
            DnsOutcome::Failed(error_code::PROTOCOL_ERROR)
        );
    }
}

#[tokio::test]
async fn a_certificate_that_does_not_verify_ends_the_query_before_anything_is_sent() {
    let pki = Pki::new();
    let server = pki.serve(Reply::Answer { chunked: false }).await;
    // The default client trusts the Mozilla roots, not this test CA.
    assert_eq!(
        ask(&HttpClient::new(), server.port).await,
        DnsOutcome::Failed(error_code::TLS_CERTIFICATE_INVALID)
    );
    assert_eq!(
        server.finish().await,
        "",
        "the question must not be sent to a server that cannot be trusted"
    );
}

#[tokio::test]
async fn a_certificate_for_another_name_is_refused_too() {
    let pki = Pki::new();
    let server = pki.serve(Reply::Answer { chunked: false }).await;
    let other = DohTarget {
        host: "other.test".into(),
        path: "/dns-query".into(),
    };
    let outcome = query(
        &pki.client(),
        LOOPBACK,
        server.port,
        &other,
        "www.example.com",
        RecordType::A,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        outcome,
        DnsOutcome::Failed(error_code::TLS_CERTIFICATE_INVALID)
    );
    assert_eq!(server.finish().await, "");
}

#[tokio::test]
async fn silence_is_a_timeout_and_a_closed_port_is_a_refusal() {
    let pki = Pki::new();
    let silent = pki.serve(Reply::Silent).await;
    let outcome = query(
        &pki.client(),
        LOOPBACK,
        silent.port,
        &target(),
        "www.example.com",
        RecordType::A,
        Duration::from_millis(400),
    )
    .await;
    assert_eq!(outcome, DnsOutcome::Timeout);

    let port = {
        let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    };
    assert_eq!(
        ask(&pki.client(), port).await,
        DnsOutcome::Failed(error_code::CONNECTION_REFUSED)
    );
}
