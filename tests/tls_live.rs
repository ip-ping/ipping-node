//! The real handshake against servers on the loopback interface: a test CA, certificates that are
//! right and wrong in different ways, and servers that are not speaking TLS at all.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipping_node::probes::http::HttpClient;
use ipping_node::probes::tls::{TlsOutcome, TlsRequest};
use ipping_node::protocol::error_code;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType, date_time_ymd,
};
use rustls::RootCertStore;
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncReadExt;
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

/// Accepts one connection, completes the handshake if it has a certificate, then reads until the
/// client hangs up. With no acceptor it just reads (a server that is not speaking TLS).
async fn serve(tls: Option<TlsAcceptor>, silent: bool) -> Server {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        if silent {
            tokio::time::sleep(Duration::from_secs(30)).await;
            return;
        }
        async fn drain<S: AsyncReadExt + Unpin>(mut stream: S, captured: Arc<Mutex<Vec<u8>>>) {
            let mut buffer = [0u8; 1024];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => captured.lock().unwrap().extend_from_slice(&buffer[..n]),
                }
            }
        }
        match tls {
            Some(acceptor) => {
                if let Ok(stream) = acceptor.accept(stream).await {
                    drain(stream, captured).await;
                }
            }
            // Say something that is not TLS, then wait for the client to give up.
            None => {
                use tokio::io::AsyncWriteExt;
                let mut stream = stream;
                let _ = stream.write_all(b"220 hello, this is not TLS\r\n").await;
                drain(stream, captured).await;
            }
        }
    });
    Server {
        port,
        received,
        task,
    }
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

    async fn serve(&self, names: &[String], ips: &[IpAddr], years: (i32, i32)) -> Server {
        let mut params = CertificateParams::new(names.to_vec()).unwrap();
        for ip in ips {
            params.subject_alt_names.push(SanType::IpAddress(*ip));
        }
        params.distinguished_name.push(
            DnType::CommonName,
            names.first().cloned().unwrap_or_else(|| "ip".into()),
        );
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
        serve(Some(TlsAcceptor::from(Arc::new(config))), false).await
    }
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|n| (*n).to_owned()).collect()
}

fn request(port: u16, server_name: &str) -> TlsRequest {
    TlsRequest {
        ip: LOOPBACK,
        port,
        server_name: server_name.into(),
        timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn a_trusted_certificate_is_described_and_no_request_is_sent() {
    let pki = Pki::new();
    let server = pki
        .serve(
            &names(&["example.test", "www.example.test"]),
            &[],
            (2024, 2099),
        )
        .await;
    let TlsOutcome::Handshake(found) = pki
        .client()
        .handshake(&request(server.port, "example.test"))
        .await
    else {
        panic!("expected a handshake");
    };
    assert!(found.info.verified && found.info.verify_error.is_none());
    assert_eq!(found.info.version.as_deref(), Some("TLSv1.3"));
    assert!(
        found
            .info
            .subject
            .as_deref()
            .unwrap()
            .contains("example.test")
    );
    assert!(found.info.issuer.as_deref().unwrap().contains("Test CA"));
    assert!(
        found
            .info
            .not_after
            .as_deref()
            .unwrap()
            .starts_with("2099-01-01")
    );
    assert_eq!(found.names, names(&["example.test", "www.example.test"]));
    assert_eq!(found.chain, 1);
    assert!(found.connect > Duration::ZERO && found.handshake > Duration::ZERO);
    // The client hung up without sending anything after the handshake: no request, over any protocol.
    assert!(server.finish().await.is_empty());
}

#[tokio::test]
async fn an_address_certificate_names_its_addresses() {
    let pki = Pki::new();
    let server = pki.serve(&[], &[LOOPBACK], (2024, 2099)).await;
    let TlsOutcome::Handshake(found) = pki
        .client()
        .handshake(&request(server.port, "127.0.0.1"))
        .await
    else {
        panic!("expected a handshake");
    };
    assert!(found.info.verified, "{:?}", found.info.verify_error);
    assert_eq!(found.names, names(&["127.0.0.1"]));
}

#[tokio::test]
async fn a_certificate_for_another_name_completes_the_handshake_and_says_why_it_is_not_trusted() {
    let pki = Pki::new();
    let server = pki
        .serve(&names(&["example.test"]), &[], (2024, 2099))
        .await;
    let TlsOutcome::Handshake(found) = pki
        .client()
        .handshake(&request(server.port, "other.test"))
        .await
    else {
        panic!("expected a handshake");
    };
    assert!(!found.info.verified);
    let reason = found.info.verify_error.as_deref().unwrap();
    assert!(reason.to_lowercase().contains("name"), "{reason}");
    // What the certificate is for is exactly what the reader needs to see.
    assert_eq!(found.names, names(&["example.test"]));
    assert!(found.info.subject.is_some());
}

#[tokio::test]
async fn an_expired_certificate_is_reported_with_its_dates() {
    let pki = Pki::new();
    let server = pki
        .serve(&names(&["example.test"]), &[], (2019, 2020))
        .await;
    let TlsOutcome::Handshake(found) = pki
        .client()
        .handshake(&request(server.port, "example.test"))
        .await
    else {
        panic!("expected a handshake");
    };
    assert!(!found.info.verified);
    assert!(
        found
            .info
            .verify_error
            .as_deref()
            .unwrap()
            .to_lowercase()
            .contains("expired"),
        "{:?}",
        found.info.verify_error
    );
    assert!(
        found
            .info
            .not_after
            .as_deref()
            .unwrap()
            .starts_with("2020-01-01")
    );
}

#[tokio::test]
async fn a_certificate_from_an_unknown_issuer_is_not_trusted() {
    let pki = Pki::new();
    let server = pki
        .serve(&names(&["example.test"]), &[], (2024, 2099))
        .await;
    // The default client trusts the Mozilla roots, not this test CA.
    let TlsOutcome::Handshake(found) = HttpClient::new()
        .handshake(&request(server.port, "example.test"))
        .await
    else {
        panic!("expected a handshake");
    };
    assert!(!found.info.verified);
    assert!(found.info.verify_error.is_some());
}

#[tokio::test]
async fn only_as_many_names_as_fit_are_reported() {
    let pki = Pki::new();
    let many: Vec<String> = (0..60).map(|i| format!("host{i}.example.test")).collect();
    let server = pki.serve(&many, &[], (2024, 2099)).await;
    let TlsOutcome::Handshake(found) = pki
        .client()
        .handshake(&request(server.port, "host0.example.test"))
        .await
    else {
        panic!("expected a handshake");
    };
    assert_eq!(found.names.len(), 24, "{:?}", found.names);
    assert_eq!(found.names[0], "host0.example.test");
}

#[tokio::test]
async fn speaking_tls_to_a_plain_server_is_a_tls_error_and_a_closed_port_is_a_refusal() {
    let plain = serve(None, false).await;
    match HttpClient::new()
        .handshake(&request(plain.port, "example.test"))
        .await
    {
        TlsOutcome::Failed { code, connect, .. } => {
            assert_eq!(code, error_code::TLS_ERROR);
            assert!(connect.is_some(), "the connection itself worked");
        }
        other => panic!("expected a TLS error, got {other:?}"),
    }

    // Find a port nobody listens on.
    let port = {
        let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    };
    match HttpClient::new()
        .handshake(&request(port, "example.test"))
        .await
    {
        TlsOutcome::Failed { code, .. } => assert_eq!(code, error_code::CONNECTION_REFUSED),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn silence_is_a_timeout() {
    let silent = serve(None, true).await;
    let mut slow = request(silent.port, "example.test");
    slow.timeout = Duration::from_millis(300);
    assert_eq!(
        HttpClient::new().handshake(&slow).await,
        TlsOutcome::Timeout
    );
}
