//! The QUIC handshake against a real QUIC server on loopback (the transport of HTTP/3): the certificate and the
//! protocol it agrees to, a certificate that is wrong, a server that does not speak h3, and one that never answers.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use ipping_node::probes::http::HttpClient;
use ipping_node::probes::tls::{TlsOutcome, TlsRequest};
use ipping_node::protocol::error_code;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, date_time_ymd};
use rustls::RootCertStore;
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

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

    /// A QUIC server for these names that offers these application protocols. Keeps the endpoint alive by returning it.
    fn serve(&self, names: &[&str], alpn: &[&[u8]]) -> (quinn::Endpoint, u16) {
        let mut params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .unwrap();
        params.distinguished_name.push(DnType::CommonName, names[0]);
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2099, 1, 1);
        let key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&key, &self.ca).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
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
        tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            (LOOPBACK, 0).into(),
        )
        .unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let accepting = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                tokio::spawn(async move {
                    if let Ok(connection) = incoming.await {
                        connection.closed().await;
                    }
                });
            }
        });
        (endpoint, port)
    }
}

fn request(port: u16, name: &str) -> TlsRequest {
    TlsRequest {
        ip: LOOPBACK,
        port,
        server_name: name.into(),
        timeout: Duration::from_secs(5),
        quic: true,
    }
}

#[tokio::test]
async fn a_trusted_certificate_over_quic_is_described_with_the_protocol_agreed() {
    let pki = Pki::new();
    let (_server, port) = pki.serve(&["example.test", "www.example.test"], &[b"h3"]);
    let TlsOutcome::Handshake(found) = pki
        .client()
        .quic_handshake(&request(port, "example.test"))
        .await
    else {
        panic!("expected a handshake");
    };
    assert!(
        found.info.verified && found.info.verify_error.is_none(),
        "{:?}",
        found.info.verify_error
    );
    assert_eq!(found.alpn.as_deref(), Some("h3"));
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
    assert_eq!(
        found.names,
        vec!["example.test".to_owned(), "www.example.test".to_owned()]
    );
    assert_eq!(found.chain, 1);
    assert!(found.handshake > Duration::ZERO);
}

#[tokio::test]
async fn a_certificate_that_does_not_verify_is_still_described_with_its_reason() {
    let pki = Pki::new();
    let (_server, port) = pki.serve(&["example.test"], &[b"h3"]);
    // the default client trusts the Mozilla roots, not this test CA
    let TlsOutcome::Handshake(untrusted) = HttpClient::new()
        .quic_handshake(&request(port, "example.test"))
        .await
    else {
        panic!("expected a handshake");
    };
    assert!(!untrusted.info.verified && untrusted.info.verify_error.is_some());
    assert_eq!(untrusted.alpn.as_deref(), Some("h3"));
    // and a certificate for another name
    let TlsOutcome::Handshake(wrong) = pki
        .client()
        .quic_handshake(&request(port, "other.test"))
        .await
    else {
        panic!("expected a handshake");
    };
    assert!(!wrong.info.verified);
    assert!(
        wrong
            .info
            .verify_error
            .as_deref()
            .unwrap()
            .to_lowercase()
            .contains("name")
    );
    assert_eq!(wrong.names, vec!["example.test".to_owned()]);
}

#[tokio::test]
async fn a_server_that_does_not_speak_h3_ends_the_handshake_with_an_error() {
    let pki = Pki::new();
    let (_server, port) = pki.serve(&["example.test"], &[b"h2"]);
    match pki
        .client()
        .quic_handshake(&request(port, "example.test"))
        .await
    {
        TlsOutcome::Failed { code, message, .. } => {
            assert_eq!(code, error_code::TLS_ERROR);
            assert!(message.contains("QUIC handshake failed"), "{message}");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[tokio::test]
async fn a_udp_port_that_never_answers_is_a_timeout() {
    // bound, so nothing is refused, and silent
    let socket = UdpSocket::bind((LOOPBACK, 0)).unwrap();
    let mut silent = request(socket.local_addr().unwrap().port(), "example.test");
    silent.timeout = Duration::from_millis(700);
    assert_eq!(
        HttpClient::new().quic_handshake(&silent).await,
        TlsOutcome::Timeout
    );
}
