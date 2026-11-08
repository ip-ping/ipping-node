//! One HTTP request to one address, measured phase by phase.
//!
//! A small HTTP/1.1 client on purpose: the task is to *measure* a request, so every phase (connect,
//! TLS handshake, time to the response head) needs its own clock, the address is pinned by the
//! caller, and the body is never read. Redirects are not followed here; the runner decides, because
//! every hop has to pass the destination policy again.
//!
//! TLS is verified against the Mozilla roots. A certificate that fails verification still
//! completes the handshake, so its details can be reported, but **no request is sent over such a
//! connection**: the result is `tls_certificate_invalid` with what the certificate said.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring as ring_provider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore,
    SignatureScheme,
};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsConnector;

use super::ConnectOutcome;
use super::tcp::classify;
use super::tls::{Finding, MAX_NAME_BYTES, MAX_NAMES, TlsOutcome, TlsRequest};
use crate::protocol::error_code;

/// Longest response head the node will read. A server that sends more is not speaking HTTP to us.
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Longest `Location` the node will act on.
pub const MAX_LOCATION_BYTES: usize = 2048;
const USER_AGENT: &str = concat!("ipping-node/", env!("CARGO_PKG_VERSION"));

/// One request to one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub ip: IpAddr,
    pub port: u16,
    /// `Some(name)` means TLS, presenting `name` (a host name or an IP literal) as the server name.
    pub tls_name: Option<String>,
    /// What goes in the `Host` header.
    pub host_header: String,
    /// Request target: a path, and a query string if a redirect brought one.
    pub path: String,
    /// For the whole exchange, up to the end of the response head.
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshake {
    pub elapsed: Duration,
    pub info: TlsInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub version: &'static str,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub location: Option<String>,
    pub connect: Duration,
    pub tls: Option<TlsHandshake>,
    /// From sending the request to receiving the whole response head.
    pub ttfb: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpFailure {
    pub code: &'static str,
    pub message: String,
    pub connect: Option<Duration>,
    pub tls: Option<TlsHandshake>,
}

impl HttpFailure {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            connect: None,
            tls: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpOutcome {
    Response(HttpResponse),
    Timeout,
    Failed(HttpFailure),
}

/// What the sample's `detail` says about an HTTP request. Mirrors the backend's `HttpDetail`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HttpDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttfb_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<RedirectHop>,
}

/// A redirect that was followed, or that the node stopped at. Never carries a query string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedirectHop {
    pub status_code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_path: Option<String>,
    pub followed: bool,
}

pub fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Verifies like the normal web verifier, but never fails the handshake: it remembers why it
/// would have, so the certificate can be reported before the connection is dropped.
#[derive(Debug)]
struct Recording {
    inner: Arc<WebPkiServerVerifier>,
    failure: Arc<Mutex<Option<String>>>,
}

impl ServerCertVerifier for Recording {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if let Err(error) = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            *self.failure.lock().expect("verifier lock") = Some(describe_tls_error(&error));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn describe_tls_error(error: &TlsError) -> String {
    match error {
        TlsError::InvalidCertificate(
            CertificateError::Expired | CertificateError::ExpiredContext { .. },
        ) => "the certificate has expired".into(),
        TlsError::InvalidCertificate(
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. },
        ) => "the certificate is not valid yet".into(),
        TlsError::InvalidCertificate(CertificateError::UnknownIssuer) => {
            "the certificate was issued by an unknown authority".into()
        }
        TlsError::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        ) => "the certificate is not valid for this name".into(),
        TlsError::InvalidCertificate(CertificateError::Revoked) => {
            "the certificate was revoked".into()
        }
        other => clean(other.to_string().as_bytes(), 200),
    }
}

/// Printable ASCII only, shortened. Everything that came from the network goes through this
/// before it is reported.
fn clean(bytes: &[u8], max: usize) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .take(max)
        .collect()
}

pub struct HttpClient {
    provider: Arc<CryptoProvider>,
    verifier: Arc<WebPkiServerVerifier>,
}

impl HttpClient {
    pub fn new() -> Self {
        Self::with_roots(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    }

    /// Trust these roots instead of the Mozilla set (tests use this for their own CA).
    pub fn with_roots(roots: RootCertStore) -> Self {
        let provider = Arc::new(ring_provider::default_provider());
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .expect("the root store is not empty");
        Self { provider, verifier }
    }

    /// A client configuration that verifies like the web does but never fails the handshake over a bad
    /// certificate: the reason goes into `failure` instead.
    fn client_config(
        &self,
        failure: Arc<Mutex<Option<String>>>,
        alpn: Vec<Vec<u8>>,
    ) -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Recording {
                inner: self.verifier.clone(),
                failure,
            }))
            .with_no_client_auth();
        config.alpn_protocols = alpn;
        config
    }

    /// Connect and complete a TLS handshake, then read what the certificate says and hang up. No
    /// request is sent, over any connection, trusted or not.
    pub async fn handshake(&self, request: &TlsRequest) -> TlsOutcome {
        let deadline = Instant::now() + request.timeout;
        let started = Instant::now();
        let stream = match timeout_at(
            deadline,
            TcpStream::connect(SocketAddr::new(request.ip, request.port)),
        )
        .await
        {
            Err(_) => return TlsOutcome::Timeout,
            Ok(Err(error)) => {
                return match classify(&error, started.elapsed()) {
                    ConnectOutcome::Refused(_) => TlsOutcome::failed(
                        error_code::CONNECTION_REFUSED,
                        "Nothing accepts connections on that port.",
                    ),
                    ConnectOutcome::Timeout => TlsOutcome::Timeout,
                    ConnectOutcome::Failed(code) => TlsOutcome::failed(code, "Could not connect."),
                    ConnectOutcome::Connected(_) => unreachable!("classify is for errors"),
                };
            }
            Ok(Ok(stream)) => stream,
        };
        let connect = started.elapsed();
        let _ = stream.set_nodelay(true);
        let Ok(server_name) = ServerName::try_from(request.server_name.clone()) else {
            return TlsOutcome::failed(
                error_code::TLS_ERROR,
                "The server name is not valid for TLS.",
            );
        };
        let failure = Arc::new(Mutex::new(None));
        let connector = TlsConnector::from(Arc::new(self.client_config(failure.clone(), vec![])));
        let tls_started = Instant::now();
        let mut tls = match timeout_at(deadline, connector.connect(server_name, stream)).await {
            Err(_) => return TlsOutcome::Timeout,
            Ok(Err(error)) => {
                return TlsOutcome::Failed {
                    code: error_code::TLS_ERROR,
                    message: format!(
                        "The TLS handshake failed: {}",
                        clean(error.to_string().as_bytes(), 160)
                    ),
                    connect: Some(connect),
                };
            }
            Ok(Ok(tls)) => tls,
        };
        let handshake = tls_started.elapsed();
        let verify_error = failure.lock().expect("verifier lock").clone();
        let (info, names, chain) = {
            let connection = tls.get_ref().1;
            let (names, chain) = certificate_names(connection);
            (tls_info(connection, verify_error), names, chain)
        };
        // Say goodbye properly (a close_notify), but never wait for the other side to answer.
        let _ = timeout_at(Instant::now() + Duration::from_millis(200), tls.shutdown()).await;
        TlsOutcome::Handshake(Finding {
            connect,
            handshake,
            info,
            names,
            chain,
        })
    }

    pub async fn fetch(&self, request: &HttpRequest) -> HttpOutcome {
        let deadline = Instant::now() + request.timeout;
        let started = Instant::now();

        let addr = SocketAddr::new(request.ip, request.port);
        let stream = match timeout_at(deadline, TcpStream::connect(addr)).await {
            Err(_) => return HttpOutcome::Timeout,
            Ok(Err(error)) => {
                return match classify(&error, started.elapsed()) {
                    ConnectOutcome::Refused(_) => fail(
                        error_code::CONNECTION_REFUSED,
                        "Nothing accepts connections on that port.",
                    ),
                    ConnectOutcome::Timeout => HttpOutcome::Timeout,
                    ConnectOutcome::Failed(code) => fail(code, "Could not connect."),
                    ConnectOutcome::Connected(_) => unreachable!("classify is for errors"),
                };
            }
            Ok(Ok(stream)) => stream,
        };
        let connect = started.elapsed();
        let _ = stream.set_nodelay(true);

        match &request.tls_name {
            None => {
                self.exchange(stream, request, deadline, connect, None)
                    .await
            }
            Some(name) => {
                let tls_started = Instant::now();
                let failure = Arc::new(Mutex::new(None));
                let Ok(server_name) = ServerName::try_from(name.clone()) else {
                    return fail(
                        error_code::TLS_ERROR,
                        "The server name is not valid for TLS.",
                    );
                };
                let config = self.client_config(failure.clone(), vec![b"http/1.1".to_vec()]);
                let connector = TlsConnector::from(Arc::new(config));
                let tls = match timeout_at(deadline, connector.connect(server_name, stream)).await {
                    Err(_) => return HttpOutcome::Timeout,
                    Ok(Err(error)) => {
                        let mut failed = HttpFailure::new(
                            error_code::TLS_ERROR,
                            format!(
                                "The TLS handshake failed: {}",
                                clean(error.to_string().as_bytes(), 160)
                            ),
                        );
                        failed.connect = Some(connect);
                        return HttpOutcome::Failed(failed);
                    }
                    Ok(Ok(tls)) => tls,
                };
                let elapsed = tls_started.elapsed();
                let verify_error = failure.lock().expect("verifier lock").clone();
                let info = tls_info(tls.get_ref().1, verify_error.clone());
                let handshake = TlsHandshake { elapsed, info };
                if let Some(reason) = verify_error {
                    // Reported, not used: nothing is sent to a server we could not authenticate.
                    let mut failed = HttpFailure::new(error_code::TLS_CERTIFICATE_INVALID, reason);
                    failed.connect = Some(connect);
                    failed.tls = Some(handshake);
                    return HttpOutcome::Failed(failed);
                }
                self.exchange(tls, request, deadline, connect, Some(handshake))
                    .await
            }
        }
    }

    async fn exchange<S: AsyncRead + AsyncWriteExt + Unpin>(
        &self,
        mut stream: S,
        request: &HttpRequest,
        deadline: Instant,
        connect: Duration,
        tls: Option<TlsHandshake>,
    ) -> HttpOutcome {
        let text = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            request.path, request.host_header
        );
        let sent = Instant::now();
        match timeout_at(deadline, async {
            stream.write_all(text.as_bytes()).await?;
            stream.flush().await
        })
        .await
        {
            Err(_) => return HttpOutcome::Timeout,
            Ok(Err(_)) => {
                return with(
                    fail(
                        error_code::CONNECTION_RESET,
                        "The connection closed while sending the request.",
                    ),
                    connect,
                    tls,
                );
            }
            Ok(Ok(())) => {}
        }
        match read_head(&mut stream, deadline).await {
            Err(HeadError::Timeout) => HttpOutcome::Timeout,
            Err(HeadError::Closed) => with(
                fail(
                    error_code::CONNECTION_RESET,
                    "The server closed the connection before answering.",
                ),
                connect,
                tls,
            ),
            Err(HeadError::Invalid(reason)) => {
                with(fail(error_code::PROTOCOL_ERROR, reason), connect, tls)
            }
            Ok(head) => HttpOutcome::Response(HttpResponse {
                status: head.status,
                version: head.version,
                server: head.server,
                content_type: head.content_type,
                location: head.location,
                connect,
                tls,
                ttfb: sent.elapsed(),
            }),
        }
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

fn fail(code: &'static str, message: impl Into<String>) -> HttpOutcome {
    HttpOutcome::Failed(HttpFailure::new(code, message))
}

fn with(outcome: HttpOutcome, connect: Duration, tls: Option<TlsHandshake>) -> HttpOutcome {
    match outcome {
        HttpOutcome::Failed(mut failure) => {
            failure.connect = Some(connect);
            failure.tls = tls;
            HttpOutcome::Failed(failure)
        }
        other => other,
    }
}

fn tls_info(connection: &rustls::ClientConnection, verify_error: Option<String>) -> TlsInfo {
    let version = connection.protocol_version().map(|v| match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_owned(),
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_owned(),
        other => clean(format!("{other:?}").as_bytes(), 16),
    });
    let cipher = connection
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()));
    let mut info = TlsInfo {
        version,
        cipher,
        subject: None,
        issuer: None,
        not_before: None,
        not_after: None,
        verified: verify_error.is_none(),
        verify_error,
    };
    if let Some(leaf) = connection.peer_certificates().and_then(|c| c.first())
        && let Ok((_, certificate)) = x509_parser::parse_x509_certificate(leaf.as_ref())
    {
        info.subject = Some(clean(certificate.subject().to_string().as_bytes(), 200));
        info.issuer = Some(clean(certificate.issuer().to_string().as_bytes(), 200));
        let rfc3339 = |t: OffsetDateTime| t.format(&Rfc3339).ok();
        info.not_before = rfc3339(certificate.validity().not_before.to_datetime());
        info.not_after = rfc3339(certificate.validity().not_after.to_datetime());
    }
    info
}

/// The names the server's certificate is valid for, and how many certificates it sent. Only what fits
/// in a result is kept, and control characters are replaced.
fn certificate_names(connection: &rustls::ClientConnection) -> (Vec<String>, usize) {
    use x509_parser::extensions::GeneralName;

    let certificates = connection.peer_certificates().unwrap_or_default();
    let mut names = vec![];
    if let Some(leaf) = certificates.first()
        && let Ok((_, certificate)) = x509_parser::parse_x509_certificate(leaf.as_ref())
        && let Ok(Some(alternative)) = certificate.subject_alternative_name()
    {
        let mut bytes = 0;
        for name in &alternative.value.general_names {
            let text = match name {
                GeneralName::DNSName(dns) => clean(dns.as_bytes(), 255),
                GeneralName::IPAddress(raw) => match raw.len() {
                    4 => IpAddr::from(<[u8; 4]>::try_from(*raw).expect("four bytes")).to_string(),
                    16 => {
                        IpAddr::from(<[u8; 16]>::try_from(*raw).expect("sixteen bytes")).to_string()
                    }
                    _ => continue,
                },
                _ => continue,
            };
            bytes += text.len();
            if names.len() >= MAX_NAMES || bytes > MAX_NAME_BYTES {
                break;
            }
            names.push(text);
        }
    }
    (names, certificates.len())
}

struct Head {
    status: u16,
    version: &'static str,
    server: Option<String>,
    content_type: Option<String>,
    location: Option<String>,
}

enum HeadError {
    Timeout,
    Closed,
    Invalid(&'static str),
}

async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    deadline: Instant,
) -> Result<Head, HeadError> {
    let mut buffer: Vec<u8> = Vec::with_capacity(2048);
    loop {
        {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut response = httparse::Response::new(&mut headers);
            match response.parse(&buffer) {
                Ok(httparse::Status::Complete(_)) => {
                    let status = response
                        .code
                        .filter(|c| (100..=599).contains(c))
                        .ok_or(HeadError::Invalid("The status code is not valid."))?;
                    let find = |name: &str| {
                        response
                            .headers
                            .iter()
                            .find(|h| h.name.eq_ignore_ascii_case(name))
                            .map(|h| h.value)
                    };
                    let location = match find("location") {
                        Some(value) if value.len() > MAX_LOCATION_BYTES => {
                            return Err(HeadError::Invalid("The redirect target is too long."));
                        }
                        Some(value) => Some(String::from_utf8_lossy(value).trim().to_owned()),
                        None => None,
                    };
                    return Ok(Head {
                        status,
                        version: if response.version == Some(0) {
                            "HTTP/1.0"
                        } else {
                            "HTTP/1.1"
                        },
                        server: find("server").map(|v| clean(v, 100)),
                        content_type: find("content-type").map(|v| clean(v, 100)),
                        location,
                    });
                }
                Ok(httparse::Status::Partial) => {}
                Err(_) => return Err(HeadError::Invalid("The answer is not valid HTTP.")),
            }
        }
        if buffer.len() >= MAX_HEAD_BYTES {
            return Err(HeadError::Invalid("The response headers are too large."));
        }
        let mut chunk = [0u8; 2048];
        match timeout_at(deadline, stream.read(&mut chunk)).await {
            Err(_) => return Err(HeadError::Timeout),
            Ok(Err(_)) | Ok(Ok(0)) => return Err(HeadError::Closed),
            Ok(Ok(n)) => buffer.extend_from_slice(&chunk[..n]),
        }
    }
}
