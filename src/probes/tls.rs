//! A TLS handshake on its own: connect, handshake, read the certificate, close. No request is sent,
//! so it works for any TLS service on an allowed port (a web server, a mail server) and says what
//! the certificate says: who it is for, who issued it, when it expires, and whether this node
//! trusts it.
//!
//! The handshake is done by [`HttpClient::handshake`](super::http::HttpClient::handshake), which
//! shares the HTTP check's verifier: the Mozilla roots, and a certificate that does not verify is
//! reported with its reason instead of failing the handshake.

use std::net::IpAddr;
use std::time::Duration;

use super::http::TlsInfo;

/// Most names of a certificate that are reported, and the most bytes they may add up to: a result has
/// to fit in the sample size the backend accepts.
pub const MAX_NAMES: usize = 24;
pub const MAX_NAME_BYTES: usize = 3000;

/// One handshake with one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRequest {
    pub ip: IpAddr,
    pub port: u16,
    /// The server name presented (SNI) and checked against the certificate: a host name or an IP literal.
    pub server_name: String,
    /// For the connection and the handshake together.
    pub timeout: Duration,
    /// Over QUIC (UDP, offering `h3`) instead of TLS over TCP.
    pub quic: bool,
}

/// What a completed handshake found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub connect: Duration,
    pub handshake: Duration,
    pub info: TlsInfo,
    /// The names the certificate is valid for (DNS names and addresses), as far as they fit.
    pub names: Vec<String>,
    /// How many certificates the server sent.
    pub chain: usize,
    /// The application protocol agreed (`h3` over QUIC); none for a TLS handshake that offered none.
    pub alpn: Option<String>,
}

// One outcome per check, so the size of the handshake variant does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsOutcome {
    Handshake(Finding),
    Failed {
        code: &'static str,
        message: String,
        connect: Option<Duration>,
    },
    Timeout,
}

impl TlsOutcome {
    pub fn failed(code: &'static str, message: impl Into<String>) -> Self {
        Self::Failed {
            code,
            message: message.into(),
            connect: None,
        }
    }
}
