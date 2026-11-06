//! Probe implementations. Each probe type has fixed semantics and hard limits; there is no
//! way to ask for a custom packet size, flood mode or a sweep.

pub mod http;
pub mod icmp;
pub mod system;
pub mod tcp;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::protocol::error_code;

/// What happened to one echo request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchoOutcome {
    /// A reply arrived after this round-trip time (measured on a monotonic clock).
    Reply(Duration),
    /// No reply within the per-packet timeout. This is the only outcome that counts as loss.
    Timeout,
    /// The echo could not be sent or read; the value is a protocol error code.
    Failed(&'static str),
}

/// What happened to one attempt to open a TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// The handshake completed after this long.
    Connected(Duration),
    /// The host answered, with a reset: nothing accepts connections on that port. The time is how
    /// long the refusal took to arrive.
    Refused(Duration),
    /// No answer within the timeout.
    Timeout,
    /// The attempt failed for another reason; the value is a protocol error code.
    Failed(&'static str),
}

/// The things a node can measure. Only `echo` has to be provided: a prober that lacks the others
/// (a test double, a platform without traceroute) answers "unsupported" and the runner reports it.
pub trait Prober: Send + Sync + 'static {
    /// Send one ICMP echo request and wait for its reply.
    fn echo(
        &self,
        ip: IpAddr,
        ident: u16,
        seq: u16,
        timeout: Duration,
    ) -> impl Future<Output = EchoOutcome> + Send;

    /// Open one TCP connection and close it again.
    fn connect(
        &self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> impl Future<Output = ConnectOutcome> + Send {
        let _ = (addr, timeout);
        async { ConnectOutcome::Failed(crate::protocol::error_code::UNSUPPORTED_KIND) }
    }

    /// Make one HTTP request to one address: connect, optionally TLS, send a GET, read the
    /// response head. Redirects are the runner's business, since each one needs the policy.
    fn http_once(
        &self,
        request: http::HttpRequest,
    ) -> impl Future<Output = http::HttpOutcome> + Send {
        let _ = request;
        async {
            http::HttpOutcome::Failed(http::HttpFailure::new(
                crate::protocol::error_code::UNSUPPORTED_KIND,
                "This node cannot make HTTP requests.",
            ))
        }
    }
}

/// Map an I/O error from sending an echo to the code the backend understands.
pub fn failure_code(error: &std::io::Error) -> &'static str {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::PermissionDenied => error_code::PERMISSION_DENIED,
        // No route for this IP version from this host.
        ErrorKind::NetworkUnreachable | ErrorKind::AddrNotAvailable => {
            error_code::UNSUPPORTED_FAMILY
        }
        _ => error_code::INTERNAL_ERROR,
    }
}
