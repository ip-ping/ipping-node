//! Probe implementations. Each probe type has fixed semantics and hard limits; there is no
//! way to ask for a custom packet size, flood mode or a sweep.

pub mod icmp;

use std::future::Future;
use std::net::IpAddr;
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

/// Sends a single ICMP echo request and waits for its reply.
pub trait Prober: Send + Sync + 'static {
    fn echo(
        &self,
        ip: IpAddr,
        ident: u16,
        seq: u16,
        timeout: Duration,
    ) -> impl Future<Output = EchoOutcome> + Send;
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
