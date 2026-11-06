//! One TCP connection attempt: how long the handshake takes, or why there is none.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};

use super::ConnectOutcome;
use crate::protocol::error_code;

/// Connect, measure, and drop the connection without sending a byte.
pub async fn connect_once(addr: SocketAddr, limit: Duration) -> ConnectOutcome {
    let started = Instant::now();
    match timeout(limit, TcpStream::connect(addr)).await {
        Err(_) => ConnectOutcome::Timeout,
        Ok(Ok(stream)) => {
            let elapsed = started.elapsed();
            drop(stream);
            ConnectOutcome::Connected(elapsed)
        }
        Ok(Err(error)) => classify(&error, started.elapsed()),
    }
}

/// Turn a failed connect into what it means for a diagnostic: a refusal is an answer from the
/// host, an unreachable route is a failure of the path.
pub fn classify(error: &std::io::Error, elapsed: Duration) -> ConnectOutcome {
    match error.kind() {
        ErrorKind::ConnectionRefused => ConnectOutcome::Refused(elapsed),
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => {
            ConnectOutcome::Failed(error_code::CONNECTION_RESET)
        }
        ErrorKind::TimedOut => ConnectOutcome::Timeout,
        ErrorKind::HostUnreachable => ConnectOutcome::Failed(error_code::HOST_UNREACHABLE),
        ErrorKind::NetworkUnreachable | ErrorKind::AddrNotAvailable => {
            ConnectOutcome::Failed(error_code::NETWORK_UNREACHABLE)
        }
        ErrorKind::PermissionDenied => ConnectOutcome::Failed(error_code::PERMISSION_DENIED),
        _ => ConnectOutcome::Failed(error_code::INTERNAL_ERROR),
    }
}
