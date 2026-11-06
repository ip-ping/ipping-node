//! Turning the configured backend address into the URLs the node needs.
//!
//! The credential travels in an HTTP header, so a plain `http://` backend is refused unless it
//! is on this machine (development) or the operator opts in explicitly.

use std::env;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set by `--insecure` (or `IPPING_NODE_ALLOW_INSECURE=1`, which the command line reads too).
static ALLOW_INSECURE: AtomicBool = AtomicBool::new(false);

/// Permit a plain `http://` backend on another host: the credential then travels unencrypted.
pub fn allow_insecure(allowed: bool) {
    ALLOW_INSECURE.store(allowed, Ordering::Relaxed);
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UrlError {
    #[error("the server address must start with https:// (or http:// for a local backend)")]
    Scheme,
    #[error("the server address has no host")]
    Host,
    #[error(
        "refusing to send credentials over plain http:// to a remote host; use https://, or set \
         --insecure (or IPPING_NODE_ALLOW_INSECURE=1) if you understand the risk"
    )]
    Insecure,
}

struct Parts<'a> {
    secure: bool,
    authority: &'a str,
    host: &'a str,
}

fn parse(server: &str) -> Result<Parts<'_>, UrlError> {
    let server = server.trim().trim_end_matches('/');
    let (secure, rest) = if let Some(rest) = server.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = server.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(UrlError::Scheme);
    };
    // Only an origin is accepted: no path, query or userinfo.
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
        return Err(UrlError::Host);
    }
    let host = if let Some(stripped) = rest.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        rest.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return Err(UrlError::Host);
    }
    Ok(Parts {
        secure,
        authority: rest,
        host,
    })
}

fn is_local(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn check(parts: &Parts<'_>) -> Result<(), UrlError> {
    let allowed = ALLOW_INSECURE.load(Ordering::Relaxed)
        || env::var("IPPING_NODE_ALLOW_INSECURE")
            .is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    if !parts.secure && !is_local(parts.host) && !allowed {
        return Err(UrlError::Insecure);
    }
    Ok(())
}

/// `https://host/path` for ordinary requests.
pub fn http_url(server: &str, path: &str) -> Result<String, UrlError> {
    let parts = parse(server)?;
    check(&parts)?;
    Ok(format!(
        "{}://{}/{path}",
        if parts.secure { "https" } else { "http" },
        parts.authority
    ))
}

/// `wss://host/path` for the node connection.
pub fn ws_url(server: &str, path: &str) -> Result<String, UrlError> {
    let parts = parse(server)?;
    check(&parts)?;
    Ok(format!(
        "{}://{}/{path}",
        if parts.secure { "wss" } else { "ws" },
        parts.authority
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_http_and_websocket_urls() {
        assert_eq!(
            http_url("https://ping.example.com/", "api/v1/x").unwrap(),
            "https://ping.example.com/api/v1/x"
        );
        assert_eq!(
            ws_url("https://ping.example.com:8443", "api/v1/nodes/connect").unwrap(),
            "wss://ping.example.com:8443/api/v1/nodes/connect"
        );
        assert_eq!(
            ws_url("http://127.0.0.1:8000", "c").unwrap(),
            "ws://127.0.0.1:8000/c"
        );
        assert_eq!(
            ws_url("http://localhost:8000", "c").unwrap(),
            "ws://localhost:8000/c"
        );
        assert_eq!(
            ws_url("http://[::1]:8000", "c").unwrap(),
            "ws://[::1]:8000/c"
        );
    }

    #[test]
    fn rejects_unsafe_or_malformed_addresses() {
        assert_eq!(ws_url("ping.example.com", "c"), Err(UrlError::Scheme));
        assert_eq!(ws_url("ftp://ping.example.com", "c"), Err(UrlError::Scheme));
        assert_eq!(ws_url("https://", "c"), Err(UrlError::Scheme));
        assert_eq!(ws_url("https://:8000", "c"), Err(UrlError::Host));
        assert_eq!(
            ws_url("https://user:pw@ping.example.com", "c"),
            Err(UrlError::Host)
        );
        assert_eq!(
            ws_url("https://ping.example.com/base", "c"),
            Err(UrlError::Host)
        );
        assert_eq!(
            ws_url("http://ping.example.com", "c"),
            Err(UrlError::Insecure)
        );
    }
}
