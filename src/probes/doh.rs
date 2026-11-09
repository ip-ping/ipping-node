//! DNS over HTTPS (RFC 8484): the same question and the same answer as `dns.rs`, carried in an HTTPS GET.
//!
//! The query is the DNS message `dns.rs` builds (with id 0, as the RFC recommends for GET), base64url-encoded in
//! the `dns` parameter. The server's certificate is verified against the Mozilla roots for the name given, and a
//! certificate that does not verify ends the query before anything is sent. Only a resolver the backend names
//! (a public address, port 443) is ever asked.

use std::net::IpAddr;
use std::time::Duration;

use super::dns::{
    DnsAnswer, DnsOutcome, ParseError, RecordType, base64url, encode_query, parse_response,
};
use super::http::{BodyOutcome, BodyRequest, HttpClient};
use crate::protocol::error_code;

/// Where a DoH resolver listens: the name its certificate is for and the path of its query endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohTarget {
    pub host: String,
    pub path: String,
}

/// A DNS message is at most 64 KiB; resolvers answering over HTTPS stay far below that.
const MAX_BODY: usize = 16 * 1024;

/// Ask `ip` on `port` (443 for a real resolver) for `name`.
pub async fn query(
    client: &HttpClient,
    ip: IpAddr,
    port: u16,
    target: &DohTarget,
    name: &str,
    record_type: RecordType,
    limit: Duration,
) -> DnsOutcome {
    let Some(message) = encode_query(0, name, record_type) else {
        return DnsOutcome::Failed(error_code::INTERNAL_ERROR);
    };
    let started = tokio::time::Instant::now();
    let request = BodyRequest {
        ip,
        port,
        server_name: target.host.clone(),
        target: format!("{}?dns={}", target.path, base64url(&message)),
        accept: "application/dns-message",
        max_body: MAX_BODY,
        timeout: limit,
    };
    match client.get_body(&request).await {
        BodyOutcome::Timeout => DnsOutcome::Timeout,
        BodyOutcome::Failed { code, .. } => DnsOutcome::Failed(code),
        BodyOutcome::Response(response) => {
            if response.status != 200
                || !response.content_type.as_deref().is_some_and(|t| {
                    t.trim()
                        .to_ascii_lowercase()
                        .starts_with("application/dns-message")
                })
            {
                return DnsOutcome::Failed(error_code::PROTOCOL_ERROR);
            }
            match parse_response(&response.body, 0, name, record_type) {
                Ok(parsed) => DnsOutcome::Answer(DnsAnswer {
                    rtt: started.elapsed(),
                    rcode: parsed.rcode,
                    authoritative: parsed.authoritative,
                    via_tcp: false,
                    truncated: parsed.truncated,
                    records: parsed.records,
                }),
                Err(ParseError::Mismatch | ParseError::Malformed) => {
                    DnsOutcome::Failed(error_code::PROTOCOL_ERROR)
                }
            }
        }
    }
}
