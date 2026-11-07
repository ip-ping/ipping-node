//! Wire protocol, version 1.
//!
//! JSON text frames over a WebSocket the node opens. The backend repository owns the
//! definition (`contracts/node-protocol-v1.schema.json`); `tests/fixtures/` holds copies of its
//! example frames, and `tests/protocol_fixtures.rs` keeps these types in agreement with them.
//!
//! Unknown fields are ignored on receipt so either side can add optional fields without a new
//! protocol version.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const PROTOCOL_VERSION: u32 = 1;

/// Longest frame the node will accept from the backend.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Frames sent by the node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    Hello {
        protocol_versions: Vec<u32>,
        node_version: String,
        capabilities: Capabilities,
    },
    TaskAck {
        task_id: String,
        attempt_id: String,
    },
    Sample {
        task_id: String,
        attempt_id: String,
        seq: u32,
        status: SampleStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rtt_us: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_code: Option<String>,
        /// What only some kinds have: an HTTP response's timings and certificate, a traceroute
        /// hop. Plain JSON on the wire; the backend validates it against the task's kind.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<serde_json::Value>,
    },
    TaskResult {
        task_id: String,
        attempt_id: String,
        status: ResultStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tested_ip: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        resolved_ips: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_message: Option<String>,
    },
    Ping,
}

/// Frames sent by the backend.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    Welcome(Welcome),
    Task(Task),
    Cancel { task_id: String },
    Pong,
    Error { code: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Capabilities {
    pub kinds: Vec<String>,
    pub ipv4: bool,
    pub ipv6: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleStatus {
    Ok,
    Timeout,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Pending,
    Approved,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Welcome {
    pub protocol_version: u32,
    pub node_id: String,
    pub node_status: NodeStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub server_time: OffsetDateTime,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_s: u64,
    #[serde(default)]
    pub limits: Limits,
}

fn default_heartbeat() -> u64 {
    15
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Limits {
    #[serde(default = "default_max_tasks")]
    pub max_concurrent_tasks: usize,
    #[serde(default = "default_max_count")]
    pub max_count: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: default_max_tasks(),
            max_count: default_max_count(),
        }
    }
}

fn default_max_tasks() -> usize {
    8
}

fn default_max_count() -> u32 {
    10
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Task {
    pub task_id: String,
    pub attempt_id: String,
    pub kind: TaskKind,
    pub target: Target,
    pub options: TaskOptions,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Ping,
    Tcp,
    Http,
    Traceroute,
    Dns,
    /// A kind from a newer backend. The task is answered with `unsupported_kind`, not dropped.
    #[serde(other)]
    Unknown,
}

/// Exactly one of `ip` (probe this address) or `hostname` (resolve it here) is set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Target {
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub family: Family,
    /// Destination port of a tcp or http task.
    #[serde(default)]
    pub port: Option<u16>,
    /// The name an http task presents (Host header, TLS server name) while connecting to `ip`.
    #[serde(default)]
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum Family {
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "4")]
    V4,
    #[serde(rename = "6")]
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Http,
    Https,
}

/// Settings of a task. Which ones matter depends on the kind: ping and tcp use `count`,
/// `interval_ms` and `timeout_ms`; http uses `scheme`, `path`, `timeout_ms` (for the whole request,
/// redirects included) and `max_redirects`; traceroute uses `max_hops` and `timeout_ms` (per hop);
/// dns uses `record_type`, `resolver_ip` and `timeout_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TaskOptions {
    #[serde(default = "default_count")]
    pub count: u32,
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
    pub timeout_ms: u64,
    #[serde(default)]
    pub scheme: Option<Scheme>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub max_redirects: Option<u8>,
    #[serde(default)]
    pub max_hops: Option<u8>,
    /// dns: the record type to ask for (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`).
    #[serde(default)]
    pub record_type: Option<String>,
    /// dns: ask this public resolver (port 53). Absent means the node's own resolvers.
    #[serde(default)]
    pub resolver_ip: Option<String>,
}

fn default_count() -> u32 {
    1
}

fn default_interval_ms() -> u64 {
    1000
}

impl Default for TaskOptions {
    fn default() -> Self {
        Self {
            count: default_count(),
            interval_ms: default_interval_ms(),
            timeout_ms: 2000,
            scheme: None,
            path: None,
            max_redirects: None,
            max_hops: None,
            record_type: None,
            resolver_ip: None,
        }
    }
}

/// Error codes a task can fail with (the backend maps unknown ones to `internal_error`).
pub mod error_code {
    pub const DNS_FAILURE: &str = "dns_failure";
    pub const UNSUPPORTED_FAMILY: &str = "unsupported_family";
    pub const BLOCKED_BY_POLICY: &str = "blocked_by_policy";
    pub const PERMISSION_DENIED: &str = "permission_denied";
    pub const NODE_BUSY: &str = "node_busy";
    pub const EXPIRED: &str = "expired";
    pub const INTERNAL_ERROR: &str = "internal_error";
    pub const UNSUPPORTED_KIND: &str = "unsupported_kind";
    pub const PORT_NOT_ALLOWED: &str = "port_not_allowed";

    // Codes a single sample can carry.
    pub const TIMEOUT: &str = "timeout";
    pub const CONNECTION_REFUSED: &str = "connection_refused";
    pub const CONNECTION_RESET: &str = "connection_reset";
    pub const HOST_UNREACHABLE: &str = "host_unreachable";
    pub const NETWORK_UNREACHABLE: &str = "network_unreachable";
    pub const TLS_ERROR: &str = "tls_error";
    pub const TLS_CERTIFICATE_INVALID: &str = "tls_certificate_invalid";
    pub const PROTOCOL_ERROR: &str = "protocol_error";
    pub const TOO_MANY_REDIRECTS: &str = "too_many_redirects";
    pub const REDIRECT_BLOCKED: &str = "redirect_blocked";
}
