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
    pub options: PingOptions,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Ping,
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
pub struct PingOptions {
    pub count: u32,
    pub interval_ms: u64,
    pub timeout_ms: u64,
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
}
