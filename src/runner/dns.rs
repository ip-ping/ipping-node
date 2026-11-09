//! The DNS check: ask one resolver one question and report what it said.
//!
//! Who may be asked is limited: a public resolver the backend names (port 53, a public address) or
//! this host's own resolvers. What is shown is limited too: a node's own resolver may know names that
//! only exist inside the operator's network, so addresses it returns that are not public are counted
//! but never reported. A public resolver's answers are public data and are shown as they are.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use super::{Failure, Job, Runner, TIMEOUT_MS, micros};
use crate::policy::{is_public, validate_hostname};
use crate::probes::Prober;
use crate::probes::dns::{DnsAnswer, DnsOutcome, DnsRequest, RecordType, Resolver};
use crate::probes::doh::DohTarget;
use crate::protocol::{SampleStatus, Task, error_code};
use crate::resolve::Resolve;

/// The most a sample's detail may weigh once written as JSON. The backend drops a detail above 8 KiB, so
/// the node leaves some room and says the answer was cut short instead.
const MAX_DETAIL_BYTES: usize = 7000;

/// What the sample of a DNS check says. Mirrors the backend's `DnsDetail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsDetail {
    /// `system` or the address of the public resolver that was asked.
    pub resolver: String,
    pub record_type: &'static str,
    /// `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED` ...
    pub rcode: String,
    pub authoritative: bool,
    pub via_tcp: bool,
    /// `doh` when the question went over HTTPS; left out for plain DNS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<&'static str>,
    pub truncated: bool,
    pub answers: Vec<AnswerDetail>,
    /// Answers left out because they were private addresses from this node's own resolver.
    pub redacted: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnswerDetail {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub ttl: u32,
    pub data: String,
}

/// A DNS task after its options have been checked.
pub(super) struct DnsPlan {
    name: String,
    record_type: RecordType,
    resolver: Resolver,
    timeout: Duration,
    /// Ask over HTTPS (port 443) instead of UDP.
    doh: Option<DohTarget>,
}

/// A DoH endpoint path the node will put on the wire: visible ASCII path characters, no query (the node adds its own).
fn valid_doh_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 64
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'.' | b'-'))
}

fn out_of_limits() -> Failure {
    Failure::new(
        error_code::INTERNAL_ERROR,
        "Task options are outside this node's limits.",
    )
}

impl<P: Prober, R: Resolve> Runner<P, R> {
    pub(super) fn dns_plan(&self, task: &Task) -> Result<DnsPlan, Failure> {
        let options = &task.options;
        if !TIMEOUT_MS.contains(&options.timeout_ms) {
            return Err(out_of_limits());
        }
        let record_type = options
            .record_type
            .as_deref()
            .and_then(RecordType::parse)
            .ok_or_else(out_of_limits)?;
        let name = match (&task.target.hostname, &task.target.ip) {
            (Some(host), None) => validate_hostname(host)
                .map_err(|e| Failure::new(error_code::BLOCKED_BY_POLICY, e.to_string()))?,
            _ => {
                return Err(Failure::new(
                    error_code::INTERNAL_ERROR,
                    "A DNS task needs a name to ask about.",
                ));
            }
        };
        let resolver = match &options.resolver_ip {
            None => Resolver::System,
            Some(text) => Resolver::Server(
                self.policy
                    .parse_ip(text)
                    .map_err(|e| Failure::new(error_code::BLOCKED_BY_POLICY, e.to_string()))?,
            ),
        };
        let doh = match options.transport.as_deref() {
            None | Some("udp") => None,
            Some("doh") => {
                // DNS over HTTPS is asked of a named public resolver, never of this node's own ones.
                if !matches!(resolver, Resolver::Server(_)) {
                    return Err(out_of_limits());
                }
                let host = options.doh_host.as_deref().ok_or_else(out_of_limits)?;
                let host = validate_hostname(host)
                    .map_err(|e| Failure::new(error_code::BLOCKED_BY_POLICY, e.to_string()))?;
                let path = options.doh_path.as_deref().ok_or_else(out_of_limits)?;
                if !valid_doh_path(path) {
                    return Err(out_of_limits());
                }
                self.policy
                    .check_port(443)
                    .map_err(|e| Failure::new(error_code::PORT_NOT_ALLOWED, e.to_string()))?;
                Some(DohTarget {
                    host,
                    path: path.to_owned(),
                })
            }
            Some(_) => return Err(out_of_limits()),
        };
        Ok(DnsPlan {
            name,
            record_type,
            resolver,
            timeout: Duration::from_millis(options.timeout_ms),
            doh,
        })
    }

    pub(super) async fn run_dns(&self, task: &Task, job: &Job) {
        let plan = match self.dns_plan(task) {
            Ok(plan) => plan,
            Err(failure) => {
                job.fail(failure).await;
                return;
            }
        };
        let request = DnsRequest {
            name: plan.name.clone(),
            record_type: plan.record_type,
            resolver: plan.resolver,
            timeout: plan.timeout,
            doh: plan.doh.clone(),
        };
        let outcome = tokio::select! {
            () = job.cancel.cancelled() => return,
            outcome = self.prober.dns_query(request) => outcome,
        };
        if self.expired(task) {
            job.fail(Failure::new(
                error_code::EXPIRED,
                "The task expired while running.",
            ))
            .await;
            return;
        }
        match outcome {
            DnsOutcome::Answer(answer) => {
                let rtt_us = Some(micros(answer.rtt));
                let (detail, addresses) = describe(&plan, answer);
                let sent = job
                    .sample_with(
                        0,
                        SampleStatus::Ok,
                        rtt_us,
                        None,
                        serde_json::to_value(&detail).ok(),
                    )
                    .await;
                if sent.is_ok() {
                    job.completed_with_answers(&addresses).await;
                }
            }
            DnsOutcome::Timeout => {
                if job
                    .sample_with(0, SampleStatus::Timeout, None, None, None)
                    .await
                    .is_ok()
                {
                    job.completed_with_answers(&[]).await;
                }
            }
            DnsOutcome::Failed(code) => {
                let message = match code {
                    // Some resolvers (Quad9) answer DNS over HTTPS only over HTTP/2, which this node does not speak.
                    error_code::PROTOCOL_ERROR if plan.doh.is_some() => {
                        "The resolver did not answer the HTTPS query. Some resolvers require HTTP/2, which this node does not speak."
                    }
                    error_code::DNS_FAILURE => "This node has no resolver configured.",
                    error_code::CONNECTION_REFUSED => "The resolver refused the connection.",
                    error_code::UNSUPPORTED_FAMILY => "This node cannot reach that resolver.",
                    error_code::PROTOCOL_ERROR => "The resolver sent a reply that is not DNS.",
                    _ => "The question could not be asked.",
                };
                job.fail(Failure::new(code, message)).await;
            }
        }
    }
}

/// The sample's detail, and the public addresses the answer contained.
fn describe(plan: &DnsPlan, answer: DnsAnswer) -> (DnsDetail, Vec<IpAddr>) {
    // Only this node's own resolver can know a private network's names.
    let own_resolver = plan.resolver == Resolver::System;
    let mut redacted = 0;
    let mut addresses: Vec<IpAddr> = Vec::new();
    let mut answers = Vec::new();
    for record in &answer.records {
        if let Some(ip) = record.address {
            if own_resolver && !is_public(ip) {
                redacted += 1;
                continue;
            }
            if is_public(ip) && !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        answers.push(AnswerDetail {
            name: record.name.clone(),
            kind: record.kind.name(),
            ttl: record.ttl,
            data: record.data.clone(),
        });
    }
    let detail = DnsDetail {
        resolver: match plan.resolver {
            Resolver::System => "system".to_string(),
            Resolver::Server(ip) => ip.to_string(),
        },
        record_type: plan.record_type.name(),
        rcode: answer.rcode_name(),
        authoritative: answer.authoritative,
        via_tcp: answer.via_tcp,
        transport: plan.doh.as_ref().map(|_| "doh"),
        truncated: answer.truncated,
        answers,
        redacted,
    };
    let mut detail = detail;
    while detail.answers.len() > 1
        && serde_json::to_vec(&detail).map_or(0, |bytes| bytes.len()) > MAX_DETAIL_BYTES
    {
        detail.answers.pop();
        detail.truncated = true;
    }
    (detail, addresses)
}
