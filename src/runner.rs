//! Runs one task: validate, acknowledge, resolve, probe, report.
//!
//! Everything the backend sends is treated as untrusted input. Options are range-checked, the
//! target goes through the local policy, and the task stops as soon as it is cancelled or
//! expires.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::policy::{Policy, validate_hostname};
use crate::probes::{EchoOutcome, Prober};
use crate::protocol::{
    Capabilities, ClientFrame, Family, PingOptions, ResultStatus, SampleStatus, Task, error_code,
};
use crate::resolve::Resolve;

pub const MAX_COUNT: u32 = 10;
const INTERVAL_MS: std::ops::RangeInclusive<u64> = 200..=5_000;
const TIMEOUT_MS: std::ops::RangeInclusive<u64> = 200..=10_000;

/// A task failure: a protocol error code plus a short human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub struct Runner<P, R> {
    prober: Arc<P>,
    resolver: Arc<R>,
    policy: Policy,
    capabilities: Capabilities,
    /// Server clock minus local clock, so a node with a wrong clock does not misjudge expiry.
    clock_offset: time::Duration,
}

impl<P, R> Clone for Runner<P, R> {
    fn clone(&self) -> Self {
        Self {
            prober: self.prober.clone(),
            resolver: self.resolver.clone(),
            policy: self.policy,
            capabilities: self.capabilities.clone(),
            clock_offset: self.clock_offset,
        }
    }
}

impl<P: Prober, R: Resolve> Runner<P, R> {
    pub fn new(
        prober: Arc<P>,
        resolver: Arc<R>,
        policy: Policy,
        capabilities: Capabilities,
    ) -> Self {
        Self {
            prober,
            resolver,
            policy,
            capabilities,
            clock_offset: time::Duration::ZERO,
        }
    }

    pub fn with_clock_offset(mut self, offset: time::Duration) -> Self {
        self.clock_offset = offset;
        self
    }

    fn expired(&self, task: &Task) -> bool {
        OffsetDateTime::now_utc() + self.clock_offset >= task.expires_at
    }

    /// Execute `task`, sending frames to `out`. Returns when the task is finished, cancelled, or
    /// the connection (the receiving end of `out`) is gone.
    pub async fn run(&self, task: Task, out: mpsc::Sender<ClientFrame>, cancel: CancellationToken) {
        let ids = (task.task_id.clone(), task.attempt_id.clone());
        let fail = |failure: Failure| ClientFrame::TaskResult {
            task_id: ids.0.clone(),
            attempt_id: ids.1.clone(),
            status: ResultStatus::Failed,
            tested_ip: None,
            resolved_ips: vec![],
            error_code: Some(failure.code.to_string()),
            error_message: Some(failure.message),
        };

        if self.expired(&task) {
            let _ = out
                .send(fail(Failure::new(
                    error_code::EXPIRED,
                    "The task expired before it started.",
                )))
                .await;
            return;
        }
        if let Err(failure) = check_options(&task.options) {
            let _ = out.send(fail(failure)).await;
            return;
        }
        if out
            .send(ClientFrame::TaskAck {
                task_id: ids.0.clone(),
                attempt_id: ids.1.clone(),
            })
            .await
            .is_err()
        {
            return;
        }

        let resolution = tokio::select! {
            () = cancel.cancelled() => return,
            resolution = self.resolve_target(&task) => resolution,
        };
        let (ip, resolved) = match resolution {
            Ok(found) => found,
            Err(failure) => {
                let _ = out.send(fail(failure)).await;
                return;
            }
        };

        let options = task.options;
        let ident: u16 = rand::random();
        let timeout = Duration::from_millis(options.timeout_ms);
        let interval = Duration::from_millis(options.interval_ms);
        let started = Instant::now();
        let mut failed_with: Option<&'static str> = None;
        let mut any_ok = false;

        for seq in 0..options.count {
            tokio::select! {
                () = cancel.cancelled() => return,
                () = sleep_until(started + interval * seq) => {}
            }
            if self.expired(&task) {
                let _ = out
                    .send(fail(Failure::new(
                        error_code::EXPIRED,
                        "The task expired while running.",
                    )))
                    .await;
                return;
            }
            let outcome = tokio::select! {
                () = cancel.cancelled() => return,
                outcome = self.prober.echo(ip, ident, seq as u16, timeout) => outcome,
            };
            let (status, rtt_us, code) = match outcome {
                EchoOutcome::Reply(rtt) => {
                    any_ok = true;
                    // A reply that took longer than the timeout is not a reply.
                    (
                        SampleStatus::Ok,
                        Some(u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX)),
                        None,
                    )
                }
                EchoOutcome::Timeout => (SampleStatus::Timeout, None, None),
                EchoOutcome::Failed(code) => {
                    failed_with = Some(code);
                    (SampleStatus::Error, None, Some(code.to_string()))
                }
            };
            let frame = ClientFrame::Sample {
                task_id: ids.0.clone(),
                attempt_id: ids.1.clone(),
                seq,
                status,
                rtt_us,
                error_code: code,
            };
            if out.send(frame).await.is_err() {
                return;
            }
        }

        // If every echo failed to even leave this host, say why instead of reporting 100% loss.
        let result = match failed_with {
            Some(code) if !any_ok => fail(Failure::new(code, "No echo request could be sent.")),
            _ => ClientFrame::TaskResult {
                task_id: ids.0.clone(),
                attempt_id: ids.1.clone(),
                status: ResultStatus::Completed,
                tested_ip: Some(ip.to_string()),
                resolved_ips: resolved.iter().map(ToString::to_string).collect(),
                error_code: None,
                error_message: None,
            },
        };
        let _ = out.send(result).await;
    }

    /// Turn the task's target into the one address that will be probed, applying the policy to
    /// every address involved. Returns that address and everything the name resolved to.
    async fn resolve_target(&self, task: &Task) -> Result<(IpAddr, Vec<IpAddr>), Failure> {
        let caps = &self.capabilities;
        let family = task.target.family;
        let family_allows = |ip: &IpAddr| {
            !matches!(
                (family, ip),
                (Family::V4, IpAddr::V6(_)) | (Family::V6, IpAddr::V4(_))
            )
        };
        let node_can = |ip: &IpAddr| if ip.is_ipv4() { caps.ipv4 } else { caps.ipv6 };

        match (&task.target.ip, &task.target.hostname) {
            (Some(text), None) => {
                let ip = self
                    .policy
                    .parse_ip(text)
                    .map_err(|e| Failure::new(error_code::BLOCKED_BY_POLICY, e.to_string()))?;
                if !family_allows(&ip) || !node_can(&ip) {
                    return Err(Failure::new(
                        error_code::UNSUPPORTED_FAMILY,
                        format!(
                            "This node cannot probe {ip} (IPv{}).",
                            if ip.is_ipv4() { 4 } else { 6 }
                        ),
                    ));
                }
                Ok((ip, vec![ip]))
            }
            (None, Some(host)) => {
                let host = validate_hostname(host)
                    .map_err(|e| Failure::new(error_code::BLOCKED_BY_POLICY, e.to_string()))?;
                let addresses = self.resolver.lookup(&host).await.map_err(|e| {
                    Failure::new(
                        error_code::DNS_FAILURE,
                        format!("Could not resolve {host}: {e}"),
                    )
                })?;
                if addresses.is_empty() {
                    return Err(Failure::new(
                        error_code::DNS_FAILURE,
                        format!("{host} has no A or AAAA records."),
                    ));
                }
                // One non-public answer refuses the whole name, rather than quietly skipping it.
                for ip in &addresses {
                    self.policy
                        .check_ip(*ip)
                        .map_err(|e| Failure::new(error_code::BLOCKED_BY_POLICY, e.to_string()))?;
                }
                let usable = |want_v4: bool| {
                    addresses
                        .iter()
                        .copied()
                        .find(|ip| ip.is_ipv4() == want_v4 && family_allows(ip) && node_can(ip))
                };
                let chosen = usable(true).or_else(|| usable(false)).ok_or_else(|| {
                    Failure::new(
                        error_code::UNSUPPORTED_FAMILY,
                        format!("{host} has no address this node can reach with the requested IP version."),
                    )
                })?;
                Ok((chosen, addresses))
            }
            _ => Err(Failure::new(
                error_code::INTERNAL_ERROR,
                "A task needs exactly one of ip or hostname.",
            )),
        }
    }
}

fn check_options(options: &PingOptions) -> Result<(), Failure> {
    if !(1..=MAX_COUNT).contains(&options.count)
        || !INTERVAL_MS.contains(&options.interval_ms)
        || !TIMEOUT_MS.contains(&options.timeout_ms)
    {
        return Err(Failure::new(
            error_code::INTERNAL_ERROR,
            "Task options are outside this node's limits.",
        ));
    }
    Ok(())
}
