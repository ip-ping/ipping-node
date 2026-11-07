//! Runs one task: validate, acknowledge, resolve, probe, report.
//!
//! Everything the backend sends is treated as untrusted input. Options are range-checked, the
//! target goes through the local policy, and the task stops as soon as it is cancelled or
//! expires.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

mod dns;
mod http;
mod traceroute;

use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::policy::{Policy, validate_hostname};
use crate::probes::http::micros;
use crate::probes::{ConnectOutcome, EchoOutcome, Prober};
use crate::protocol::{
    Capabilities, ClientFrame, Family, ResultStatus, SampleStatus, Task, TaskKind, TaskOptions,
    error_code,
};
use crate::resolve::Resolve;

pub const MAX_COUNT: u32 = 10;
const INTERVAL_MS: std::ops::RangeInclusive<u64> = 200..=5_000;
pub(crate) const TIMEOUT_MS: std::ops::RangeInclusive<u64> = 200..=10_000;

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
        let job = Job {
            task_id: task.task_id.clone(),
            attempt_id: task.attempt_id.clone(),
            out,
            cancel,
        };

        if self.expired(&task) {
            job.fail(Failure::new(
                error_code::EXPIRED,
                "The task expired before it started.",
            ))
            .await;
            return;
        }
        if let Err(failure) = self.check(&task) {
            job.fail(failure).await;
            return;
        }
        if job.ack().await.is_err() {
            return;
        }

        // A DNS check asks about the name; it never resolves it for a probe of its own.
        if task.kind == TaskKind::Dns {
            self.run_dns(&task, &job).await;
            return;
        }

        let dns_started = Instant::now();
        let resolution = tokio::select! {
            () = job.cancel.cancelled() => return,
            resolution = self.resolve_target(&task) => resolution,
        };
        let dns = if task.target.hostname.is_some() {
            dns_started.elapsed()
        } else {
            Duration::ZERO
        };
        let (ip, resolved) = match resolution {
            Ok(found) => found,
            Err(failure) => {
                job.fail(failure).await;
                return;
            }
        };

        match task.kind {
            TaskKind::Ping | TaskKind::Tcp => self.run_series(&task, &job, ip, &resolved).await,
            TaskKind::Http => self.run_http(&task, &job, ip, &resolved, dns).await,
            TaskKind::Traceroute => self.run_traceroute(&task, &job, ip, &resolved).await,
            // Handled above, before any name is resolved; `check` has already refused the other.
            TaskKind::Dns | TaskKind::Unknown => {}
        }
    }

    /// Everything about a task that can be checked before touching the network.
    fn check(&self, task: &Task) -> Result<(), Failure> {
        let advertised = match task.kind {
            TaskKind::Ping => "ping",
            TaskKind::Tcp => "tcp",
            TaskKind::Http => "http",
            TaskKind::Traceroute => "traceroute",
            TaskKind::Dns => "dns",
            TaskKind::Unknown => "",
        };
        if !self.capabilities.kinds.iter().any(|k| k == advertised) {
            return Err(Failure::new(
                error_code::UNSUPPORTED_KIND,
                "This node does not run that kind of measurement.",
            ));
        }
        match task.kind {
            TaskKind::Ping => check_series_options(&task.options),
            TaskKind::Tcp => {
                check_series_options(&task.options)?;
                let port = task.target.port.unwrap_or(0);
                self.policy
                    .check_port(port)
                    .map(|_| ())
                    .map_err(|e| Failure::new(error_code::PORT_NOT_ALLOWED, e.to_string()))
            }
            TaskKind::Http => self.check_http(task),
            TaskKind::Traceroute => self.check_traceroute(task),
            TaskKind::Dns => self.dns_plan(task).map(|_| ()),
            TaskKind::Unknown => Err(Failure::new(
                error_code::UNSUPPORTED_KIND,
                "This node does not run that kind of measurement.",
            )),
        }
    }

    /// ping and tcp: a fixed number of attempts, one second (or so) apart, one sample each.
    async fn run_series(&self, task: &Task, job: &Job, ip: IpAddr, resolved: &[IpAddr]) {
        let options = &task.options;
        let ident: u16 = rand::random();
        let timeout = Duration::from_millis(options.timeout_ms);
        let interval = Duration::from_millis(options.interval_ms);
        let started = Instant::now();
        let mut failed_with: Option<&'static str> = None;
        let mut any_answer = false;

        for seq in 0..options.count {
            tokio::select! {
                () = job.cancel.cancelled() => return,
                () = sleep_until(started + interval * seq) => {}
            }
            if self.expired(task) {
                job.fail(Failure::new(
                    error_code::EXPIRED,
                    "The task expired while running.",
                ))
                .await;
                return;
            }
            let observation = tokio::select! {
                () = job.cancel.cancelled() => return,
                observation = self.attempt(task, ip, ident, seq, timeout) => observation,
            };
            if observation.answered {
                any_answer = true;
            } else {
                failed_with = observation.code;
            }
            if job
                .sample(
                    seq,
                    observation.status,
                    observation.rtt_us,
                    observation.code,
                )
                .await
                .is_err()
            {
                return;
            }
        }

        // If every attempt failed to even leave this host, say why instead of reporting 100% loss.
        match failed_with {
            Some(code) if !any_answer => {
                job.fail(Failure::new(code, "No probe could be sent."))
                    .await;
            }
            _ => job.completed(ip, resolved).await,
        }
    }

    async fn attempt(
        &self,
        task: &Task,
        ip: IpAddr,
        ident: u16,
        seq: u32,
        timeout: Duration,
    ) -> Observation {
        match task.kind {
            TaskKind::Tcp => {
                let port = task.target.port.unwrap_or(0);
                match self
                    .prober
                    .connect(SocketAddr::new(ip, port), timeout)
                    .await
                {
                    ConnectOutcome::Connected(rtt) => Observation::ok(rtt),
                    // The host answered, so the time is real; it is still not a connection.
                    ConnectOutcome::Refused(rtt) => Observation {
                        status: SampleStatus::Error,
                        rtt_us: Some(micros(rtt)),
                        code: Some(error_code::CONNECTION_REFUSED),
                        answered: true,
                    },
                    ConnectOutcome::Timeout => Observation::timeout(),
                    ConnectOutcome::Failed(code) => Observation::failed(code),
                }
            }
            _ => match self.prober.echo(ip, ident, seq as u16, timeout).await {
                EchoOutcome::Reply(rtt) => Observation::ok(rtt),
                EchoOutcome::Timeout => Observation::timeout(),
                EchoOutcome::Failed(code) => Observation::failed(code),
            },
        }
    }

    /// Turn the task's target into the one address that will be probed, applying the policy to
    /// every address involved. Returns that address and everything the name resolved to.
    async fn resolve_target(&self, task: &Task) -> Result<(IpAddr, Vec<IpAddr>), Failure> {
        let family = task.target.family;
        match (&task.target.ip, &task.target.hostname) {
            (Some(text), None) => {
                let ip = self
                    .policy
                    .parse_ip(text)
                    .map_err(|e| Failure::new(error_code::BLOCKED_BY_POLICY, e.to_string()))?;
                self.check_literal(ip, family)?;
                Ok((ip, vec![ip]))
            }
            (None, Some(host)) => {
                let host = validate_hostname(host)
                    .map_err(|e| Failure::new(error_code::BLOCKED_BY_POLICY, e.to_string()))?;
                self.resolve_name(&host, family).await
            }
            _ => Err(Failure::new(
                error_code::INTERNAL_ERROR,
                "A task needs exactly one of ip or hostname.",
            )),
        }
    }

    /// An address given as a literal: the family the task asked for, and one this node can reach.
    fn check_literal(&self, ip: IpAddr, family: Family) -> Result<(), Failure> {
        if !family_allows(family, &ip) || !self.node_can(&ip) {
            return Err(Failure::new(
                error_code::UNSUPPORTED_FAMILY,
                format!(
                    "This node cannot probe {ip} (IPv{}).",
                    if ip.is_ipv4() { 4 } else { 6 }
                ),
            ));
        }
        Ok(())
    }

    fn node_can(&self, ip: &IpAddr) -> bool {
        if ip.is_ipv4() {
            self.capabilities.ipv4
        } else {
            self.capabilities.ipv6
        }
    }

    /// Resolve a (validated) hostname here and pick the address to use. One non-public answer
    /// refuses the whole name, rather than quietly skipping it.
    async fn resolve_name(
        &self,
        host: &str,
        family: Family,
    ) -> Result<(IpAddr, Vec<IpAddr>), Failure> {
        let addresses = self.resolver.lookup(host).await.map_err(|e| {
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
        for ip in &addresses {
            self.policy
                .check_ip(*ip)
                .map_err(|e| Failure::new(error_code::BLOCKED_BY_POLICY, e.to_string()))?;
        }
        let usable = |want_v4: bool| {
            addresses.iter().copied().find(|ip| {
                ip.is_ipv4() == want_v4 && family_allows(family, ip) && self.node_can(ip)
            })
        };
        let chosen = usable(true).or_else(|| usable(false)).ok_or_else(|| {
            Failure::new(
                error_code::UNSUPPORTED_FAMILY,
                format!("{host} has no address this node can reach with the requested IP version."),
            )
        })?;
        Ok((chosen, addresses))
    }
}

fn family_allows(family: Family, ip: &IpAddr) -> bool {
    !matches!(
        (family, ip),
        (Family::V4, IpAddr::V6(_)) | (Family::V6, IpAddr::V4(_))
    )
}

fn check_series_options(options: &TaskOptions) -> Result<(), Failure> {
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

/// What one attempt of a series came to.
struct Observation {
    status: SampleStatus,
    rtt_us: Option<u64>,
    code: Option<&'static str>,
    /// Did something answer? A refusal did; a send failure did not.
    answered: bool,
}

impl Observation {
    fn ok(rtt: Duration) -> Self {
        Self {
            status: SampleStatus::Ok,
            rtt_us: Some(micros(rtt)),
            code: None,
            answered: true,
        }
    }
    fn timeout() -> Self {
        Self {
            status: SampleStatus::Timeout,
            rtt_us: None,
            code: None,
            answered: true,
        }
    }
    fn failed(code: &'static str) -> Self {
        Self {
            status: SampleStatus::Error,
            rtt_us: None,
            code: Some(code),
            answered: false,
        }
    }
}

/// The frames of one task, addressed with its ids.
struct Job {
    task_id: String,
    attempt_id: String,
    out: mpsc::Sender<ClientFrame>,
    cancel: CancellationToken,
}

/// The connection is gone: stop, there is nobody to tell.
struct Disconnected;

impl Job {
    async fn ack(&self) -> Result<(), Disconnected> {
        self.out
            .send(ClientFrame::TaskAck {
                task_id: self.task_id.clone(),
                attempt_id: self.attempt_id.clone(),
            })
            .await
            .map_err(|_| Disconnected)
    }

    async fn sample(
        &self,
        seq: u32,
        status: SampleStatus,
        rtt_us: Option<u64>,
        code: Option<&'static str>,
    ) -> Result<(), Disconnected> {
        self.sample_with(seq, status, rtt_us, code, None).await
    }

    async fn sample_with(
        &self,
        seq: u32,
        status: SampleStatus,
        rtt_us: Option<u64>,
        code: Option<&'static str>,
        detail: Option<serde_json::Value>,
    ) -> Result<(), Disconnected> {
        self.out
            .send(ClientFrame::Sample {
                task_id: self.task_id.clone(),
                attempt_id: self.attempt_id.clone(),
                seq,
                status,
                rtt_us,
                error_code: code.map(str::to_owned),
                detail,
            })
            .await
            .map_err(|_| Disconnected)
    }

    async fn completed(&self, ip: IpAddr, resolved: &[IpAddr]) {
        let _ = self
            .out
            .send(ClientFrame::TaskResult {
                task_id: self.task_id.clone(),
                attempt_id: self.attempt_id.clone(),
                status: ResultStatus::Completed,
                tested_ip: Some(ip.to_string()),
                resolved_ips: resolved.iter().map(ToString::to_string).collect(),
                error_code: None,
                error_message: None,
            })
            .await;
    }

    /// A DNS check ends without a tested address: what it learned is in its sample.
    async fn completed_with_answers(&self, resolved: &[IpAddr]) {
        let _ = self
            .out
            .send(ClientFrame::TaskResult {
                task_id: self.task_id.clone(),
                attempt_id: self.attempt_id.clone(),
                status: ResultStatus::Completed,
                tested_ip: None,
                resolved_ips: resolved.iter().map(ToString::to_string).collect(),
                error_code: None,
                error_message: None,
            })
            .await;
    }

    async fn fail(&self, failure: Failure) {
        let _ = self
            .out
            .send(ClientFrame::TaskResult {
                task_id: self.task_id.clone(),
                attempt_id: self.attempt_id.clone(),
                status: ResultStatus::Failed,
                tested_ip: None,
                resolved_ips: vec![],
                error_code: Some(failure.code.to_string()),
                error_message: Some(failure.message),
            })
            .await;
    }
}
