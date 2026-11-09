//! The certificate check: one TLS handshake with the target, and what the certificate says.
//!
//! No request is sent. The sample is `ok` when the certificate verifies against the Mozilla roots for
//! the name presented; a certificate that does not (expired, wrong name, unknown issuer) is an
//! `error` with `tls_certificate_invalid`, and the detail still says what the certificate was, so the
//! result can show why. The days left are not worked out here: the node reports `not_after` and the
//! reader knows what day it is.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;
use tokio::time::Instant;

use super::{Failure, Job, Runner, micros};
use crate::probes::Prober;
use crate::probes::http::TlsInfo;
use crate::probes::tls::{TlsOutcome, TlsRequest};
use crate::protocol::{SampleStatus, Task, error_code};
use crate::resolve::Resolve;

/// What a certificate check's sample says. Mirrors the backend's `TlsDetail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsDetail {
    pub server_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    /// How many certificates the server sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<u32>,
    /// `quic` when the handshake was QUIC; left out for TLS over TCP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<&'static str>,
    /// The application protocol agreed (`h3` over QUIC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
}

impl<P: Prober, R: Resolve> Runner<P, R> {
    pub(super) fn check_tls(&self, task: &Task) -> Result<(), Failure> {
        if !matches!(
            task.options.transport.as_deref(),
            None | Some("tcp" | "quic")
        ) || !super::TIMEOUT_MS.contains(&task.options.timeout_ms)
        {
            return Err(Failure::new(
                error_code::INTERNAL_ERROR,
                "Task options are outside this node's limits.",
            ));
        }
        self.policy
            .check_port(task.target.port.unwrap_or(0))
            .map_err(|e| Failure::new(error_code::PORT_NOT_ALLOWED, e.to_string()))?;
        self.presented_host(task).map(|_| ())
    }

    pub(super) async fn run_tls(
        &self,
        task: &Task,
        job: &Job,
        ip: IpAddr,
        resolved: &[IpAddr],
        dns: Duration,
    ) {
        let (Some(port), Ok(server_name)) = (task.target.port, self.presented_host(task)) else {
            job.fail(Failure::new(
                error_code::INTERNAL_ERROR,
                "Invalid tls task.",
            ))
            .await;
            return;
        };
        let started = Instant::now();
        let request = TlsRequest {
            ip,
            port,
            server_name: server_name.clone(),
            timeout: Duration::from_millis(task.options.timeout_ms),
            quic: task.options.transport.as_deref() == Some("quic"),
        };
        let quic = request.quic;
        let outcome = tokio::select! {
            () = job.cancel.cancelled() => return,
            outcome = self.prober.tls_once(request) => outcome,
        };
        let total = micros(dns + started.elapsed());
        let mut detail = TlsDetail {
            server_name,
            connect_us: None,
            tls_us: None,
            total_us: Some(total),
            tls: None,
            names: vec![],
            chain: None,
            transport: quic.then_some("quic"),
            alpn: None,
        };
        let (status, code, rtt_us) = match outcome {
            TlsOutcome::Timeout => (SampleStatus::Timeout, None, None),
            TlsOutcome::Failed { code, connect, .. } => {
                detail.connect_us = connect.map(micros);
                (SampleStatus::Error, Some(code), None)
            }
            TlsOutcome::Handshake(found) => {
                detail.connect_us = Some(micros(found.connect));
                detail.tls_us = Some(micros(found.handshake));
                detail.chain = u32::try_from(found.chain).ok();
                detail.names = found.names;
                detail.alpn = found.alpn;
                let trusted = found.info.verified;
                detail.tls = Some(found.info);
                if trusted {
                    (SampleStatus::Ok, None, Some(total))
                } else {
                    (
                        SampleStatus::Error,
                        Some(error_code::TLS_CERTIFICATE_INVALID),
                        None,
                    )
                }
            }
        };
        if job
            .sample_with(0, status, rtt_us, code, serde_json::to_value(&detail).ok())
            .await
            .is_ok()
        {
            job.completed(ip, resolved).await;
        }
    }
}
