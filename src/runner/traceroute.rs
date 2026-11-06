//! The traceroute check: the routers on the way to the target, one sample per hop.
//!
//! Three probes go to each hop at the same time and the hop is reported once. A router that does not
//! answer is normal and costs only a timeout; the trace stops when the destination answers, when a
//! router says the destination is unreachable, or after eight silent hops in a row.
//!
//! Hop addresses that are not public (the node operator's own router, carrier-grade NAT) are never
//! reported: the sample says "a private hop" and nothing more, so a result does not disclose the
//! layout of someone's network.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use super::{Failure, Job, Runner, micros};
use crate::probes::Prober;
use crate::probes::traceroute::HopOutcome;
use crate::protocol::{SampleStatus, Task, error_code};
use crate::resolve::Resolve;

pub const MAX_HOPS: u8 = 30;
const PROBES_PER_HOP: usize = 3;
const MAX_SILENT_HOPS: u32 = 8;
const HOP_TIMEOUT_MS: std::ops::RangeInclusive<u64> = 200..=3_000;

/// What a hop's sample says. Mirrors the backend's `HopDetail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HopDetail {
    pub ttl: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub private: bool,
    pub rtts_us: Vec<u64>,
    pub reached: bool,
}

impl<P: Prober, R: Resolve> Runner<P, R> {
    pub(super) fn check_traceroute(&self, task: &Task) -> Result<(), Failure> {
        let options = &task.options;
        match options.max_hops {
            Some(hops)
                if (1..=MAX_HOPS).contains(&hops)
                    && HOP_TIMEOUT_MS.contains(&options.timeout_ms) =>
            {
                Ok(())
            }
            _ => Err(Failure::new(
                error_code::INTERNAL_ERROR,
                "Task options are outside this node's limits.",
            )),
        }
    }

    pub(super) async fn run_traceroute(
        &self,
        task: &Task,
        job: &Job,
        ip: IpAddr,
        resolved: &[IpAddr],
    ) {
        let max_hops = task.options.max_hops.unwrap_or(MAX_HOPS).min(MAX_HOPS);
        let timeout = Duration::from_millis(task.options.timeout_ms);
        let mut silent = 0;

        for ttl in 1..=max_hops {
            if job.cancel.is_cancelled() {
                return;
            }
            if self.expired(task) {
                job.fail(Failure::new(
                    error_code::EXPIRED,
                    "The task expired while running.",
                ))
                .await;
                return;
            }
            let probes = [0u16, 1, 2].map(|n| {
                let seq = u16::from(ttl) * 4 + n;
                self.prober.hop(ip, ttl, seq, timeout)
            });
            let outcomes = tokio::select! {
                () = job.cancel.cancelled() => return,
                outcomes = futures_util::future::join_all(probes) => outcomes,
            };
            debug_assert_eq!(outcomes.len(), PROBES_PER_HOP);

            let mut rtts: Vec<Duration> = vec![];
            let mut responder: Option<IpAddr> = None;
            let (mut reached, mut terminal) = (false, false);
            let mut failure: Option<&'static str> = None;
            for outcome in &outcomes {
                match *outcome {
                    HopOutcome::Reply {
                        from,
                        rtt,
                        reached: arrived,
                        terminal: stop,
                    } => {
                        rtts.push(rtt);
                        responder.get_or_insert(from);
                        reached |= arrived;
                        terminal |= stop;
                    }
                    HopOutcome::Timeout => {}
                    HopOutcome::Failed(code) => failure = Some(code),
                }
            }
            rtts.sort();

            let (status, code) = match (rtts.is_empty(), failure) {
                (false, _) => (SampleStatus::Ok, None),
                (true, Some(code))
                    if outcomes.iter().all(|o| matches!(o, HopOutcome::Failed(_))) =>
                {
                    (SampleStatus::Error, Some(code))
                }
                (true, _) => (SampleStatus::Timeout, None),
            };
            if status == SampleStatus::Error && ttl == 1 {
                // Nothing could even be sent: say why instead of a route of question marks.
                if let Some(code) = code {
                    job.fail(Failure::new(code, "No probe could be sent."))
                        .await;
                    return;
                }
            }

            let public = responder.filter(|a| self.policy.check_ip(*a).is_ok());
            let detail = HopDetail {
                ttl,
                ip: public.map(|a| a.to_string()),
                private: responder.is_some() && public.is_none(),
                rtts_us: rtts.iter().map(|r| micros(*r)).collect(),
                reached,
            };
            let rtt_us = rtts.first().map(|r| micros(*r));
            let sent = job
                .sample_with(
                    u32::from(ttl) - 1,
                    status,
                    rtt_us,
                    code,
                    serde_json::to_value(&detail).ok(),
                )
                .await;
            if sent.is_err() {
                return;
            }

            silent = if rtts.is_empty() { silent + 1 } else { 0 };
            if reached || terminal || silent >= MAX_SILENT_HOPS {
                break;
            }
        }
        job.completed(ip, resolved).await;
    }
}
