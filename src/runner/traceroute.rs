//! The traceroute check: the routers on the way to the target, one sample per hop.
//!
//! Three probes go to each hop at the same time and the hop is reported once. A router that does not
//! answer is normal and costs only a timeout; the trace stops when the destination answers, when a
//! router says the destination is unreachable, or after eight silent hops in a row.
//!
//! With `count` above one the trace is repeated like `mtr` does: the first round is the trace above,
//! every later round sends one probe to each hop found, all hops at once and `interval_ms` apart (a
//! router answers a burst to the same hop with less and less, which would look like loss). The hops
//! are reported afterwards, each once, with every round-trip time and how many probes were sent.
//!
//! Hop addresses that are not public (the node operator's own router, carrier-grade NAT) are never
//! reported: the sample says "a private hop" and nothing more, so a result does not disclose the
//! layout of someone's network.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;
use tokio::time::sleep;

use super::{Failure, Job, MAX_COUNT, Runner, micros};
use crate::probes::Prober;
use crate::probes::traceroute::HopOutcome;
use crate::protocol::{SampleStatus, Task, error_code};
use crate::resolve::Resolve;

pub const MAX_HOPS: u8 = 30;
const PROBES_PER_HOP: usize = 3;
const MAX_SILENT_HOPS: u32 = 8;
const HOP_TIMEOUT_MS: std::ops::RangeInclusive<u64> = 200..=3_000;
const ROUND_INTERVAL_MS: std::ops::RangeInclusive<u64> = 200..=5_000;

/// What a hop's sample says. Mirrors the backend's `HopDetail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HopDetail {
    pub ttl: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub private: bool,
    pub rtts_us: Vec<u64>,
    pub reached: bool,
    /// How many probes went to this hop. Left out for a single round, which always sends three.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent: Option<u32>,
}

/// What the probes sent to one hop came back with.
#[derive(Default)]
struct Tally {
    sent: u32,
    rtts: Vec<Duration>,
    responder: Option<IpAddr>,
    reached: bool,
    terminal: bool,
    failed: u32,
    failure: Option<&'static str>,
}

impl Tally {
    fn add(&mut self, outcome: &HopOutcome) {
        self.sent += 1;
        match *outcome {
            HopOutcome::Reply {
                from,
                rtt,
                reached,
                terminal,
            } => {
                self.rtts.push(rtt);
                self.responder.get_or_insert(from);
                self.reached |= reached;
                self.terminal |= terminal;
            }
            HopOutcome::Timeout => {}
            HopOutcome::Failed(code) => {
                self.failed += 1;
                self.failure = Some(code);
            }
        }
    }

    fn answered(&self) -> bool {
        !self.rtts.is_empty()
    }

    /// A hop whose probes all failed to leave is an error; one that was only quiet is a timeout.
    fn status(&self) -> (SampleStatus, Option<&'static str>) {
        if self.answered() {
            (SampleStatus::Ok, None)
        } else if self.sent > 0 && self.failed == self.sent {
            (SampleStatus::Error, self.failure)
        } else {
            (SampleStatus::Timeout, None)
        }
    }
}

impl<P: Prober, R: Resolve> Runner<P, R> {
    pub(super) fn check_traceroute(&self, task: &Task) -> Result<(), Failure> {
        let options = &task.options;
        match options.max_hops {
            Some(hops)
                if (1..=MAX_HOPS).contains(&hops)
                    && HOP_TIMEOUT_MS.contains(&options.timeout_ms)
                    && (1..=MAX_COUNT).contains(&options.count)
                    && ROUND_INTERVAL_MS.contains(&options.interval_ms) =>
            {
                Ok(())
            }
            _ => Err(Failure::new(
                error_code::INTERNAL_ERROR,
                "Task options are outside this node's limits.",
            )),
        }
    }

    /// Send the three probes of one hop together. `None` means the task was cancelled meanwhile.
    async fn probe_hop(&self, job: &Job, ip: IpAddr, ttl: u8, timeout: Duration) -> Option<Tally> {
        let probes = [0u16, 1, 2].map(|n| {
            let seq = u16::from(ttl) * 4 + n;
            self.prober.hop(ip, ttl, seq, timeout)
        });
        let outcomes = tokio::select! {
            () = job.cancel.cancelled() => return None,
            outcomes = futures_util::future::join_all(probes) => outcomes,
        };
        debug_assert_eq!(outcomes.len(), PROBES_PER_HOP);
        let mut tally = Tally::default();
        for outcome in &outcomes {
            tally.add(outcome);
        }
        Some(tally)
    }

    /// One more probe to each of the first `hops` hops, all at once. `None` means cancelled.
    async fn probe_round(
        &self,
        job: &Job,
        ip: IpAddr,
        hops: usize,
        round: u32,
        timeout: Duration,
    ) -> Option<Vec<HopOutcome>> {
        let probes = (1..=hops).map(|n| {
            let ttl = u8::try_from(n).unwrap_or(MAX_HOPS);
            // Past the sequence numbers of the first round (`ttl * 4 + 0..3`), one range per round.
            let seq = 128 + u16::try_from(round).unwrap_or(0) * 32 + u16::from(ttl);
            self.prober.hop(ip, ttl, seq, timeout)
        });
        tokio::select! {
            () = job.cancel.cancelled() => None,
            outcomes = futures_util::future::join_all(probes) => Some(outcomes),
        }
    }

    async fn send_hop(&self, job: &Job, ttl: u8, tally: &Tally, rounds: u32) -> Result<(), ()> {
        let (status, code) = tally.status();
        let mut rtts = tally.rtts.clone();
        rtts.sort();
        let public = tally.responder.filter(|a| self.policy.check_ip(*a).is_ok());
        let detail = HopDetail {
            ttl,
            ip: public.map(|a| a.to_string()),
            private: tally.responder.is_some() && public.is_none(),
            rtts_us: rtts.iter().map(|r| micros(*r)).collect(),
            reached: tally.reached,
            sent: (rounds > 1).then_some(tally.sent),
        };
        let rtt_us = rtts.first().map(|r| micros(*r));
        job.sample_with(
            u32::from(ttl) - 1,
            status,
            rtt_us,
            code,
            serde_json::to_value(&detail).ok(),
        )
        .await
        .map_err(|_| ())
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
        let rounds = task.options.count.clamp(1, MAX_COUNT);
        let mut found: Vec<Tally> = vec![];
        let mut silent = 0;

        for ttl in 1..=max_hops {
            if job.cancel.is_cancelled() {
                return;
            }
            if self.expired(task) {
                self.fail_expired(job).await;
                return;
            }
            let Some(tally) = self.probe_hop(job, ip, ttl, timeout).await else {
                return;
            };
            let (status, code) = tally.status();
            if status == SampleStatus::Error && ttl == 1 {
                // Nothing could even be sent: say why instead of a route of question marks.
                if let Some(code) = code {
                    job.fail(Failure::new(code, "No probe could be sent."))
                        .await;
                    return;
                }
            }

            silent = if tally.answered() { 0 } else { silent + 1 };
            let done = tally.reached || tally.terminal || silent >= MAX_SILENT_HOPS;
            if rounds == 1 {
                // One round: each hop is reported as soon as it is known, so the route draws live.
                if self.send_hop(job, ttl, &tally, rounds).await.is_err() {
                    return;
                }
            } else {
                found.push(tally);
            }
            if done {
                break;
            }
        }

        if rounds > 1 {
            let interval = Duration::from_millis(task.options.interval_ms);
            for round in 1..rounds {
                tokio::select! {
                    () = job.cancel.cancelled() => return,
                    () = sleep(interval) => {}
                }
                if self.expired(task) {
                    self.fail_expired(job).await;
                    return;
                }
                let Some(outcomes) = self.probe_round(job, ip, found.len(), round, timeout).await
                else {
                    return;
                };
                for (tally, outcome) in found.iter_mut().zip(&outcomes) {
                    tally.add(outcome);
                }
            }
            for (index, tally) in found.iter().enumerate() {
                let ttl = u8::try_from(index + 1).unwrap_or(MAX_HOPS);
                if self.send_hop(job, ttl, tally, rounds).await.is_err() {
                    return;
                }
            }
        }
        job.completed(ip, resolved).await;
    }

    async fn fail_expired(&self, job: &Job) {
        job.fail(Failure::new(
            error_code::EXPIRED,
            "The task expired while running.",
        ))
        .await;
    }
}
