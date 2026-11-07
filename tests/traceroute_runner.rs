//! The traceroute check with scripted hops.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipping_node::policy::Policy;
use ipping_node::probes::traceroute::HopOutcome;
use ipping_node::probes::{EchoOutcome, Prober};
use ipping_node::protocol::{
    Capabilities, ClientFrame, ResultStatus, SampleStatus, ServerFrame, Task, error_code,
};
use ipping_node::resolve::Resolve;
use ipping_node::runner::Runner;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const DESTINATION: &str = "93.184.216.34";

#[derive(Default)]
struct Route {
    /// What the three probes of each TTL get, in order; a TTL without an entry gets silence.
    hops: HashMap<u8, Vec<HopOutcome>>,
    calls: Mutex<Vec<(u8, u16)>>,
}

impl Route {
    fn new(hops: Vec<(u8, Vec<HopOutcome>)>) -> Arc<Self> {
        Arc::new(Self {
            hops: hops.into_iter().collect(),
            ..Default::default()
        })
    }
    fn calls(&self) -> Vec<(u8, u16)> {
        self.calls.lock().unwrap().clone()
    }
}

impl Prober for Route {
    async fn echo(&self, _: IpAddr, _: u16, _: u16, _: Duration) -> EchoOutcome {
        EchoOutcome::Timeout
    }

    async fn hop(&self, _ip: IpAddr, ttl: u8, seq: u16, _timeout: Duration) -> HopOutcome {
        let nth = {
            let mut calls = self.calls.lock().unwrap();
            let nth = calls.iter().filter(|(t, _)| *t == ttl).count();
            calls.push((ttl, seq));
            nth
        };
        tokio::time::sleep(Duration::from_millis(1)).await;
        self.hops
            .get(&ttl)
            .and_then(|outcomes| outcomes.get(nth))
            .copied()
            .unwrap_or(HopOutcome::Timeout)
    }
}

fn reply(from: &str, ms: u64) -> HopOutcome {
    HopOutcome::Reply {
        from: from.parse().unwrap(),
        rtt: Duration::from_millis(ms),
        reached: false,
        terminal: false,
    }
}

fn arrival(ms: u64) -> HopOutcome {
    HopOutcome::Reply {
        from: DESTINATION.parse().unwrap(),
        rtt: Duration::from_millis(ms),
        reached: true,
        terminal: false,
    }
}

struct NoDns;
impl Resolve for NoDns {
    async fn lookup(&self, _: &str) -> io::Result<Vec<IpAddr>> {
        Ok(vec![])
    }
}

fn caps() -> Capabilities {
    Capabilities {
        kinds: vec!["ping".into(), "traceroute".into()],
        ipv4: true,
        ipv6: true,
    }
}

fn task(max_hops: u32, timeout_ms: u64) -> Task {
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(60);
    let frame = json!({
        "type": "task", "task_id": "t1", "attempt_id": "a1", "kind": "traceroute",
        "target": {"ip": DESTINATION},
        "options": {"timeout_ms": timeout_ms, "max_hops": max_hops},
        "expires_at": expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
    });
    match serde_json::from_value(frame).unwrap() {
        ServerFrame::Task(task) => task,
        other => panic!("{other:?}"),
    }
}

/// The same trace repeated `count` times, a second apart.
fn repeated(max_hops: u32, count: u32, interval_ms: u64) -> Task {
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(60);
    let frame = json!({
        "type": "task", "task_id": "t1", "attempt_id": "a1", "kind": "traceroute",
        "target": {"ip": DESTINATION},
        "options": {
            "timeout_ms": 1000, "max_hops": max_hops, "count": count, "interval_ms": interval_ms,
        },
        "expires_at": expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
    });
    match serde_json::from_value(frame).unwrap() {
        ServerFrame::Task(task) => task,
        other => panic!("{other:?}"),
    }
}

async fn run(route: Arc<Route>, policy: Policy, task: Task) -> Vec<ClientFrame> {
    let runner = Runner::new(route, Arc::new(NoDns), policy, caps());
    let (tx, mut rx) = mpsc::channel(128);
    runner.run(task, tx, CancellationToken::new()).await;
    let mut frames = vec![];
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }
    frames
}

struct Hop {
    seq: u32,
    status: SampleStatus,
    rtt_us: Option<u64>,
    detail: Value,
}

fn hops_of(frames: &[ClientFrame]) -> Vec<Hop> {
    frames
        .iter()
        .filter_map(|f| match f {
            ClientFrame::Sample {
                seq,
                status,
                rtt_us,
                detail,
                ..
            } => Some(Hop {
                seq: *seq,
                status: *status,
                rtt_us: *rtt_us,
                detail: detail.clone().unwrap(),
            }),
            _ => None,
        })
        .collect()
}

fn result_of(frames: &[ClientFrame]) -> (ResultStatus, Option<String>) {
    match frames.last().unwrap() {
        ClientFrame::TaskResult {
            status, error_code, ..
        } => (*status, error_code.clone()),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_route_is_reported_hop_by_hop_and_stops_at_the_destination() {
    let route = Route::new(vec![
        (
            1,
            vec![
                reply("192.168.1.1", 1),
                reply("192.168.1.1", 2),
                reply("192.168.1.1", 1),
            ],
        ),
        (
            2,
            vec![
                reply("62.115.1.1", 9),
                reply("62.115.1.1", 7),
                HopOutcome::Timeout,
            ],
        ),
        // Hop 3 is silent.
        (4, vec![arrival(25), arrival(21), arrival(23)]),
        (5, vec![arrival(99)]),
    ]);
    let frames = run(route.clone(), Policy::public_only(), task(30, 1000)).await;

    assert!(matches!(frames[0], ClientFrame::TaskAck { .. }));
    let hops = hops_of(&frames);
    assert_eq!(hops.len(), 4, "the trace stops at the destination");
    assert_eq!(hops.iter().map(|h| h.seq).collect::<Vec<_>>(), [0, 1, 2, 3]);

    // The node operator's own router is "a private hop", never an address.
    assert_eq!(hops[0].status, SampleStatus::Ok);
    assert_eq!(
        hops[0].detail,
        json!({"ttl": 1, "private": true, "rtts_us": [1000, 1000, 2000], "reached": false})
    );
    assert_eq!(
        hops[0].rtt_us,
        Some(1000),
        "the fastest reply is the hop's time"
    );

    assert_eq!(
        hops[1].detail,
        json!({"ttl": 2, "ip": "62.115.1.1", "private": false, "rtts_us": [7000, 9000], "reached": false})
    );
    assert_eq!(hops[2].status, SampleStatus::Timeout);
    assert_eq!(hops[2].rtt_us, None);
    assert_eq!(
        hops[2].detail,
        json!({"ttl": 3, "private": false, "rtts_us": [], "reached": false})
    );
    assert_eq!(hops[3].detail["reached"], true);
    assert_eq!(hops[3].detail["ip"], DESTINATION);
    assert_eq!(hops[3].rtt_us, Some(21_000));

    let (status, code) = result_of(&frames);
    assert_eq!((status, code), (ResultStatus::Completed, None));
    let calls = route.calls();
    assert_eq!(calls.len(), 12, "three probes for each of four hops");
    let mut seqs: Vec<_> = calls.iter().map(|(_, s)| *s).collect();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs.len(), 12, "every probe has its own sequence number");
}

#[tokio::test(start_paused = true)]
async fn a_silent_route_gives_up_after_eight_hops() {
    let route = Route::new(vec![(1, vec![reply("62.115.1.1", 5)])]);
    let frames = run(route, Policy::public_only(), task(30, 1000)).await;
    let hops = hops_of(&frames);
    assert_eq!(hops.len(), 9, "one answering hop, then eight silent ones");
    assert_eq!(result_of(&frames).0, ResultStatus::Completed);
}

#[tokio::test(start_paused = true)]
async fn the_hop_limit_is_respected() {
    let everyone_answers: Vec<_> = (1..=30u8)
        .map(|t| (t, vec![reply("62.115.1.1", 5); 3]))
        .collect();
    let frames = run(
        Route::new(everyone_answers),
        Policy::public_only(),
        task(5, 1000),
    )
    .await;
    assert_eq!(hops_of(&frames).len(), 5);
    assert!(
        hops_of(&frames)
            .iter()
            .all(|h| h.detail["reached"] == false)
    );
}

#[tokio::test(start_paused = true)]
async fn a_router_saying_unreachable_ends_the_trace() {
    let stop = HopOutcome::Reply {
        from: "62.115.9.9".parse().unwrap(),
        rtt: Duration::from_millis(12),
        reached: false,
        terminal: true,
    };
    let route = Route::new(vec![
        (1, vec![reply("62.115.1.1", 5)]),
        (2, vec![stop, stop, stop]),
    ]);
    let frames = run(route, Policy::public_only(), task(30, 1000)).await;
    assert_eq!(hops_of(&frames).len(), 2);
    assert_eq!(result_of(&frames).0, ResultStatus::Completed);
}

#[tokio::test(start_paused = true)]
async fn when_nothing_can_be_sent_the_task_fails_with_the_reason() {
    let denied = HopOutcome::Failed(error_code::PERMISSION_DENIED);
    let route = Route::new(vec![(1, vec![denied, denied, denied])]);
    let frames = run(route, Policy::public_only(), task(30, 1000)).await;
    assert!(hops_of(&frames).is_empty());
    assert_eq!(
        result_of(&frames),
        (ResultStatus::Failed, Some("permission_denied".into()))
    );
}

#[tokio::test(start_paused = true)]
async fn out_of_range_tasks_are_refused_before_anything_is_sent() {
    for (hops, timeout) in [(0, 1000), (31, 1000), (10, 100), (10, 60_000)] {
        let route = Route::new(vec![]);
        let frames = run(route.clone(), Policy::public_only(), task(hops, timeout)).await;
        assert_eq!(frames.len(), 1, "{hops} hops, {timeout} ms: {frames:?}");
        assert_eq!(result_of(&frames).0, ResultStatus::Failed);
        assert!(route.calls().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn private_destinations_are_never_traced() {
    let mut private = task(10, 1000);
    private.target.ip = Some("10.0.0.5".into());
    let route = Route::new(vec![]);
    let frames = run(route.clone(), Policy::public_only(), private).await;
    assert_eq!(
        result_of(&frames).1.as_deref(),
        Some(error_code::BLOCKED_BY_POLICY)
    );
    assert!(route.calls().is_empty());
}

#[tokio::test(start_paused = true)]
async fn only_tests_ever_see_non_public_hops() {
    let route = Route::new(vec![(1, vec![reply("192.168.1.1", 1)])]);
    let frames = run(route, Policy::permissive_for_tests(), task(1, 1000)).await;
    assert_eq!(hops_of(&frames)[0].detail["ip"], "192.168.1.1");
    assert_eq!(hops_of(&frames)[0].detail["private"], false);
}

#[tokio::test(start_paused = true)]
async fn cancelling_stops_the_trace() {
    let route = Route::new(vec![]);
    let runner = Runner::new(
        route.clone(),
        Arc::new(NoDns),
        Policy::public_only(),
        caps(),
    );
    let (tx, mut rx) = mpsc::channel(128);
    let cancel = CancellationToken::new();
    let handle = tokio::spawn({
        let cancel = cancel.clone();
        async move { runner.run(task(30, 1000), tx, cancel).await }
    });
    tokio::time::sleep(Duration::from_millis(5)).await;
    cancel.cancel();
    handle.await.unwrap();
    let mut frames = vec![];
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }
    assert!(
        !frames
            .iter()
            .any(|f| matches!(f, ClientFrame::TaskResult { .. })),
        "a cancelled task sends no result: {frames:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn repeated_rounds_are_reported_once_per_hop_with_every_reply() {
    // Three rounds: the first sends three probes to each hop, each later round one more.
    let route = Route::new(vec![
        (
            1,
            vec![
                reply("62.115.1.1", 2),
                reply("62.115.1.1", 3),
                reply("62.115.1.1", 2),
                reply("62.115.1.1", 9),
                reply("62.115.1.1", 4),
            ],
        ),
        // Hop 2 loses every probe of the later rounds and one of the first three.
        (
            2,
            vec![
                reply("62.115.2.2", 11),
                HopOutcome::Timeout,
                reply("62.115.2.2", 12),
                HopOutcome::Timeout,
                HopOutcome::Timeout,
            ],
        ),
        // Hop 3 is silent in every round.
        (
            4,
            vec![
                arrival(30),
                arrival(31),
                arrival(29),
                arrival(33),
                arrival(32),
            ],
        ),
    ]);
    let frames = run(route.clone(), Policy::public_only(), repeated(30, 3, 1000)).await;
    let hops = hops_of(&frames);
    assert_eq!(
        hops.len(),
        4,
        "one sample per hop, however many rounds: {frames:?}"
    );
    assert_eq!(hops.iter().map(|h| h.seq).collect::<Vec<_>>(), [0, 1, 2, 3]);

    assert_eq!(
        hops[0].detail,
        json!({
            "ttl": 1, "ip": "62.115.1.1", "private": false,
            "rtts_us": [2000, 2000, 3000, 4000, 9000], "reached": false, "sent": 5,
        })
    );
    assert_eq!(hops[0].rtt_us, Some(2000));
    assert_eq!(hops[1].detail["rtts_us"], json!([11_000, 12_000]));
    assert_eq!(hops[1].detail["sent"], 5);
    assert_eq!(hops[2].status, SampleStatus::Timeout);
    assert_eq!(hops[2].detail["sent"], 5);
    assert_eq!(hops[2].detail["rtts_us"], json!([]));
    assert_eq!(hops[3].detail["reached"], true);
    assert_eq!(hops[3].detail["sent"], 5);
    assert_eq!(result_of(&frames).0, ResultStatus::Completed);

    let calls = route.calls();
    assert_eq!(calls.len(), 4 * 5, "five probes to each of four hops");
    let mut seqs: Vec<_> = calls.iter().map(|(_, s)| *s).collect();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(
        seqs.len(),
        calls.len(),
        "every probe has its own sequence number"
    );
}

#[tokio::test(start_paused = true)]
async fn rounds_are_spaced_by_the_interval() {
    let route = Route::new(vec![(1, vec![arrival(5), arrival(5), arrival(5)])]);
    let started = tokio::time::Instant::now();
    let frames = run(route, Policy::public_only(), repeated(30, 4, 1500)).await;
    let elapsed = started.elapsed();
    assert_eq!(hops_of(&frames).len(), 1);
    assert!(
        elapsed >= Duration::from_millis(3 * 1500),
        "three gaps of 1.5 s between four rounds, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "and no longer: {elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn one_round_reports_as_before_without_a_probe_count() {
    let route = Route::new(vec![(1, vec![arrival(5), arrival(6), arrival(7)])]);
    let frames = run(route, Policy::public_only(), repeated(30, 1, 1000)).await;
    let hops = hops_of(&frames);
    assert_eq!(hops.len(), 1);
    assert!(hops[0].detail.get("sent").is_none(), "{:?}", hops[0].detail);
}

#[tokio::test(start_paused = true)]
async fn too_many_rounds_or_a_tiny_interval_are_refused() {
    for (count, interval_ms) in [(0, 1000), (11, 1000), (3, 50), (3, 60_000)] {
        let route = Route::new(vec![]);
        let frames = run(
            route.clone(),
            Policy::public_only(),
            repeated(10, count, interval_ms),
        )
        .await;
        assert_eq!(
            frames.len(),
            1,
            "{count} rounds, {interval_ms} ms: {frames:?}"
        );
        assert_eq!(result_of(&frames).0, ResultStatus::Failed);
        assert!(route.calls().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn cancelling_between_rounds_reports_nothing() {
    let route = Route::new(vec![(1, vec![arrival(5), arrival(5), arrival(5)])]);
    let runner = Runner::new(
        route.clone(),
        Arc::new(NoDns),
        Policy::public_only(),
        caps(),
    );
    let (tx, mut rx) = mpsc::channel(128);
    let cancel = CancellationToken::new();
    let handle = tokio::spawn({
        let cancel = cancel.clone();
        async move { runner.run(repeated(30, 5, 1000), tx, cancel).await }
    });
    // The first round is done in a few milliseconds; the second is a second away.
    tokio::time::sleep(Duration::from_millis(500)).await;
    cancel.cancel();
    handle.await.unwrap();
    let mut frames = vec![];
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }
    assert!(
        hops_of(&frames).is_empty(),
        "nothing is reported half-way: {frames:?}"
    );
    assert!(
        !frames
            .iter()
            .any(|f| matches!(f, ClientFrame::TaskResult { .. })),
        "a cancelled task sends no result: {frames:?}"
    );
}
