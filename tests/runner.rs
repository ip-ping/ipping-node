//! Task runner behaviour, with scripted probe results and DNS answers.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipping_node::policy::Policy;
use ipping_node::probes::{EchoOutcome, Prober};
use ipping_node::protocol::{
    Capabilities, ClientFrame, ResultStatus, SampleStatus, ServerFrame, Task, error_code,
};
use ipping_node::resolve::Resolve;
use ipping_node::runner::Runner;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct ScriptedProber {
    outcomes: Mutex<VecDeque<EchoOutcome>>,
    calls: Mutex<Vec<(IpAddr, Instant)>>,
    hang: bool,
}

impl ScriptedProber {
    fn with(outcomes: Vec<EchoOutcome>) -> Arc<Self> {
        Arc::new(Self {
            outcomes: Mutex::new(outcomes.into()),
            ..Default::default()
        })
    }
    fn calls(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Prober for ScriptedProber {
    async fn echo(&self, ip: IpAddr, _ident: u16, _seq: u16, _timeout: Duration) -> EchoOutcome {
        self.calls.lock().unwrap().push((ip, Instant::now()));
        if self.hang {
            std::future::pending::<()>().await;
        }
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(EchoOutcome::Timeout)
    }
}

struct FakeResolver(HashMap<&'static str, Vec<&'static str>>);

impl Resolve for FakeResolver {
    async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        match self.0.get(host) {
            Some(ips) => Ok(ips.iter().map(|s| s.parse().unwrap()).collect()),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "no such host")),
        }
    }
}

fn resolver() -> Arc<FakeResolver> {
    Arc::new(FakeResolver(HashMap::from([
        ("example.com", vec!["93.184.216.34"]),
        (
            "dual.example.com",
            vec!["2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34"],
        ),
        (
            "v6only.example.com",
            vec!["2606:2800:220:1:248:1893:25c8:1946"],
        ),
        ("internal.example.com", vec!["10.0.0.5"]),
        ("mixed.example.com", vec!["93.184.216.34", "192.168.1.1"]),
        ("empty.example.com", vec![]),
    ])))
}

fn caps(ipv4: bool, ipv6: bool) -> Capabilities {
    Capabilities {
        kinds: vec!["ping".into()],
        ipv4,
        ipv6,
    }
}

fn task_with(target: serde_json::Value, count: u32, expires_in_s: i64) -> Task {
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in_s);
    let frame = json!({
        "type": "task", "task_id": "t1", "attempt_id": "a1", "kind": "ping",
        "target": target,
        "options": {"count": count, "interval_ms": 1000, "timeout_ms": 2000},
        "expires_at": expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
    });
    match serde_json::from_value(frame).unwrap() {
        ServerFrame::Task(task) => task,
        other => panic!("not a task: {other:?}"),
    }
}

fn ip_task(ip: &str, count: u32) -> Task {
    task_with(json!({"ip": ip}), count, 30)
}

async fn run<P: Prober>(
    prober: Arc<P>,
    policy: Policy,
    caps: Capabilities,
    task: Task,
) -> Vec<ClientFrame> {
    let runner = Runner::new(prober, resolver(), policy, caps);
    let (tx, mut rx) = mpsc::channel(64);
    runner.run(task, tx, CancellationToken::new()).await;
    let mut frames = vec![];
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }
    frames
}

fn result_of(frames: &[ClientFrame]) -> (&ResultStatus, Option<&str>, Option<&str>) {
    match frames.last().expect("no frames") {
        ClientFrame::TaskResult {
            status,
            tested_ip,
            error_code,
            ..
        } => (status, tested_ip.as_deref(), error_code.as_deref()),
        other => panic!("last frame is not a result: {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn successful_ping_reports_every_echo_then_completes() {
    let prober = ScriptedProber::with(vec![
        EchoOutcome::Reply(Duration::from_millis(12)),
        EchoOutcome::Timeout,
        EchoOutcome::Reply(Duration::from_micros(30_500)),
        EchoOutcome::Reply(Duration::from_millis(20)),
    ]);
    let frames = run(
        prober.clone(),
        Policy::public_only(),
        caps(true, true),
        ip_task("93.184.216.34", 4),
    )
    .await;

    assert!(matches!(frames[0], ClientFrame::TaskAck { .. }));
    let samples: Vec<_> = frames
        .iter()
        .filter_map(|f| match f {
            ClientFrame::Sample {
                seq,
                status,
                rtt_us,
                ..
            } => Some((*seq, *status, *rtt_us)),
            _ => None,
        })
        .collect();
    assert_eq!(
        samples,
        vec![
            (0, SampleStatus::Ok, Some(12_000)),
            (1, SampleStatus::Timeout, None),
            (2, SampleStatus::Ok, Some(30_500)),
            (3, SampleStatus::Ok, Some(20_000)),
        ]
    );
    assert_eq!(
        result_of(&frames),
        (&ResultStatus::Completed, Some("93.184.216.34"), None)
    );
}

#[tokio::test(start_paused = true)]
async fn echoes_are_spaced_by_the_interval() {
    let prober = ScriptedProber::with(vec![EchoOutcome::Reply(Duration::from_millis(5)); 3]);
    run(
        prober.clone(),
        Policy::public_only(),
        caps(true, true),
        ip_task("93.184.216.34", 3),
    )
    .await;
    let times: Vec<Instant> = prober.calls.lock().unwrap().iter().map(|c| c.1).collect();
    assert_eq!(times[1] - times[0], Duration::from_secs(1));
    assert_eq!(times[2] - times[1], Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn hostname_is_resolved_locally_and_prefers_ipv4() {
    let prober = ScriptedProber::with(vec![EchoOutcome::Reply(Duration::from_millis(5))]);
    let task = task_with(
        json!({"hostname": "dual.example.com", "family": "auto"}),
        1,
        30,
    );
    let frames = run(prober, Policy::public_only(), caps(true, true), task).await;
    match frames.last().unwrap() {
        ClientFrame::TaskResult {
            status: ResultStatus::Completed,
            tested_ip,
            resolved_ips,
            ..
        } => {
            assert_eq!(tested_ip.as_deref(), Some("93.184.216.34"));
            assert_eq!(resolved_ips.len(), 2);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn ipv6_is_used_when_requested_and_when_the_node_lacks_ipv4() {
    let v6 = "2606:2800:220:1:248:1893:25c8:1946";
    let prober = ScriptedProber::with(vec![EchoOutcome::Reply(Duration::from_millis(5))]);
    let task = task_with(
        json!({"hostname": "dual.example.com", "family": "6"}),
        1,
        30,
    );
    let frames = run(prober, Policy::public_only(), caps(true, true), task).await;
    assert_eq!(
        result_of(&frames),
        (&ResultStatus::Completed, Some(v6), None)
    );

    let prober = ScriptedProber::with(vec![EchoOutcome::Reply(Duration::from_millis(5))]);
    let task = task_with(json!({"hostname": "dual.example.com"}), 1, 30);
    let frames = run(prober, Policy::public_only(), caps(false, true), task).await;
    assert_eq!(
        result_of(&frames),
        (&ResultStatus::Completed, Some(v6), None)
    );
}

#[tokio::test(start_paused = true)]
async fn unsupported_family_is_reported_not_counted_as_loss() {
    let prober = ScriptedProber::with(vec![]);
    let task = task_with(json!({"hostname": "v6only.example.com"}), 1, 30);
    let frames = run(
        prober.clone(),
        Policy::public_only(),
        caps(true, false),
        task,
    )
    .await;
    assert_eq!(
        result_of(&frames),
        (
            &ResultStatus::Failed,
            None,
            Some(error_code::UNSUPPORTED_FAMILY)
        )
    );
    assert_eq!(prober.calls(), 0);

    let frames = run(
        prober.clone(),
        Policy::public_only(),
        caps(true, false),
        ip_task("2606:4700:4700::1111", 1),
    )
    .await;
    assert_eq!(
        result_of(&frames),
        (
            &ResultStatus::Failed,
            None,
            Some(error_code::UNSUPPORTED_FAMILY)
        )
    );
}

#[tokio::test(start_paused = true)]
async fn dns_problems_have_their_own_error() {
    for host in ["nope.example.com", "empty.example.com"] {
        let prober = ScriptedProber::with(vec![]);
        let frames = run(
            prober.clone(),
            Policy::public_only(),
            caps(true, true),
            task_with(json!({"hostname": host}), 1, 30),
        )
        .await;
        assert_eq!(
            result_of(&frames),
            (&ResultStatus::Failed, None, Some(error_code::DNS_FAILURE)),
            "{host}"
        );
        assert_eq!(prober.calls(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn destinations_outside_the_policy_are_never_probed() {
    for target in [
        json!({"ip": "127.0.0.1"}),
        json!({"ip": "169.254.169.254"}),
        json!({"ip": "::1"}),
        json!({"ip": "not-an-ip"}),
        json!({"hostname": "internal.example.com"}),
        json!({"hostname": "mixed.example.com"}), // one private answer refuses the whole name
        json!({"hostname": "localhost"}),
    ] {
        let prober = ScriptedProber::with(vec![]);
        let frames = run(
            prober.clone(),
            Policy::public_only(),
            caps(true, true),
            task_with(target.clone(), 1, 30),
        )
        .await;
        assert_eq!(
            result_of(&frames),
            (
                &ResultStatus::Failed,
                None,
                Some(error_code::BLOCKED_BY_POLICY)
            ),
            "{target}"
        );
        assert_eq!(prober.calls(), 0, "{target}");
    }
}

#[tokio::test(start_paused = true)]
async fn expired_and_out_of_range_tasks_are_refused_before_acknowledging() {
    let prober = ScriptedProber::with(vec![]);
    let frames = run(
        prober.clone(),
        Policy::public_only(),
        caps(true, true),
        task_with(json!({"ip": "8.8.8.8"}), 1, -1),
    )
    .await;
    assert_eq!(frames.len(), 1);
    assert_eq!(
        result_of(&frames),
        (&ResultStatus::Failed, None, Some(error_code::EXPIRED))
    );

    let frames = run(
        prober.clone(),
        Policy::public_only(),
        caps(true, true),
        ip_task("8.8.8.8", 11),
    )
    .await;
    assert_eq!(frames.len(), 1);
    assert_eq!(
        result_of(&frames),
        (
            &ResultStatus::Failed,
            None,
            Some(error_code::INTERNAL_ERROR)
        )
    );
    assert_eq!(prober.calls(), 0);
}

#[tokio::test(start_paused = true)]
async fn clock_offset_keeps_a_node_with_a_wrong_clock_working() {
    // The node's clock is an hour ahead of the server's; the task still has 30 s to live.
    let task = ip_task("8.8.8.8", 1);
    let runner = Runner::new(
        ScriptedProber::with(vec![EchoOutcome::Reply(Duration::from_millis(1))]),
        resolver(),
        Policy::public_only(),
        caps(true, true),
    );
    let (tx, mut rx) = mpsc::channel(8);
    runner
        .clone()
        .with_clock_offset(time::Duration::hours(-1))
        .run(task.clone(), tx, CancellationToken::new())
        .await;
    let mut last = None;
    while let Ok(f) = rx.try_recv() {
        last = Some(f);
    }
    assert!(matches!(
        last,
        Some(ClientFrame::TaskResult {
            status: ResultStatus::Completed,
            ..
        })
    ));

    // Without the correction the same task looks expired, which is what the offset prevents.
    let (tx, mut rx) = mpsc::channel(8);
    let ahead = task_with(json!({"ip": "8.8.8.8"}), 1, -3600 + 30);
    runner.run(ahead, tx, CancellationToken::new()).await;
    assert!(matches!(
        rx.try_recv(),
        Ok(ClientFrame::TaskResult {
            status: ResultStatus::Failed,
            ..
        })
    ));
}

#[tokio::test(start_paused = true)]
async fn when_no_echo_can_be_sent_the_task_fails_with_the_reason() {
    let prober = ScriptedProber::with(vec![EchoOutcome::Failed(error_code::PERMISSION_DENIED); 2]);
    let frames = run(
        prober,
        Policy::public_only(),
        caps(true, true),
        ip_task("8.8.8.8", 2),
    )
    .await;
    assert!(frames.iter().any(|f| matches!(
        f,
        ClientFrame::Sample {
            status: SampleStatus::Error,
            ..
        }
    )));
    assert_eq!(
        result_of(&frames),
        (
            &ResultStatus::Failed,
            None,
            Some(error_code::PERMISSION_DENIED)
        )
    );
}

#[tokio::test(start_paused = true)]
async fn cancellation_stops_a_task_without_a_result() {
    let prober = Arc::new(ScriptedProber {
        hang: true,
        ..Default::default()
    });
    let runner = Runner::new(
        prober.clone(),
        resolver(),
        Policy::public_only(),
        caps(true, true),
    );
    let (tx, mut rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = tokio::spawn({
        let cancel = cancel.clone();
        async move { runner.run(ip_task("8.8.8.8", 4), tx, cancel).await }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    cancel.cancel();
    handle.await.unwrap();
    assert!(matches!(rx.try_recv(), Ok(ClientFrame::TaskAck { .. })));
    assert!(
        rx.try_recv().is_err(),
        "a cancelled task must not report a result"
    );
    assert_eq!(prober.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_closed_connection_stops_the_task() {
    let prober = ScriptedProber::with(vec![EchoOutcome::Reply(Duration::from_millis(1)); 4]);
    let runner = Runner::new(
        prober.clone(),
        resolver(),
        Policy::public_only(),
        caps(true, true),
    );
    let (tx, rx) = mpsc::channel(8);
    drop(rx);
    runner
        .run(ip_task("8.8.8.8", 4), tx, CancellationToken::new())
        .await;
    assert_eq!(prober.calls(), 0);
}
