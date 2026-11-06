//! Real traceroute probes, Linux only.
//!
//! * On loopback, which every Linux host has, a TTL of 1 still reaches the destination.
//! * `tests/netns/traceroute.sh` builds a three-hop network out of network namespaces and runs the
//!   second test inside it, with the expected route in the environment. It needs root, so a normal
//!   `cargo test` skips it.

#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use ipping_node::policy::Policy;
use ipping_node::probes::Prober;
use ipping_node::probes::system::SystemProber;
use ipping_node::probes::traceroute::{HopOutcome, available};
use ipping_node::protocol::{Capabilities, ClientFrame, ResultStatus, SampleStatus, ServerFrame};
use ipping_node::resolve::Resolve;
use ipping_node::runner::Runner;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn on_loopback_the_destination_answers_at_once() {
    if !available(false) {
        eprintln!("skipped: this user cannot open ICMP ping sockets with IP_RECVERR");
        return;
    }
    let prober = SystemProber::new();
    let outcome = prober
        .hop("127.0.0.1".parse().unwrap(), 1, 1, Duration::from_secs(2))
        .await;
    match outcome {
        HopOutcome::Reply {
            from,
            rtt,
            reached,
            terminal,
        } => {
            assert_eq!(from, "127.0.0.1".parse::<IpAddr>().unwrap());
            assert!(reached && !terminal);
            assert!(rtt < Duration::from_secs(1), "{rtt:?}");
        }
        other => panic!("expected the destination to answer, got {other:?}"),
    }
    assert!(available(false));
}

#[tokio::test]
async fn a_probe_to_nowhere_times_out_or_fails_cleanly() {
    if !available(false) {
        return;
    }
    // 192.0.2.1 is documentation space: nothing answers, or the host has no route.
    let outcome = SystemProber::new()
        .hop(
            "192.0.2.1".parse().unwrap(),
            5,
            2,
            Duration::from_millis(300),
        )
        .await;
    assert!(
        matches!(
            outcome,
            HopOutcome::Timeout | HopOutcome::Failed(_) | HopOutcome::Reply { reached: false, .. }
        ),
        "{outcome:?}"
    );
}

struct NoDns;
impl Resolve for NoDns {
    async fn lookup(&self, _: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(vec![])
    }
}

/// Set by `tests/netns/traceroute.sh`: `IPPING_TRACE_DEST=10.0.3.2`,
/// `IPPING_TRACE_HOPS=10.0.1.2,10.0.2.2` (the routers in between, in order).
#[tokio::test]
async fn through_real_routers_in_network_namespaces() {
    let (Ok(destination), Ok(hops)) = (
        std::env::var("IPPING_TRACE_DEST"),
        std::env::var("IPPING_TRACE_HOPS"),
    ) else {
        eprintln!("skipped: run tests/netns/traceroute.sh as root to build the test network");
        return;
    };
    let routers: Vec<&str> = hops.split(',').collect();

    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(60);
    let frame = json!({
        "type": "task", "task_id": "t", "attempt_id": "a", "kind": "traceroute",
        "target": {"ip": destination},
        "options": {"timeout_ms": 1500, "max_hops": 10},
        "expires_at": expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
    });
    let ServerFrame::Task(task) = serde_json::from_value(frame).unwrap() else {
        panic!("not a task")
    };
    let capabilities = Capabilities {
        kinds: vec!["traceroute".into()],
        ipv4: true,
        ipv6: true,
    };
    // The routers are private addresses, which only a test policy will name.
    let runner = Runner::new(
        Arc::new(SystemProber::new()),
        Arc::new(NoDns),
        Policy::permissive_for_tests(),
        capabilities,
    );
    let (tx, mut rx) = mpsc::channel(64);
    runner.run(task, tx, CancellationToken::new()).await;
    let mut frames = vec![];
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }

    let samples: Vec<_> = frames
        .iter()
        .filter_map(|f| match f {
            ClientFrame::Sample {
                seq,
                status,
                rtt_us,
                detail,
                ..
            } => Some((*seq, *status, *rtt_us, detail.clone().unwrap())),
            _ => None,
        })
        .collect();
    eprintln!("{samples:#?}");

    assert_eq!(
        samples.len(),
        routers.len() + 1,
        "one sample per router, then the destination"
    );
    for (index, router) in routers.iter().enumerate() {
        let (seq, status, rtt, detail) = &samples[index];
        assert_eq!(*seq as usize, index);
        assert_eq!(*status, SampleStatus::Ok, "hop {}", index + 1);
        assert_eq!(detail["ttl"], index + 1);
        assert_eq!(detail["ip"], *router, "hop {}", index + 1);
        assert_eq!(detail["reached"], false);
        assert!(rtt.unwrap() > 0 && rtt.unwrap() < 1_000_000);
        // A router may rate-limit the ICMP errors it sends (the kernel's global limit did drop one
        // of three in a burst), which is why a hop gets three probes. One answer is a hop.
        let answered = detail["rtts_us"].as_array().unwrap().len();
        assert!(
            (1..=3).contains(&answered),
            "hop {}: {answered} of 3 probes answered",
            index + 1
        );
    }
    let (_, status, rtt, last) = samples.last().unwrap();
    assert_eq!(*status, SampleStatus::Ok);
    assert_eq!(last["reached"], true);
    assert_eq!(last["ip"], destination);
    assert!(rtt.unwrap() > 0);
    assert!(matches!(
        frames.last(),
        Some(ClientFrame::TaskResult {
            status: ResultStatus::Completed,
            ..
        })
    ));
}
