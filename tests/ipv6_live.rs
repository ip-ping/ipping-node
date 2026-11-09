//! Every kind over IPv6, with the node's real policy and real sockets, against the lab that
//! `tests/netns/ipv6.sh` builds out of network namespaces (global IPv6 addresses, a router in between, real
//! servers). Skipped unless that script sets the environment, so a normal `cargo test` ignores it.

#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::sync::Arc;

use ipping_node::policy::Policy;
use ipping_node::probes::system::SystemProber;
use ipping_node::protocol::{
    Capabilities, ClientFrame, ResultStatus, SampleStatus, ServerFrame, Task, error_code,
};
use ipping_node::resolve::Resolve;
use ipping_node::runner::Runner;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct NoDns;
impl Resolve for NoDns {
    async fn lookup(&self, _: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(vec![])
    }
}

struct Lab {
    dest: String,
    router: String,
}

fn lab() -> Option<Lab> {
    let (Ok(dest), Ok(router)) = (
        std::env::var("IPPING_V6_DEST"),
        std::env::var("IPPING_V6_ROUTER"),
    ) else {
        eprintln!("skipped: run tests/netns/ipv6.sh as root to build the lab");
        return None;
    };
    Some(Lab { dest, router })
}

fn task(kind: &str, target: Value, options: Value) -> Task {
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(60);
    let frame = json!({
        "type": "task", "task_id": "t", "attempt_id": "a", "kind": kind,
        "target": target, "options": options,
        "expires_at": expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
    });
    match serde_json::from_value(frame).unwrap() {
        ServerFrame::Task(task) => task,
        other => panic!("not a task: {other:?}"),
    }
}

/// Run a task with the production policy (public addresses only) and return all its frames.
async fn run(task: Task) -> Vec<ClientFrame> {
    let caps = Capabilities {
        kinds: ["ping", "tcp", "http", "tls", "dns", "traceroute"]
            .map(String::from)
            .to_vec(),
        ipv4: true,
        ipv6: true,
    };
    let runner = Runner::new(
        Arc::new(SystemProber::new()),
        Arc::new(NoDns),
        Policy::public_only(),
        caps,
    );
    let (tx, mut rx) = mpsc::channel(128);
    runner.run(task, tx, CancellationToken::new()).await;
    let mut frames = vec![];
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }
    frames
}

struct Sample {
    status: SampleStatus,
    code: Option<String>,
    detail: Value,
}

fn samples(frames: &[ClientFrame]) -> Vec<Sample> {
    frames
        .iter()
        .filter_map(|f| match f {
            ClientFrame::Sample {
                status,
                error_code,
                detail,
                ..
            } => Some(Sample {
                status: *status,
                code: error_code.clone(),
                detail: detail.clone().unwrap_or(Value::Null),
            }),
            _ => None,
        })
        .collect()
}

fn result(frames: &[ClientFrame]) -> (ResultStatus, Option<String>, Option<String>) {
    match frames.last().unwrap() {
        ClientFrame::TaskResult {
            status,
            error_code,
            tested_ip,
            ..
        } => (*status, error_code.clone(), tested_ip.clone()),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn ping_and_tcp_reach_a_global_ipv6_address() {
    let Some(lab) = lab() else { return };
    let ping = run(task(
        "ping",
        json!({"ip": lab.dest}),
        json!({"count": 3, "interval_ms": 200, "timeout_ms": 2000}),
    ))
    .await;
    let got = samples(&ping);
    assert_eq!(got.len(), 3);
    assert!(
        got.iter().all(|s| s.status == SampleStatus::Ok),
        "ping over IPv6: {ping:?}"
    );
    assert_eq!(
        result(&ping),
        (ResultStatus::Completed, None, Some(lab.dest.clone()))
    );

    let tcp = run(task(
        "tcp",
        json!({"ip": lab.dest, "port": 80}),
        json!({"count": 2, "interval_ms": 200, "timeout_ms": 2000}),
    ))
    .await;
    assert!(
        samples(&tcp).iter().all(|s| s.status == SampleStatus::Ok),
        "tcp over IPv6: {tcp:?}"
    );

    // a closed port is a refusal that kept its time, as over IPv4
    let closed = run(task(
        "tcp",
        json!({"ip": lab.dest, "port": 25}),
        json!({"count": 1, "interval_ms": 200, "timeout_ms": 2000}),
    ))
    .await;
    assert_eq!(
        samples(&closed)[0].code.as_deref(),
        Some("connection_refused")
    );
}

#[tokio::test]
async fn http_to_an_ipv6_address_sends_a_bracketed_host() {
    let Some(lab) = lab() else { return };
    let frames = run(task(
        "http",
        json!({"ip": lab.dest, "port": 80}),
        json!({"timeout_ms": 5000, "scheme": "http", "path": "/", "max_redirects": 0}),
    ))
    .await;
    let got = samples(&frames);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].status, SampleStatus::Ok, "{frames:?}");
    assert_eq!(got[0].detail["status_code"], 200);
    assert_eq!(got[0].detail["final_host"], lab.dest.as_str());
}

#[tokio::test]
async fn a_certificate_over_ipv6_is_described_and_not_trusted() {
    let Some(lab) = lab() else { return };
    let frames = run(task(
        "tls",
        json!({"ip": lab.dest, "port": 8443}),
        json!({"timeout_ms": 5000}),
    ))
    .await;
    let got = samples(&frames);
    assert_eq!(got.len(), 1);
    // The lab's certificate is self-signed: the handshake completes, and the reason is the finding.
    assert_eq!(got[0].status, SampleStatus::Error, "{frames:?}");
    assert_eq!(
        got[0].code.as_deref(),
        Some(error_code::TLS_CERTIFICATE_INVALID)
    );
    assert_eq!(got[0].detail["tls"]["verified"], false);
    assert!(
        got[0].detail["tls"]["subject"]
            .as_str()
            .unwrap()
            .contains("ipv6-lab")
    );
    assert_eq!(got[0].detail["names"], json!(["ipv6-lab.example.org"]));
}

#[tokio::test]
async fn a_resolver_named_by_ipv6_address_answers_a_and_aaaa() {
    let Some(lab) = lab() else { return };
    for (record, expected) in [("A", "192.0.2.7"), ("AAAA", "2001:4860:4860::7")] {
        let frames = run(task(
            "dns",
            json!({"hostname": "lab.example.org"}),
            json!({"timeout_ms": 3000, "record_type": record, "resolver_ip": lab.dest}),
        ))
        .await;
        let got = samples(&frames);
        assert_eq!(got.len(), 1, "{frames:?}");
        assert_eq!(got[0].status, SampleStatus::Ok, "{record}: {frames:?}");
        assert_eq!(got[0].detail["rcode"], "NOERROR");
        assert_eq!(got[0].detail["answers"][0]["data"], expected, "{record}");
    }
}

#[tokio::test]
async fn a_traceroute_reports_the_global_address_of_the_router() {
    let Some(lab) = lab() else { return };
    let frames = run(task(
        "traceroute",
        json!({"ip": lab.dest}),
        json!({"timeout_ms": 1500, "max_hops": 8, "count": 2, "interval_ms": 300}),
    ))
    .await;
    let hops = samples(&frames);
    assert_eq!(
        hops.len(),
        2,
        "one router, then the destination: {frames:?}"
    );
    // The router's address is global, so the node reports it (a private one would be "a private hop").
    assert_eq!(hops[0].detail["ip"], lab.router.as_str());
    assert_eq!(hops[0].detail["private"], false);
    assert_eq!(hops[1].detail["ip"], lab.dest.as_str());
    assert_eq!(hops[1].detail["reached"], true);
    assert_eq!(
        hops[1].detail["sent"], 4,
        "three probes, then one more round"
    );
}

#[tokio::test]
async fn addresses_that_are_not_public_are_refused_before_anything_is_sent() {
    let Some(_) = lab() else { return };
    for target in [
        "fd00:1::2",
        "2001:db8::1",
        "fe80::1",
        "::1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
    ] {
        let frames = run(task(
            "tcp",
            json!({"ip": target, "port": 80}),
            json!({"count": 1, "interval_ms": 200, "timeout_ms": 1000}),
        ))
        .await;
        assert_eq!(
            result(&frames).1.as_deref(),
            Some(error_code::BLOCKED_BY_POLICY),
            "{target} must be refused: {frames:?}"
        );
        assert!(samples(&frames).is_empty(), "{target}");
    }
}
