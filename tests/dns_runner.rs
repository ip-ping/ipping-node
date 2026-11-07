//! The DNS task as the runner handles it: which names and resolvers are allowed, what the sample
//! says, and what is kept back when the answer came from the node's own resolver.

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipping_node::policy::Policy;
use ipping_node::probes::dns::{DnsAnswer, DnsOutcome, DnsRequest, Record, RecordType, Resolver};
use ipping_node::probes::{EchoOutcome, Prober};
use ipping_node::protocol::{
    Capabilities, ClientFrame, ResultStatus, SampleStatus, ServerFrame, Task, error_code,
};
use ipping_node::resolve::Resolve;
use ipping_node::runner::Runner;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct ScriptedDns {
    outcome: DnsOutcome,
    asked: Mutex<Vec<DnsRequest>>,
}

impl ScriptedDns {
    fn new(outcome: DnsOutcome) -> Arc<Self> {
        Arc::new(Self {
            outcome,
            asked: Mutex::new(vec![]),
        })
    }
}

impl Prober for ScriptedDns {
    async fn echo(&self, _: IpAddr, _: u16, _: u16, _: Duration) -> EchoOutcome {
        unreachable!("a DNS task never pings")
    }
    async fn dns_query(&self, request: DnsRequest) -> DnsOutcome {
        self.asked.lock().unwrap().push(request);
        self.outcome.clone()
    }
}

struct NeverResolves;
impl Resolve for NeverResolves {
    async fn lookup(&self, _: &str) -> io::Result<Vec<IpAddr>> {
        panic!("a DNS task must not resolve the name itself");
    }
}

fn record(kind: RecordType, data: &str, address: Option<&str>) -> Record {
    Record {
        name: "example.com".into(),
        kind,
        ttl: 300,
        data: data.into(),
        address: address.map(|a| a.parse().unwrap()),
    }
}

fn answer(records: Vec<Record>) -> DnsOutcome {
    DnsOutcome::Answer(DnsAnswer {
        rtt: Duration::from_micros(23_400),
        rcode: 0,
        authoritative: false,
        via_tcp: false,
        truncated: false,
        records,
    })
}

fn caps(kinds: &[&str]) -> Capabilities {
    Capabilities {
        kinds: kinds.iter().map(|k| (*k).to_string()).collect(),
        ipv4: true,
        ipv6: true,
    }
}

fn dns_task(target: Value, options: Value) -> Task {
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(30);
    let frame = json!({
        "type": "task", "task_id": "t1", "attempt_id": "a1", "kind": "dns",
        "target": target, "options": options,
        "expires_at": expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
    });
    match serde_json::from_value(frame).unwrap() {
        ServerFrame::Task(task) => task,
        other => panic!("not a task: {other:?}"),
    }
}

fn simple(resolver_ip: Option<&str>) -> Task {
    let mut options = json!({"timeout_ms": 3000, "record_type": "A"});
    if let Some(ip) = resolver_ip {
        options["resolver_ip"] = json!(ip);
    }
    dns_task(json!({"hostname": "example.com"}), options)
}

async fn run(prober: Arc<ScriptedDns>, kinds: &[&str], task: Task) -> Vec<ClientFrame> {
    let runner = Runner::new(
        prober,
        Arc::new(NeverResolves),
        Policy::public_only(),
        caps(kinds),
    );
    let (tx, mut rx) = mpsc::channel(16);
    runner.run(task, tx, CancellationToken::new()).await;
    let mut frames = vec![];
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }
    frames
}

fn failed_with(frames: &[ClientFrame]) -> &str {
    match frames.last().unwrap() {
        ClientFrame::TaskResult {
            status: ResultStatus::Failed,
            error_code: Some(code),
            ..
        } => code,
        other => panic!("not a failure: {other:?}"),
    }
}

fn sample(frames: &[ClientFrame]) -> (SampleStatus, Option<u64>, Option<&Value>) {
    frames
        .iter()
        .find_map(|f| match f {
            ClientFrame::Sample {
                status,
                rtt_us,
                detail,
                ..
            } => Some((*status, *rtt_us, detail.as_ref())),
            _ => None,
        })
        .expect("no sample")
}

#[tokio::test]
async fn a_public_resolver_is_asked_and_its_answers_are_reported_as_they_are() {
    let prober = ScriptedDns::new(answer(vec![
        record(RecordType::A, "93.184.216.34", Some("93.184.216.34")),
        // a public record that points at a private address is real data from a public resolver
        record(RecordType::A, "10.1.2.3", Some("10.1.2.3")),
    ]));
    let frames = run(prober.clone(), &["dns"], simple(Some("1.1.1.1"))).await;

    let asked = prober.asked.lock().unwrap();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].name, "example.com");
    assert_eq!(asked[0].record_type, RecordType::A);
    assert_eq!(
        asked[0].resolver,
        Resolver::Server("1.1.1.1".parse().unwrap())
    );
    assert_eq!(asked[0].timeout, Duration::from_secs(3));

    assert!(matches!(frames[0], ClientFrame::TaskAck { .. }));
    let (status, rtt, detail) = sample(&frames);
    assert_eq!(status, SampleStatus::Ok);
    assert_eq!(rtt, Some(23_400));
    let detail = detail.unwrap();
    assert_eq!(detail["resolver"], "1.1.1.1");
    assert_eq!(detail["record_type"], "A");
    assert_eq!(detail["rcode"], "NOERROR");
    assert_eq!(detail["redacted"], 0);
    assert_eq!(detail["answers"].as_array().unwrap().len(), 2);
    assert_eq!(
        detail["answers"][0],
        json!({"name": "example.com", "type": "A", "ttl": 300, "data": "93.184.216.34"})
    );
    match frames.last().unwrap() {
        ClientFrame::TaskResult {
            status: ResultStatus::Completed,
            tested_ip,
            resolved_ips,
            ..
        } => {
            assert_eq!(tested_ip, &None, "a DNS check tests no address");
            assert_eq!(resolved_ips, &vec!["93.184.216.34".to_string()]);
        }
        other => panic!("not completed: {other:?}"),
    }
}

#[tokio::test]
async fn a_private_answer_from_the_nodes_own_resolver_is_counted_but_not_shown() {
    let prober = ScriptedDns::new(answer(vec![
        record(RecordType::A, "93.184.216.34", Some("93.184.216.34")),
        record(RecordType::A, "192.168.7.7", Some("192.168.7.7")),
        record(RecordType::Aaaa, "fd00::1", Some("fd00::1")),
        record(RecordType::Txt, "v=spf1 -all", None),
    ]));
    let frames = run(prober.clone(), &["dns"], simple(None)).await;
    assert_eq!(prober.asked.lock().unwrap()[0].resolver, Resolver::System);
    let (_, _, detail) = sample(&frames);
    let detail = detail.unwrap();
    assert_eq!(detail["resolver"], "system");
    assert_eq!(detail["redacted"], 2);
    let data: Vec<&str> = detail["answers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["data"].as_str().unwrap())
        .collect();
    assert_eq!(data, ["93.184.216.34", "v=spf1 -all"]);
    assert!(!detail.to_string().contains("192.168"), "{detail}");
    assert!(!detail.to_string().contains("fd00"), "{detail}");
}

#[tokio::test]
async fn an_error_code_from_the_resolver_is_still_a_sample() {
    let prober = ScriptedDns::new(DnsOutcome::Answer(DnsAnswer {
        rtt: Duration::from_millis(9),
        rcode: 3,
        authoritative: false,
        via_tcp: false,
        truncated: false,
        records: vec![],
    }));
    let frames = run(prober, &["dns"], simple(Some("8.8.8.8"))).await;
    let (status, _, detail) = sample(&frames);
    assert_eq!(status, SampleStatus::Ok);
    assert_eq!(detail.unwrap()["rcode"], "NXDOMAIN");
}

#[tokio::test]
async fn silence_is_a_timeout_sample() {
    let frames = run(
        ScriptedDns::new(DnsOutcome::Timeout),
        &["dns"],
        simple(Some("1.1.1.1")),
    )
    .await;
    let (status, rtt, detail) = sample(&frames);
    assert_eq!((status, rtt, detail), (SampleStatus::Timeout, None, None));
    assert!(matches!(
        frames.last().unwrap(),
        ClientFrame::TaskResult {
            status: ResultStatus::Completed,
            ..
        }
    ));
}

#[tokio::test]
async fn a_failure_to_ask_fails_the_task_with_its_code() {
    let prober = ScriptedDns::new(DnsOutcome::Failed(error_code::CONNECTION_REFUSED));
    let frames = run(prober, &["dns"], simple(Some("1.1.1.1"))).await;
    assert_eq!(failed_with(&frames), error_code::CONNECTION_REFUSED);
    let prober = ScriptedDns::new(DnsOutcome::Failed(error_code::DNS_FAILURE));
    let frames = run(prober, &["dns"], simple(None)).await;
    assert_eq!(failed_with(&frames), error_code::DNS_FAILURE);
}

#[tokio::test]
async fn only_public_resolvers_may_be_named() {
    for ip in [
        "10.0.0.1",
        "127.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fd00::53",
    ] {
        let prober = ScriptedDns::new(answer(vec![]));
        let frames = run(prober.clone(), &["dns"], simple(Some(ip))).await;
        assert_eq!(failed_with(&frames), error_code::BLOCKED_BY_POLICY, "{ip}");
        assert!(
            prober.asked.lock().unwrap().is_empty(),
            "{ip} must not be asked"
        );
    }
    let frames = run(
        ScriptedDns::new(answer(vec![])),
        &["dns"],
        simple(Some("not an address")),
    )
    .await;
    assert_eq!(failed_with(&frames), error_code::BLOCKED_BY_POLICY);
}

#[tokio::test]
async fn internal_names_and_addresses_are_not_looked_up() {
    for host in [
        "nas.lan",
        "printer.home.arpa",
        "localhost",
        "intranet",
        "wiki.corp",
        "a.onion",
    ] {
        let task = dns_task(
            json!({"hostname": host}),
            json!({"timeout_ms": 2000, "record_type": "A", "resolver_ip": "1.1.1.1"}),
        );
        let prober = ScriptedDns::new(answer(vec![]));
        let frames = run(prober.clone(), &["dns"], task).await;
        assert_eq!(
            failed_with(&frames),
            error_code::BLOCKED_BY_POLICY,
            "{host}"
        );
        assert!(
            prober.asked.lock().unwrap().is_empty(),
            "{host} must not be asked"
        );
    }
    let by_address = dns_task(
        json!({"ip": "1.1.1.1"}),
        json!({"timeout_ms": 2000, "record_type": "A"}),
    );
    let frames = run(ScriptedDns::new(answer(vec![])), &["dns"], by_address).await;
    assert_eq!(failed_with(&frames), error_code::INTERNAL_ERROR);
}

#[tokio::test]
async fn options_outside_the_limits_are_refused() {
    for options in [
        json!({"timeout_ms": 2000}),
        json!({"timeout_ms": 2000, "record_type": "ANY"}),
        json!({"timeout_ms": 2000, "record_type": "AXFR"}),
        json!({"timeout_ms": 50, "record_type": "A"}),
        json!({"timeout_ms": 600_000, "record_type": "A"}),
    ] {
        let task = dns_task(json!({"hostname": "example.com"}), options.clone());
        let prober = ScriptedDns::new(answer(vec![]));
        let frames = run(prober.clone(), &["dns"], task).await;
        assert_eq!(
            failed_with(&frames),
            error_code::INTERNAL_ERROR,
            "{options}"
        );
        assert!(prober.asked.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_node_that_does_not_advertise_dns_refuses_the_task() {
    let prober = ScriptedDns::new(answer(vec![]));
    let frames = run(prober.clone(), &["ping", "tcp"], simple(Some("1.1.1.1"))).await;
    assert_eq!(failed_with(&frames), error_code::UNSUPPORTED_KIND);
    assert!(prober.asked.lock().unwrap().is_empty());
}
