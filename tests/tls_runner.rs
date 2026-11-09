//! The certificate check, with scripted handshakes: what is reported, and what is refused first.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipping_node::policy::Policy;
use ipping_node::probes::http::TlsInfo;
use ipping_node::probes::tls::{Finding, TlsOutcome, TlsRequest};
use ipping_node::probes::{EchoOutcome, Prober};
use ipping_node::protocol::{
    Capabilities, ClientFrame, ResultStatus, SampleStatus, ServerFrame, Task, error_code,
};
use ipping_node::resolve::Resolve;
use ipping_node::runner::Runner;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct Scripted {
    outcome: Mutex<Option<TlsOutcome>>,
    requests: Mutex<Vec<TlsRequest>>,
}

impl Scripted {
    fn new(outcome: TlsOutcome) -> Arc<Self> {
        Arc::new(Self {
            outcome: Mutex::new(Some(outcome)),
            requests: Mutex::default(),
        })
    }
    fn requests(&self) -> Vec<TlsRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Prober for Scripted {
    async fn echo(&self, _: IpAddr, _: u16, _: u16, _: Duration) -> EchoOutcome {
        EchoOutcome::Timeout
    }

    async fn tls_once(&self, request: TlsRequest) -> TlsOutcome {
        self.requests.lock().unwrap().push(request);
        tokio::time::sleep(Duration::from_millis(40)).await;
        self.outcome
            .lock()
            .unwrap()
            .take()
            .unwrap_or(TlsOutcome::Timeout)
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

fn caps(kinds: &[&str]) -> Capabilities {
    Capabilities {
        kinds: kinds.iter().map(|k| (*k).to_owned()).collect(),
        ipv4: true,
        ipv6: true,
    }
}

fn info(verified: bool, error: Option<&str>) -> TlsInfo {
    TlsInfo {
        version: Some("TLSv1.3".into()),
        cipher: Some("TLS13_AES_256_GCM_SHA384".into()),
        subject: Some("CN=example.com".into()),
        issuer: Some("CN=Test CA".into()),
        not_before: Some("2026-10-01T00:00:00Z".into()),
        not_after: Some("2027-01-01T00:00:00Z".into()),
        verified,
        verify_error: error.map(str::to_owned),
    }
}

fn finding(verified: bool, error: Option<&str>) -> TlsOutcome {
    TlsOutcome::Handshake(Finding {
        connect: Duration::from_millis(9),
        handshake: Duration::from_millis(23),
        info: info(verified, error),
        names: vec!["example.com".into(), "www.example.com".into()],
        chain: 2,
        alpn: None,
    })
}

fn task(target: Value, timeout_ms: u64) -> Task {
    task_with(
        target,
        json!({"count": 1, "interval_ms": 1000, "timeout_ms": timeout_ms}),
    )
}

fn task_with(target: Value, options: Value) -> Task {
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(30);
    let frame = json!({
        "type": "task", "task_id": "t1", "attempt_id": "a1", "kind": "tls",
        "target": target,
        "options": options,
        "expires_at": expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
    });
    match serde_json::from_value(frame).unwrap() {
        ServerFrame::Task(task) => task,
        other => panic!("not a task: {other:?}"),
    }
}

fn pinned() -> Task {
    task(
        json!({"ip": "93.184.216.34", "port": 443, "server_name": "example.com"}),
        10_000,
    )
}

async fn run_with(prober: Arc<Scripted>, kinds: &[&str], task: Task) -> Vec<ClientFrame> {
    let resolver = Arc::new(FakeResolver(HashMap::from([
        ("example.com", vec!["93.184.216.34"]),
        ("internal.example.com", vec!["10.0.0.5"]),
    ])));
    let runner = Runner::new(prober, resolver, Policy::public_only(), caps(kinds));
    let (tx, mut rx) = mpsc::channel(64);
    runner.run(task, tx, CancellationToken::new()).await;
    let mut frames = vec![];
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }
    frames
}

async fn run(prober: Arc<Scripted>, task: Task) -> Vec<ClientFrame> {
    run_with(prober, &["ping", "tls"], task).await
}

struct Sample {
    status: SampleStatus,
    rtt_us: Option<u64>,
    code: Option<String>,
    detail: Value,
}

fn sample_of(frames: &[ClientFrame]) -> Sample {
    let samples: Vec<_> = frames
        .iter()
        .filter_map(|f| match f {
            ClientFrame::Sample {
                status,
                rtt_us,
                error_code,
                detail,
                ..
            } => Some(Sample {
                status: *status,
                rtt_us: *rtt_us,
                code: error_code.clone(),
                detail: detail.clone().unwrap_or(Value::Null),
            }),
            _ => None,
        })
        .collect();
    assert_eq!(samples.len(), 1, "a tls task yields one sample: {frames:?}");
    samples.into_iter().next().unwrap()
}

fn result_of(frames: &[ClientFrame]) -> (ResultStatus, Option<String>, Option<String>) {
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

#[tokio::test(start_paused = true)]
async fn a_trusted_certificate_is_an_ok_sample_with_everything_it_says() {
    let prober = Scripted::new(finding(true, None));
    let frames = run(prober.clone(), pinned()).await;
    let sample = sample_of(&frames);
    assert_eq!(sample.status, SampleStatus::Ok);
    assert!(sample.code.is_none());
    assert!(sample.rtt_us.is_some_and(|us| us >= 40_000));
    assert_eq!(sample.detail["server_name"], "example.com");
    assert_eq!(sample.detail["connect_us"], 9000);
    assert_eq!(sample.detail["tls_us"], 23000);
    assert_eq!(sample.detail["chain"], 2);
    assert_eq!(
        sample.detail["names"],
        json!(["example.com", "www.example.com"])
    );
    assert_eq!(sample.detail["tls"]["verified"], true);
    assert_eq!(sample.detail["tls"]["not_after"], "2027-01-01T00:00:00Z");
    assert_eq!(
        result_of(&frames),
        (ResultStatus::Completed, None, Some("93.184.216.34".into()))
    );

    // The address is the one the task pinned, and the name presented is the one it gave.
    let requests = prober.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].ip, "93.184.216.34".parse::<IpAddr>().unwrap());
    assert_eq!(requests[0].port, 443);
    assert_eq!(requests[0].server_name, "example.com");
}

#[tokio::test(start_paused = true)]
async fn a_certificate_that_does_not_verify_is_an_error_that_still_says_what_it_is() {
    let prober = Scripted::new(finding(false, Some("the certificate has expired")));
    let frames = run(prober, pinned()).await;
    let sample = sample_of(&frames);
    assert_eq!(sample.status, SampleStatus::Error);
    assert_eq!(sample.code.as_deref(), Some("tls_certificate_invalid"));
    assert!(
        sample.rtt_us.is_none(),
        "an untrusted handshake is not a result to rank"
    );
    assert_eq!(sample.detail["tls"]["verified"], false);
    assert_eq!(
        sample.detail["tls"]["verify_error"],
        "the certificate has expired"
    );
    assert_eq!(sample.detail["tls"]["subject"], "CN=example.com");
    assert_eq!(result_of(&frames).0, ResultStatus::Completed);
}

#[tokio::test(start_paused = true)]
async fn a_failed_handshake_keeps_the_connect_time_and_a_timeout_is_a_timeout() {
    let failed = TlsOutcome::Failed {
        code: error_code::TLS_ERROR,
        message: "The TLS handshake failed: peer is incompatible".into(),
        connect: Some(Duration::from_millis(7)),
    };
    let sample = sample_of(&run(Scripted::new(failed), pinned()).await);
    assert_eq!(sample.status, SampleStatus::Error);
    assert_eq!(sample.code.as_deref(), Some("tls_error"));
    assert_eq!(sample.detail["connect_us"], 7000);
    assert!(sample.detail.get("tls").is_none());

    let sample = sample_of(&run(Scripted::new(TlsOutcome::Timeout), pinned()).await);
    assert_eq!(sample.status, SampleStatus::Timeout);
    assert!(sample.code.is_none() && sample.rtt_us.is_none());

    let refused = TlsOutcome::failed(error_code::CONNECTION_REFUSED, "refused");
    let sample = sample_of(&run(Scripted::new(refused), pinned()).await);
    assert_eq!(sample.code.as_deref(), Some("connection_refused"));
}

#[tokio::test(start_paused = true)]
async fn a_hostname_is_resolved_here_and_presented_as_the_name() {
    let target = task(
        json!({"hostname": "example.com", "port": 443, "family": "auto"}),
        10_000,
    );
    let prober = Scripted::new(finding(true, None));
    let frames = run(prober.clone(), target).await;
    assert_eq!(sample_of(&frames).status, SampleStatus::Ok);
    let request = &prober.requests()[0];
    assert_eq!(request.ip, "93.184.216.34".parse::<IpAddr>().unwrap());
    assert_eq!(request.server_name, "example.com");
}

#[tokio::test(start_paused = true)]
async fn a_bare_address_presents_the_address() {
    let target = task(json!({"ip": "93.184.216.34", "port": 443}), 10_000);
    let prober = Scripted::new(finding(true, None));
    run(prober.clone(), target).await;
    assert_eq!(prober.requests()[0].server_name, "93.184.216.34");
}

#[tokio::test(start_paused = true)]
async fn refusals_happen_before_anything_is_sent() {
    let cases = [
        // a port that is not on the allowed list
        (
            task(
                json!({"ip": "93.184.216.34", "port": 6379, "server_name": "example.com"}),
                10_000,
            ),
            error_code::PORT_NOT_ALLOWED,
        ),
        // a name that resolves to a private address
        (
            task(
                json!({"hostname": "internal.example.com", "port": 443, "family": "auto"}),
                10_000,
            ),
            error_code::BLOCKED_BY_POLICY,
        ),
        // an internal name is not presented at all
        (
            task(
                json!({"ip": "93.184.216.34", "port": 443, "server_name": "printer.lan"}),
                10_000,
            ),
            error_code::BLOCKED_BY_POLICY,
        ),
        // a private address
        (
            task(json!({"ip": "10.0.0.5", "port": 443}), 10_000),
            error_code::BLOCKED_BY_POLICY,
        ),
    ];
    for (task, code) in cases {
        let prober = Scripted::new(finding(true, None));
        let frames = run(prober.clone(), task).await;
        // an acknowledgement at most (a private address is only found when the target is resolved)
        assert!(frames.len() <= 2, "{frames:?}");
        assert_eq!(result_of(&frames).0, ResultStatus::Failed);
        assert_eq!(result_of(&frames).1.as_deref(), Some(code));
        assert!(prober.requests().is_empty());
    }

    // a timeout outside the node's limits
    let prober = Scripted::new(finding(true, None));
    let frames = run(
        prober.clone(),
        task(
            json!({"ip": "93.184.216.34", "port": 443, "server_name": "example.com"}),
            60_000,
        ),
    )
    .await;
    assert_eq!(result_of(&frames).0, ResultStatus::Failed);
    assert!(prober.requests().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_quic_handshake_is_asked_for_and_the_sample_says_so() {
    let quic = TlsOutcome::Handshake(Finding {
        connect: Duration::ZERO,
        handshake: Duration::from_millis(31),
        info: info(true, None),
        names: vec!["example.com".into()],
        chain: 2,
        alpn: Some("h3".into()),
    });
    let prober = Scripted::new(quic);
    let mut options = json!({"timeout_ms": 8000, "transport": "quic"});
    options["count"] = json!(1);
    let frames = run(
        prober.clone(),
        task_with(
            json!({"ip": "93.184.216.34", "port": 443, "server_name": "example.com"}),
            options,
        ),
    )
    .await;
    let sample = sample_of(&frames);
    assert_eq!(sample.status, SampleStatus::Ok);
    assert_eq!(sample.detail["transport"], "quic");
    assert_eq!(sample.detail["alpn"], "h3");
    assert_eq!(sample.detail["tls"]["verified"], true);
    assert!(prober.requests()[0].quic);

    // over TCP there is neither
    let tcp = Scripted::new(finding(true, None));
    let frames = run(tcp.clone(), pinned()).await;
    let detail = sample_of(&frames).detail;
    assert!(detail.get("transport").is_none() && detail.get("alpn").is_none());
    assert!(!tcp.requests()[0].quic);
}

#[tokio::test(start_paused = true)]
async fn a_transport_nobody_knows_is_refused_before_anything_is_sent() {
    for transport in ["udp", "doh", "dot", "QUIC"] {
        let prober = Scripted::new(finding(true, None));
        let frames = run(
            prober.clone(),
            task_with(
                json!({"ip": "93.184.216.34", "port": 443, "server_name": "example.com"}),
                json!({"timeout_ms": 8000, "transport": transport}),
            ),
        )
        .await;
        assert_eq!(result_of(&frames).0, ResultStatus::Failed, "{transport}");
        assert!(prober.requests().is_empty(), "{transport}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_node_that_does_not_advertise_tls_says_so() {
    let prober = Scripted::new(finding(true, None));
    let frames = run_with(prober.clone(), &["ping"], pinned()).await;
    assert_eq!(
        result_of(&frames).1.as_deref(),
        Some(error_code::UNSUPPORTED_KIND)
    );
    assert!(prober.requests().is_empty());
}
