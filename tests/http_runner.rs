//! The HTTP check, with scripted responses: redirects, the policy at every hop, what is reported.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipping_node::policy::Policy;
use ipping_node::probes::http::{
    HttpFailure, HttpOutcome, HttpRequest, HttpResponse, TlsHandshake, TlsInfo,
};
use ipping_node::probes::{EchoOutcome, Prober};
use ipping_node::protocol::{
    Capabilities, ClientFrame, ResultStatus, SampleStatus, ServerFrame, Task, error_code,
};
use ipping_node::resolve::Resolve;
use ipping_node::runner::Runner;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct ScriptedHttp {
    outcomes: Mutex<VecDeque<HttpOutcome>>,
    requests: Mutex<Vec<HttpRequest>>,
    latency: Duration,
}

impl ScriptedHttp {
    fn with(outcomes: Vec<HttpOutcome>) -> Arc<Self> {
        Arc::new(Self {
            outcomes: Mutex::new(outcomes.into()),
            latency: Duration::from_millis(40),
            ..Default::default()
        })
    }
    fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Prober for ScriptedHttp {
    async fn echo(&self, _: IpAddr, _: u16, _: u16, _: Duration) -> EchoOutcome {
        EchoOutcome::Timeout
    }

    async fn http_once(&self, request: HttpRequest) -> HttpOutcome {
        self.requests.lock().unwrap().push(request);
        tokio::time::sleep(self.latency).await;
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(HttpOutcome::Timeout)
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
        ("www.example.com", vec!["93.184.216.35"]),
        ("internal.example.com", vec!["10.0.0.5"]),
    ])))
}

fn caps() -> Capabilities {
    Capabilities {
        kinds: vec!["ping".into(), "http".into()],
        ipv4: true,
        ipv6: true,
    }
}

fn response(status: u16, location: Option<&str>) -> HttpOutcome {
    HttpOutcome::Response(HttpResponse {
        status,
        version: "HTTP/1.1",
        server: Some("test-server".into()),
        content_type: Some("text/html".into()),
        location: location.map(str::to_owned),
        connect: Duration::from_millis(8),
        tls: Some(TlsHandshake {
            elapsed: Duration::from_millis(21),
            info: TlsInfo {
                version: Some("TLSv1.3".into()),
                cipher: None,
                subject: Some("CN=example.com".into()),
                issuer: Some("CN=Test CA".into()),
                not_before: None,
                not_after: Some("2027-01-01T00:00:00Z".into()),
                verified: true,
                verify_error: None,
            },
        }),
        ttfb: Duration::from_millis(30),
    })
}

fn http_task(target: Value, scheme: &str, path: &str, max_redirects: u8) -> Task {
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(30);
    let frame = json!({
        "type": "task", "task_id": "t1", "attempt_id": "a1", "kind": "http",
        "target": target,
        "options": {"count": 1, "interval_ms": 1000, "timeout_ms": 10000,
                    "scheme": scheme, "path": path, "max_redirects": max_redirects},
        "expires_at": expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
    });
    match serde_json::from_value(frame).unwrap() {
        ServerFrame::Task(task) => task,
        other => panic!("not a task: {other:?}"),
    }
}

fn pinned(max_redirects: u8) -> Task {
    http_task(
        json!({"ip": "93.184.216.34", "port": 443, "server_name": "example.com"}),
        "https",
        "/a",
        max_redirects,
    )
}

async fn run(prober: Arc<ScriptedHttp>, task: Task) -> Vec<ClientFrame> {
    let runner = Runner::new(prober, resolver(), Policy::public_only(), caps());
    let (tx, mut rx) = mpsc::channel(64);
    runner.run(task, tx, CancellationToken::new()).await;
    let mut frames = vec![];
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }
    frames
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
    assert_eq!(
        samples.len(),
        1,
        "an http task yields one sample: {frames:?}"
    );
    samples.into_iter().next().unwrap()
}

fn result_of(frames: &[ClientFrame]) -> (ResultStatus, Option<String>, Option<String>) {
    match frames.last().expect("no frames") {
        ClientFrame::TaskResult {
            status,
            tested_ip,
            error_code,
            ..
        } => (*status, tested_ip.clone(), error_code.clone()),
        other => panic!("last frame is not a result: {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_request_reports_status_timings_certificate_and_where_it_went() {
    let prober = ScriptedHttp::with(vec![response(200, None)]);
    let frames = run(prober.clone(), pinned(0)).await;

    assert!(matches!(frames[0], ClientFrame::TaskAck { .. }));
    let sample = sample_of(&frames);
    assert_eq!(sample.status, SampleStatus::Ok);
    assert_eq!(sample.rtt_us, Some(40_000), "the request took 40 ms in all");
    let d = &sample.detail;
    assert_eq!(d["status_code"], 200);
    assert_eq!(d["http_version"], "HTTP/1.1");
    assert_eq!(d["server"], "test-server");
    assert_eq!(d["connect_us"], 8_000);
    assert_eq!(d["tls_us"], 21_000);
    assert_eq!(d["ttfb_us"], 30_000);
    assert_eq!(d["total_us"], 40_000);
    assert_eq!(d["dns_us"], 0, "a pinned address needs no lookup");
    assert_eq!(d["final_host"], "example.com");
    assert_eq!(d["final_path"], "/a");
    assert_eq!(d["tls"]["verified"], true);
    assert_eq!(d["tls"]["issuer"], "CN=Test CA");
    assert!(d.get("redirects").is_none());

    let request = &prober.requests()[0];
    assert_eq!(request.ip, "93.184.216.34".parse::<IpAddr>().unwrap());
    assert_eq!(request.port, 443);
    assert_eq!(request.tls_name.as_deref(), Some("example.com"));
    assert_eq!(request.host_header, "example.com");
    assert_eq!(request.path, "/a");

    let (status, tested, code) = result_of(&frames);
    assert_eq!(
        (status, tested.as_deref(), code),
        (ResultStatus::Completed, Some("93.184.216.34"), None)
    );
}

#[tokio::test(start_paused = true)]
async fn an_address_without_a_name_presents_the_address() {
    let prober = ScriptedHttp::with(vec![response(200, None), response(200, None)]);
    run(
        prober.clone(),
        http_task(json!({"ip": "93.184.216.34", "port": 80}), "http", "/", 0),
    )
    .await;
    run(
        prober.clone(),
        http_task(
            json!({"ip": "2606:4700:4700::1111", "port": 8443}),
            "https",
            "/",
            0,
        ),
    )
    .await;
    let requests = prober.requests();
    assert_eq!(requests[0].host_header, "93.184.216.34");
    assert_eq!(requests[0].tls_name, None, "plain http");
    assert_eq!(requests[1].host_header, "[2606:4700:4700::1111]:8443");
    assert_eq!(
        requests[1].tls_name.as_deref(),
        Some("2606:4700:4700::1111")
    );
}

#[tokio::test(start_paused = true)]
async fn a_hostname_is_resolved_on_the_node_and_the_lookup_is_timed() {
    let prober = ScriptedHttp::with(vec![response(200, None)]);
    let frames = run(
        prober.clone(),
        http_task(
            json!({"hostname": "www.example.com", "port": 443}),
            "https",
            "/",
            0,
        ),
    )
    .await;
    let request = &prober.requests()[0];
    assert_eq!(request.ip, "93.184.216.35".parse::<IpAddr>().unwrap());
    assert_eq!(request.tls_name.as_deref(), Some("www.example.com"));
    assert!(sample_of(&frames).detail.get("dns_us").is_some());
}

#[tokio::test(start_paused = true)]
async fn a_redirect_is_reported_not_followed_unless_asked() {
    let prober = ScriptedHttp::with(vec![response(
        301,
        Some("https://www.example.com/x?token=secret"),
    )]);
    let frames = run(prober.clone(), pinned(0)).await;
    let sample = sample_of(&frames);
    assert_eq!(sample.status, SampleStatus::Ok);
    assert_eq!(sample.detail["status_code"], 301);
    assert_eq!(
        sample.detail["redirects"],
        json!([{"status_code": 301, "location_scheme": "https", "location_host": "www.example.com",
                "location_port": 443, "location_path": "/x", "followed": false}])
    );
    assert!(
        !sample.detail.to_string().contains("secret"),
        "no query string is ever reported"
    );
    assert_eq!(prober.requests().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn redirects_are_followed_with_the_policy_applied_to_every_hop() {
    let prober = ScriptedHttp::with(vec![
        response(301, Some("https://www.example.com/next?q=1")),
        response(302, Some("/final")),
        response(200, None),
    ]);
    let frames = run(prober.clone(), pinned(5)).await;

    let requests = prober.requests();
    assert_eq!(requests.len(), 3);
    // The query string is for the server being followed to, and never reported.
    assert_eq!(requests[1].path, "/next?q=1");
    assert_eq!(requests[1].ip, "93.184.216.35".parse::<IpAddr>().unwrap());
    assert_eq!(requests[1].host_header, "www.example.com");
    assert_eq!(requests[2].path, "/final");
    assert_eq!(requests[2].host_header, "www.example.com");

    let sample = sample_of(&frames);
    assert_eq!(sample.status, SampleStatus::Ok);
    assert_eq!(sample.rtt_us, Some(120_000), "three requests of 40 ms");
    assert_eq!(sample.detail["status_code"], 200);
    assert_eq!(sample.detail["final_host"], "www.example.com");
    assert_eq!(sample.detail["final_path"], "/final");
    let redirects = sample.detail["redirects"].as_array().unwrap();
    assert_eq!(redirects.len(), 2);
    assert!(redirects.iter().all(|r| r["followed"] == true));
    assert!(!sample.detail.to_string().contains("q=1"));

    // The task still names the address the backend pinned.
    assert_eq!(result_of(&frames).1.as_deref(), Some("93.184.216.34"));
}

#[tokio::test(start_paused = true)]
async fn redirects_to_places_the_policy_forbids_stop_the_request() {
    for location in [
        "http://10.0.0.5/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://internal.example.com/",
        "https://example.com:6379/",
        "ftp://example.com/",
        "https://user:pw@example.com/",
        "http://",
    ] {
        let prober = ScriptedHttp::with(vec![response(302, Some(location)), response(200, None)]);
        let frames = run(prober.clone(), pinned(5)).await;
        let sample = sample_of(&frames);
        assert_eq!(sample.status, SampleStatus::Error, "{location}");
        assert_eq!(
            sample.code.as_deref(),
            Some("redirect_blocked"),
            "{location}"
        );
        assert_eq!(
            sample.detail["redirects"][0]["followed"], false,
            "{location}"
        );
        assert_eq!(
            prober.requests().len(),
            1,
            "{location} must not be requested"
        );
        assert_eq!(result_of(&frames).0, ResultStatus::Completed);
    }
}

#[tokio::test(start_paused = true)]
async fn the_redirect_limit_is_enforced() {
    let prober = ScriptedHttp::with(vec![
        response(301, Some("/1")),
        response(301, Some("/2")),
        response(301, Some("/3")),
        response(200, None),
    ]);
    let frames = run(prober.clone(), pinned(2)).await;
    let sample = sample_of(&frames);
    assert_eq!(sample.code.as_deref(), Some(error_code::TOO_MANY_REDIRECTS));
    assert_eq!(
        prober.requests().len(),
        3,
        "the original request and two follows"
    );
}

#[tokio::test(start_paused = true)]
async fn the_whole_chain_shares_one_time_budget() {
    // 40 ms per request against a 10 s budget is fine; make each request take 6 s.
    let prober = Arc::new(ScriptedHttp {
        outcomes: Mutex::new(
            vec![
                response(301, Some("/1")),
                response(301, Some("/2")),
                response(200, None),
            ]
            .into(),
        ),
        latency: Duration::from_secs(6),
        ..Default::default()
    });
    let frames = run(prober.clone(), pinned(5)).await;
    let sample = sample_of(&frames);
    assert_eq!(sample.status, SampleStatus::Timeout);
    assert_eq!(sample.rtt_us, None);
    assert_eq!(
        prober.requests().len(),
        2,
        "no third request once the budget is spent"
    );
}

#[tokio::test(start_paused = true)]
async fn failures_keep_what_was_learned_before_them() {
    let mut failure = HttpFailure::new(
        error_code::TLS_CERTIFICATE_INVALID,
        "the certificate has expired",
    );
    failure.connect = Some(Duration::from_millis(9));
    failure.tls = Some(TlsHandshake {
        elapsed: Duration::from_millis(18),
        info: TlsInfo {
            version: Some("TLSv1.2".into()),
            cipher: None,
            subject: Some("CN=expired.example.com".into()),
            issuer: Some("CN=Test CA".into()),
            not_before: None,
            not_after: Some("2020-01-01T00:00:00Z".into()),
            verified: false,
            verify_error: Some("the certificate has expired".into()),
        },
    });
    let frames = run(
        ScriptedHttp::with(vec![HttpOutcome::Failed(failure)]),
        pinned(0),
    )
    .await;
    let sample = sample_of(&frames);
    assert_eq!(sample.status, SampleStatus::Error);
    assert_eq!(sample.code.as_deref(), Some("tls_certificate_invalid"));
    assert_eq!(sample.rtt_us, None);
    assert_eq!(sample.detail["connect_us"], 9_000);
    assert_eq!(sample.detail["tls"]["verified"], false);
    assert_eq!(
        sample.detail["tls"]["verify_error"],
        "the certificate has expired"
    );
    assert!(sample.detail.get("status_code").is_none());
    assert_eq!(result_of(&frames).0, ResultStatus::Completed);

    let refused = HttpOutcome::Failed(HttpFailure::new(error_code::CONNECTION_REFUSED, "refused"));
    let frames = run(ScriptedHttp::with(vec![refused]), pinned(0)).await;
    assert_eq!(
        sample_of(&frames).code.as_deref(),
        Some("connection_refused")
    );
}

#[tokio::test(start_paused = true)]
async fn tasks_that_could_smuggle_a_request_are_refused_before_anything_happens() {
    let cases = [
        ("path with a space", pinned_with_path("/a b")),
        (
            "path that ends the request line",
            pinned_with_path("/a\r\nX-Evil: 1"),
        ),
        ("relative path", pinned_with_path("a")),
        ("scheme-relative path", pinned_with_path("")),
        (
            "port off the list",
            http_task(json!({"ip": "93.184.216.34", "port": 9200}), "http", "/", 0),
        ),
        (
            "no port",
            http_task(json!({"ip": "93.184.216.34"}), "http", "/", 0),
        ),
        (
            "internal server name",
            http_task(
                json!({"ip": "93.184.216.34", "port": 80, "server_name": "localhost"}),
                "http",
                "/",
                0,
            ),
        ),
        (
            "too many redirects",
            http_task(json!({"ip": "93.184.216.34", "port": 80}), "http", "/", 9),
        ),
    ];
    for (name, task) in cases {
        let prober = ScriptedHttp::with(vec![response(200, None)]);
        let frames = run(prober.clone(), task).await;
        assert_eq!(frames.len(), 1, "{name}: {frames:?}");
        assert_eq!(result_of(&frames).0, ResultStatus::Failed, "{name}");
        assert!(prober.requests().is_empty(), "{name}");
    }
}

fn pinned_with_path(path: &str) -> Task {
    http_task(
        json!({"ip": "93.184.216.34", "port": 443, "server_name": "example.com"}),
        "https",
        path,
        0,
    )
}

#[tokio::test(start_paused = true)]
async fn a_node_without_http_does_not_run_it() {
    let runner = Runner::new(
        ScriptedHttp::with(vec![response(200, None)]),
        resolver(),
        Policy::public_only(),
        Capabilities {
            kinds: vec!["ping".into()],
            ipv4: true,
            ipv6: true,
        },
    );
    let (tx, mut rx) = mpsc::channel(8);
    runner.run(pinned(0), tx, CancellationToken::new()).await;
    let Some(ClientFrame::TaskResult { error_code, .. }) = rx.try_recv().ok() else {
        panic!("expected a result")
    };
    assert_eq!(error_code.as_deref(), Some("unsupported_kind"));
}
