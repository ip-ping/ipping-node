//! The long-lived connection to the backend.
//!
//! The node dials out, says hello, then serves tasks until the connection drops or the process
//! is told to stop. Reconnection uses jittered exponential backoff so a restarting backend is not
//! hit by every node at the same instant.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use time::OffsetDateTime;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant, interval, timeout};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_util::sync::CancellationToken;

use crate::policy::Policy;
use crate::probes::icmp::IcmpProber;
use crate::protocol::{
    ClientFrame, MAX_FRAME_BYTES, NodeStatus, PROTOCOL_VERSION, ResultStatus, ServerFrame, Welcome,
    error_code,
};
use crate::resolve::SystemResolver;
use crate::runner::Runner;
use crate::server_url::{self, UrlError};

const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A session this long counts as healthy and resets the backoff.
const HEALTHY_SESSION: Duration = Duration::from_secs(30);
/// Frames waiting to be sent to the backend; tasks block (and so slow down) rather than grow it.
const OUTBOUND_BUFFER: usize = 256;

pub struct Settings {
    pub server: String,
    pub credential: String,
    /// Local ceiling on simultaneous tasks, applied on top of what the backend allows.
    pub max_concurrent_tasks: usize,
}

#[derive(Debug, thiserror::Error)]
enum SessionError {
    #[error(transparent)]
    Url(#[from] UrlError),
    #[error(
        "the backend refused this node's credential (HTTP {0}); it may have been revoked or rotated"
    )]
    Rejected(u16),
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("the backend closed the connection")]
    Closed,
    #[error("no data from the backend for too long")]
    Silent,
}

/// Run until `shutdown` is cancelled, reconnecting as needed.
pub async fn run(settings: Settings, shutdown: CancellationToken) {
    let prober = Arc::new(IcmpProber::new());
    if !prober.has_any_socket() {
        tracing::error!(
            "cannot open ICMP sockets. Allow unprivileged ping (sysctl net.ipv4.ping_group_range) or \
             grant CAP_NET_RAW; the node will connect but every task will fail until then"
        );
    }
    let mut backoff = MIN_BACKOFF;
    loop {
        let started = Instant::now();
        let result = session(&settings, &prober, &shutdown).await;
        if shutdown.is_cancelled() {
            return;
        }
        match &result {
            Ok(()) => tracing::info!("disconnected"),
            Err(error @ (SessionError::Rejected(_) | SessionError::Url(_))) => {
                tracing::error!(%error);
                backoff = MAX_BACKOFF;
            }
            Err(error) => tracing::warn!(%error, "session ended"),
        }
        if started.elapsed() >= HEALTHY_SESSION {
            backoff = MIN_BACKOFF;
        }
        let wait = jitter(backoff);
        tracing::info!(seconds = wait.as_secs_f32(), "reconnecting");
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(wait) => {}
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn jitter(base: Duration) -> Duration {
    base.mul_f64(rand::random_range(0.8..1.2))
}

fn encode(frame: &ClientFrame) -> Message {
    Message::text(serde_json::to_string(frame).expect("frames always serialise"))
}

async fn session(
    settings: &Settings,
    prober: &Arc<IcmpProber>,
    shutdown: &CancellationToken,
) -> Result<(), SessionError> {
    let url = server_url::ws_url(&settings.server, "api/v1/nodes/connect")?;
    let mut request = url
        .into_client_request()
        .map_err(|e| SessionError::Connect(e.to_string()))?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", settings.credential)
            .parse()
            .map_err(|_| SessionError::Connect("credential is not valid header text".into()))?,
    );

    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES));
    let (socket, _) =
        match tokio_tungstenite::connect_async_with_config(request, Some(config), false).await {
            Ok(connected) => connected,
            Err(tungstenite::Error::Http(response)) => {
                return Err(SessionError::Rejected(response.status().as_u16()));
            }
            Err(error) => return Err(SessionError::Connect(error.to_string())),
        };
    let (mut sink, mut stream) = socket.split();

    // Capabilities are checked on every connect: a route can appear or disappear.
    let capabilities = prober.capabilities();
    tracing::info!(
        ipv4 = capabilities.ipv4,
        ipv6 = capabilities.ipv6,
        "connected"
    );
    let hello = ClientFrame::Hello {
        protocol_versions: vec![PROTOCOL_VERSION],
        node_version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: capabilities.clone(),
    };
    sink.send(encode(&hello))
        .await
        .map_err(|e| SessionError::Connect(e.to_string()))?;

    let welcome = timeout(HELLO_TIMEOUT, async {
        loop {
            match stream.next().await {
                Some(Ok(Message::Text(text))) => match serde_json::from_str::<ServerFrame>(&text) {
                    Ok(ServerFrame::Welcome(welcome)) => return Ok(welcome),
                    Ok(ServerFrame::Error { code, message }) => {
                        return Err(SessionError::Protocol(format!("{code}: {message}")));
                    }
                    _ => return Err(SessionError::Protocol("expected welcome".into())),
                },
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(_)) | None => return Err(SessionError::Closed),
                Some(Err(error)) => return Err(SessionError::Connect(error.to_string())),
            }
        }
    })
    .await
    .map_err(|_| SessionError::Silent)??;
    let Welcome {
        node_status,
        limits,
        heartbeat_interval_s,
        server_time,
        ..
    } = welcome;
    match node_status {
        NodeStatus::Approved => tracing::info!("approved; ready for tasks"),
        NodeStatus::Pending => tracing::warn!("waiting for an administrator to approve this node"),
    }

    let offset = server_time - OffsetDateTime::now_utc();
    let runner = Runner::new(
        prober.clone(),
        Arc::new(SystemResolver),
        Policy::public_only(),
        capabilities,
    )
    .with_clock_offset(offset);
    let permits = settings
        .max_concurrent_tasks
        .min(limits.max_concurrent_tasks)
        .max(1);
    let slots = Arc::new(Semaphore::new(permits));

    let (out_tx, mut out_rx) = mpsc::channel::<ClientFrame>(OUTBOUND_BUFFER);
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<String>();
    let mut running: HashMap<String, CancellationToken> = HashMap::new();
    let session_token = shutdown.child_token();
    let heartbeat_every = Duration::from_secs(heartbeat_interval_s.max(1));
    let mut heartbeat = interval(heartbeat_every);
    let mut last_heard = Instant::now();

    let outcome = loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                let _ = sink.send(Message::Close(None)).await;
                break Ok(());
            }
            incoming = stream.next() => {
                last_heard = Instant::now();
                let text = match incoming {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Close(_))) | None => break Err(SessionError::Closed),
                    Some(Ok(_)) => continue,
                    Some(Err(error)) => break Err(SessionError::Connect(error.to_string())),
                };
                match serde_json::from_str::<ServerFrame>(&text) {
                    Ok(ServerFrame::Task(task)) => {
                        let task_id = task.task_id.clone();
                        if running.contains_key(&task_id) {
                            continue; // a retransmitted task
                        }
                        let Ok(permit) = slots.clone().try_acquire_owned() else {
                            let refusal = ClientFrame::TaskResult {
                                task_id,
                                attempt_id: task.attempt_id,
                                status: ResultStatus::Failed,
                                tested_ip: None,
                                resolved_ips: vec![],
                                error_code: Some(error_code::NODE_BUSY.to_owned()),
                                error_message: Some("The node is at its concurrency limit.".to_owned()),
                            };
                            let _ = out_tx.try_send(refusal);
                            continue;
                        };
                        let cancel = session_token.child_token();
                        running.insert(task_id.clone(), cancel.clone());
                        let (runner, out, done) = (runner.clone(), out_tx.clone(), done_tx.clone());
                        tokio::spawn(async move {
                            runner.run(task, out, cancel).await;
                            drop(permit);
                            let _ = done.send(task_id);
                        });
                    }
                    Ok(ServerFrame::Cancel { task_id }) => {
                        if let Some(token) = running.get(&task_id) {
                            token.cancel();
                        }
                    }
                    Ok(ServerFrame::Error { code, message }) => {
                        tracing::warn!(%code, %message, "backend reported an error");
                        if code == "unsupported_protocol" {
                            break Err(SessionError::Protocol(message));
                        }
                    }
                    Ok(ServerFrame::Pong | ServerFrame::Welcome(_)) => {}
                    // A newer backend may send frames this version does not know. Skip them.
                    Err(error) => tracing::debug!(%error, "ignoring a frame this version does not understand"),
                }
            }
            Some(frame) = out_rx.recv() => {
                if let Err(error) = sink.send(encode(&frame)).await {
                    break Err(SessionError::Connect(error.to_string()));
                }
            }
            Some(task_id) = done_rx.recv() => {
                running.remove(&task_id);
            }
            _ = heartbeat.tick() => {
                if last_heard.elapsed() > heartbeat_every * 3 {
                    break Err(SessionError::Silent);
                }
                if let Err(error) = sink.send(encode(&ClientFrame::Ping)).await {
                    break Err(SessionError::Connect(error.to_string()));
                }
            }
        }
    };

    // Whatever ends the session, stop work for a backend that is no longer listening.
    session_token.cancel();
    outcome
}
