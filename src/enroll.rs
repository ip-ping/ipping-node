//! One-time enrollment: trade a short-lived token for this node's own credential.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::server_url::{self, UrlError};

#[derive(Debug, Clone, Default, Serialize)]
pub struct Details {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct Enrolled {
    pub node_id: String,
    pub credential: String,
    pub status: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error(transparent)]
    Url(#[from] UrlError),
    #[error("the enrollment token was refused: it is invalid, already used or expired")]
    TokenRefused,
    #[error("too many enrollment attempts; wait a minute and retry")]
    RateLimited,
    #[error("the backend rejected the request ({status}): {message}")]
    Rejected { status: u16, message: String },
    #[error("could not reach the backend: {0}")]
    Network(String),
}

#[derive(Serialize)]
struct Request<'a> {
    token: &'a str,
    #[serde(flatten)]
    details: &'a Details,
}

/// Blocking HTTP, so run it with `spawn_blocking` from async code.
pub fn enroll(server: &str, token: &str, details: &Details) -> Result<Enrolled, EnrollError> {
    let url = server_url::http_url(server, "api/v1/nodes/enroll")?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut response = agent
        .post(url.as_str())
        .send_json(Request { token, details })
        .map_err(|e| EnrollError::Network(e.to_string()))?;
    let status = response.status().as_u16();
    match status {
        201 => response
            .body_mut()
            .read_json()
            .map_err(|e| EnrollError::Network(format!("unexpected reply: {e}"))),
        403 => Err(EnrollError::TokenRefused),
        429 => Err(EnrollError::RateLimited),
        _ => {
            let body: serde_json::Value = response.body_mut().read_json().unwrap_or_default();
            let message = body["error"]["message"]
                .as_str()
                .unwrap_or("no details")
                .to_owned();
            Err(EnrollError::Rejected { status, message })
        }
    }
}
