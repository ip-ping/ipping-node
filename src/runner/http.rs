//! The HTTP check: one request to the target, optionally following redirects.
//!
//! The first request goes to the address the task pinned. A redirect sends the node somewhere the
//! backend never vetted, so every hop is resolved here and goes through the destination policy
//! again (public addresses only, allowed ports only, http/https only, no credentials in the URL).
//! The sample reports where the request ended up, but never a query string.

use std::net::IpAddr;
use std::time::Duration;

use tokio::time::Instant;
use url::{Host, Url};

use super::{Failure, Job, Runner, micros};
use crate::policy::validate_hostname;
use crate::probes::Prober;
use crate::probes::http::{HttpDetail, HttpFailure, HttpOutcome, HttpRequest, RedirectHop};
use crate::protocol::{Family, SampleStatus, Scheme, Task, error_code};
use crate::resolve::Resolve;

pub const MAX_REDIRECTS: u8 = 5;
const MAX_PATH_BYTES: usize = 256;

/// Where one request goes.
struct Hop {
    ip: IpAddr,
    port: u16,
    scheme: Scheme,
    /// The name (or IP literal) the request presents: the `Host` header and the TLS server name.
    host: String,
    /// Path and query, as sent on the request line.
    target: String,
    /// Time spent resolving this hop's name on this node.
    dns: Duration,
}

impl Hop {
    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = match self.scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    fn url(&self) -> Option<Url> {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let scheme = match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        Url::parse(&format!("{scheme}://{host}:{}{}", self.port, self.target)).ok()
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// A request target the node is willing to put on the wire: an absolute path made of visible
/// ASCII, so nothing in it can end the request line or start another request.
fn valid_target(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_PATH_BYTES
        && path.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

impl<P: Prober, R: Resolve> Runner<P, R> {
    /// The name this task presents: the one the backend gave with a pinned address, the hostname
    /// being resolved, or (for a bare address) the address itself.
    pub(super) fn presented_host(&self, task: &Task) -> Result<String, Failure> {
        let name = task
            .target
            .server_name
            .as_deref()
            .or(task.target.hostname.as_deref());
        match name {
            Some(name) => validate_hostname(name)
                .map_err(|e| Failure::new(error_code::BLOCKED_BY_POLICY, e.to_string())),
            None => {
                task.target.ip.clone().ok_or_else(|| {
                    Failure::new(error_code::INTERNAL_ERROR, "The task has no target.")
                })
            }
        }
    }

    pub(super) fn check_http(&self, task: &Task) -> Result<(), Failure> {
        let options = &task.options;
        let bad = |what: &str| Failure::new(error_code::INTERNAL_ERROR, what.to_owned());
        if !super::TIMEOUT_MS.contains(&options.timeout_ms) {
            return Err(bad("Task options are outside this node's limits."));
        }
        if options.max_redirects.unwrap_or(0) > MAX_REDIRECTS {
            return Err(bad("Too many redirects requested."));
        }
        let (Some(_), Some(path)) = (options.scheme, options.path.as_deref()) else {
            return Err(bad("An http task needs a scheme and a path."));
        };
        if !valid_target(path) {
            return Err(bad("The request path is not acceptable."));
        }
        let port = task.target.port.unwrap_or(0);
        self.policy
            .check_port(port)
            .map_err(|e| Failure::new(error_code::PORT_NOT_ALLOWED, e.to_string()))?;
        self.presented_host(task).map(|_| ())
    }

    pub(super) async fn run_http(
        &self,
        task: &Task,
        job: &Job,
        first_ip: IpAddr,
        resolved: &[IpAddr],
        dns: Duration,
    ) {
        // `check_http` has validated all of this.
        let (Some(scheme), Some(path), Some(port), Ok(host)) = (
            task.options.scheme,
            task.options.path.clone(),
            task.target.port,
            self.presented_host(task),
        ) else {
            job.fail(Failure::new(
                error_code::INTERNAL_ERROR,
                "Invalid http task.",
            ))
            .await;
            return;
        };
        let family = task.target.family;
        let max_redirects = usize::from(task.options.max_redirects.unwrap_or(0));
        let budget = Duration::from_millis(task.options.timeout_ms);
        let started = Instant::now();

        let mut detail = HttpDetail::default();
        let mut hop = Hop {
            ip: first_ip,
            port,
            scheme,
            host,
            target: path,
            dns,
        };
        // How the sample ends: set exactly once, by the loop below.
        let (status, code): (SampleStatus, Option<&'static str>);

        let mut followed = 0;
        loop {
            let used = hop.dns + started.elapsed();
            let Some(remaining) = budget.checked_sub(used).filter(|r| !r.is_zero()) else {
                (status, code) = (SampleStatus::Timeout, None);
                break;
            };
            detail.dns_us = Some(micros(hop.dns));
            detail.final_scheme = Some(scheme_name(hop.scheme).to_owned());
            detail.final_host = Some(hop.host.clone());
            detail.final_path = Some(path_only(&hop.target));
            let request = HttpRequest {
                ip: hop.ip,
                port: hop.port,
                tls_name: (hop.scheme == Scheme::Https).then(|| hop.host.clone()),
                host_header: hop.host_header(),
                path: hop.target.clone(),
                timeout: remaining,
            };
            let outcome = tokio::select! {
                () = job.cancel.cancelled() => return,
                outcome = self.prober.http_once(request) => outcome,
            };
            match outcome {
                HttpOutcome::Timeout => {
                    (status, code) = (SampleStatus::Timeout, None);
                    break;
                }
                HttpOutcome::Failed(failure) => {
                    note_failure(&mut detail, &failure);
                    (status, code) = (SampleStatus::Error, Some(failure.code));
                    break;
                }
                HttpOutcome::Response(response) => {
                    detail.status_code = Some(response.status);
                    detail.http_version = Some(response.version.to_owned());
                    detail.server = response.server.clone();
                    detail.content_type = response.content_type.clone();
                    detail.connect_us = Some(micros(response.connect));
                    detail.tls_us = response.tls.as_ref().map(|t| micros(t.elapsed));
                    detail.tls = response.tls.as_ref().map(|t| t.info.clone());
                    detail.ttfb_us = Some(micros(response.ttfb));

                    let location = response
                        .location
                        .as_deref()
                        .filter(|_| is_redirect(response.status));
                    let (Some(location), Some(base)) = (location, hop.url()) else {
                        (status, code) = (SampleStatus::Ok, None);
                        break;
                    };
                    let next = base.join(location);
                    let mut record = redirect_record(response.status, next.as_ref().ok());
                    if max_redirects == 0 {
                        // Reporting the redirect is the result; the caller did not ask to follow.
                        detail.redirects.push(record);
                        (status, code) = (SampleStatus::Ok, None);
                        break;
                    }
                    if followed >= max_redirects {
                        detail.redirects.push(record);
                        (status, code) =
                            (SampleStatus::Error, Some(error_code::TOO_MANY_REDIRECTS));
                        break;
                    }
                    let next_hop = match next {
                        Ok(url) => tokio::select! {
                            () = job.cancel.cancelled() => return,
                            hop = self.next_hop(&url, family) => hop,
                        },
                        Err(_) => Err(Failure::new(
                            error_code::REDIRECT_BLOCKED,
                            "The redirect target is not a valid URL.",
                        )),
                    };
                    match next_hop {
                        Ok(next_hop) => {
                            record.followed = true;
                            detail.redirects.push(record);
                            hop = next_hop;
                            followed += 1;
                        }
                        Err(failure) => {
                            detail.redirects.push(record);
                            (status, code) = (SampleStatus::Error, Some(failure.code));
                            break;
                        }
                    }
                }
            }
        }

        let total = dns + started.elapsed();
        detail.total_us = Some(micros(total));
        let rtt_us = (status == SampleStatus::Ok).then(|| micros(total));
        let detail = serde_json::to_value(&detail).ok();
        if job
            .sample_with(0, status, rtt_us, code, detail)
            .await
            .is_ok()
        {
            job.completed(first_ip, resolved).await;
        }
    }

    /// Check a redirect target against the policy and work out where to send the next request.
    async fn next_hop(&self, url: &Url, family: Family) -> Result<Hop, Failure> {
        let blocked = |why: String| Failure::new(error_code::REDIRECT_BLOCKED, why);
        let scheme = match url.scheme() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            other => return Err(blocked(format!("Redirects to {other}: are not followed."))),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(blocked("The redirect target contains credentials.".into()));
        }
        let port = url
            .port_or_known_default()
            .ok_or_else(|| blocked("The redirect target has no port.".into()))?;
        self.policy
            .check_port(port)
            .map_err(|e| blocked(e.to_string()))?;

        let started = Instant::now();
        let (ip, host) = match url.host() {
            Some(Host::Domain(domain)) => {
                let name = validate_hostname(domain).map_err(|e| blocked(e.to_string()))?;
                let (ip, _) = self.resolve_name(&name, family).await.map_err(|f| {
                    if f.code == error_code::BLOCKED_BY_POLICY {
                        blocked(f.message)
                    } else {
                        f
                    }
                })?;
                (ip, name)
            }
            Some(Host::Ipv4(address)) => self.literal_hop(IpAddr::V4(address), family)?,
            Some(Host::Ipv6(address)) => self.literal_hop(IpAddr::V6(address), family)?,
            None => return Err(blocked("The redirect target has no host.".into())),
        };
        let mut target = url.path().to_owned();
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        if !valid_target(&target) {
            return Err(blocked("The redirect path is not acceptable.".into()));
        }
        Ok(Hop {
            ip,
            port,
            scheme,
            host,
            target,
            dns: started.elapsed(),
        })
    }

    fn literal_hop(&self, ip: IpAddr, family: Family) -> Result<(IpAddr, String), Failure> {
        self.policy
            .check_ip(ip)
            .map_err(|e| Failure::new(error_code::REDIRECT_BLOCKED, e.to_string()))?;
        self.check_literal(ip, family)?;
        Ok((ip, ip.to_string()))
    }
}

fn scheme_name(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    }
}

/// The path of a request target, without its query string.
fn path_only(target: &str) -> String {
    let path = target.split('?').next().unwrap_or("/");
    path.chars().take(200).collect()
}

fn redirect_record(status: u16, to: Option<&Url>) -> RedirectHop {
    RedirectHop {
        status_code: status,
        location_scheme: to.map(|u| u.scheme().to_owned()),
        location_host: to.and_then(|u| match u.host() {
            Some(Host::Domain(d)) => Some(d.to_owned()),
            Some(Host::Ipv4(a)) => Some(a.to_string()),
            Some(Host::Ipv6(a)) => Some(a.to_string()),
            None => None,
        }),
        location_port: to.and_then(Url::port_or_known_default),
        location_path: to.map(|u| u.path().chars().take(200).collect()),
        followed: false,
    }
}

fn note_failure(detail: &mut HttpDetail, failure: &HttpFailure) {
    detail.connect_us = failure.connect.map(micros);
    detail.tls_us = failure.tls.as_ref().map(|t| micros(t.elapsed));
    detail.tls = failure.tls.as_ref().map(|t| t.info.clone());
}
