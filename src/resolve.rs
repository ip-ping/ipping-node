//! Hostname resolution, behind a trait so tests can supply answers.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

pub trait Resolve: Send + Sync + 'static {
    fn lookup(&self, host: &str) -> impl Future<Output = io::Result<Vec<IpAddr>>> + Send;
}

/// The operating system's resolver, with a hard time limit.
pub struct SystemResolver;

impl Resolve for SystemResolver {
    async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let lookup = tokio::net::lookup_host((host, 0));
        let addresses = tokio::time::timeout(Duration::from_secs(5), lookup)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS lookup timed out"))??;
        let mut unique: Vec<IpAddr> = Vec::new();
        for address in addresses {
            if !unique.contains(&address.ip()) {
                unique.push(address.ip());
            }
        }
        Ok(unique)
    }
}
