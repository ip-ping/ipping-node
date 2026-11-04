//! Which destinations this node will probe.
//!
//! The backend already filters targets; the node repeats the check so that a compromised or
//! buggy backend cannot point it at a private network. Only globally routable unicast addresses
//! pass. The rule is deliberately an allowlist of "public", not a blocklist of "RFC 1918".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IPv4 ranges that are not valid public unicast destinations, from the IANA special-purpose
/// registry (plus multicast and the reserved class E block).
const BLOCKED_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),       // "this network"
    (Ipv4Addr::new(10, 0, 0, 0), 8),      // private
    (Ipv4Addr::new(100, 64, 0, 0), 10),   // carrier-grade NAT
    (Ipv4Addr::new(127, 0, 0, 0), 8),     // loopback
    (Ipv4Addr::new(169, 254, 0, 0), 16),  // link-local, includes cloud metadata
    (Ipv4Addr::new(172, 16, 0, 0), 12),   // private
    (Ipv4Addr::new(192, 0, 0, 0), 24),    // IETF protocol assignments
    (Ipv4Addr::new(192, 0, 2, 0), 24),    // documentation
    (Ipv4Addr::new(192, 88, 99, 0), 24),  // deprecated 6to4 relay
    (Ipv4Addr::new(192, 168, 0, 0), 16),  // private
    (Ipv4Addr::new(198, 18, 0, 0), 15),   // benchmarking
    (Ipv4Addr::new(198, 51, 100, 0), 24), // documentation
    (Ipv4Addr::new(203, 0, 113, 0), 24),  // documentation
    (Ipv4Addr::new(224, 0, 0, 0), 4),     // multicast
    (Ipv4Addr::new(240, 0, 0, 0), 4),     // reserved, includes broadcast
];

/// IPv6 ranges that are not valid public unicast destinations. Ranges that embed or translate
/// to an IPv4 address (NAT64, 6to4, Teredo, IPv4-mapped) are refused outright because the
/// embedded address could be private.
const BLOCKED_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::UNSPECIFIED, 96), // ::/96 incl. :: and ::a.b.c.d
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96), // IPv4-mapped
    (Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96), // NAT64
    (Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48), // local-use NAT64
    (Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 64), // discard-only
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23), // IETF assignments, Teredo
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32), // documentation
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16), // 6to4
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20), // documentation
    (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16), // SRv6 SIDs
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7), // unique local
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10), // link-local
    (Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10), // deprecated site-local
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8), // multicast
];

fn v4_in(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(ip) & mask == u32::from(net) & mask
}

fn v6_in(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
    u128::from(ip) & mask == u128::from(net) & mask
}

pub fn is_public_v4(ip: Ipv4Addr) -> bool {
    !BLOCKED_V4
        .iter()
        .any(|&(net, prefix)| v4_in(ip, net, prefix))
}

pub fn is_public_v6(ip: Ipv6Addr) -> bool {
    !BLOCKED_V6
        .iter()
        .any(|&(net, prefix)| v6_in(ip, net, prefix))
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("{0} is not a public address")]
    NotPublic(IpAddr),
    #[error("not a valid IP address")]
    InvalidAddress,
    #[error("not a valid public hostname")]
    InvalidHostname,
}

/// The node's destination rules. Production code only ever builds [`Policy::public_only`].
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    allow_non_public: bool,
}

impl Policy {
    pub const fn public_only() -> Self {
        Self {
            allow_non_public: false,
        }
    }

    /// For tests that must probe loopback. The command line never exposes this.
    pub const fn permissive_for_tests() -> Self {
        Self {
            allow_non_public: true,
        }
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<IpAddr, PolicyError> {
        if self.allow_non_public || is_public(ip) {
            Ok(ip)
        } else {
            Err(PolicyError::NotPublic(ip))
        }
    }

    /// Parse a literal address from a task and apply the policy. Scoped addresses
    /// (`fe80::1%eth0`) and anything that is not a plain literal are rejected by the parser.
    pub fn parse_ip(&self, text: &str) -> Result<IpAddr, PolicyError> {
        let ip: IpAddr = text.parse().map_err(|_| PolicyError::InvalidAddress)?;
        self.check_ip(ip)
    }
}

const INTERNAL_SUFFIXES: &[&str] = &[
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
    ".home.arpa",
    ".onion",
];

/// Check a hostname before asking DNS about it. Returns it lower-cased without a trailing dot.
/// Names must be ASCII (the backend sends punycode), have at least two labels and not end in a
/// number, which some resolvers would read as an IPv4 shorthand such as `127.1`.
pub fn validate_hostname(host: &str) -> Result<String, PolicyError> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" || INTERNAL_SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return Err(PolicyError::InvalidHostname);
    }
    let labels: Vec<&str> = host.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if host.len() > 253
        || labels.len() < 2
        || !labels.iter().all(label_ok)
        || labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(PolicyError::InvalidHostname);
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn private_and_special_addresses_are_refused() {
        for s in [
            "0.0.0.0",
            "127.0.0.1",
            "127.255.255.254",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "ff02::1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "2002:7f00:1::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
            "::7f00:1",
            "100::1",
            "fec0::1",
        ] {
            assert!(!is_public(ip(s)), "{s} must be refused");
        }
    }

    #[test]
    fn public_addresses_pass() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2a00:1450:4001:81b::200e",
        ] {
            assert!(is_public(ip(s)), "{s} must be allowed");
        }
    }

    #[test]
    fn policy_parses_literals_strictly() {
        let policy = Policy::public_only();
        assert_eq!(policy.parse_ip("8.8.8.8"), Ok(ip("8.8.8.8")));
        assert_eq!(
            policy.parse_ip("127.0.0.1"),
            Err(PolicyError::NotPublic(ip("127.0.0.1")))
        );
        for bad in [
            "",
            "example.com",
            "127.1",
            "0x7f.0.0.1",
            "8.8.8.8:53",
            "fe80::1%eth0",
            " 8.8.8.8",
        ] {
            assert_eq!(
                policy.parse_ip(bad),
                Err(PolicyError::InvalidAddress),
                "{bad:?}"
            );
        }
        assert_eq!(
            Policy::permissive_for_tests().parse_ip("127.0.0.1"),
            Ok(ip("127.0.0.1"))
        );
    }

    #[test]
    fn hostnames_are_validated() {
        assert_eq!(
            validate_hostname("Example.COM.").as_deref(),
            Ok("example.com")
        );
        assert_eq!(
            validate_hostname("xn--bcher-kva.example").as_deref(),
            Ok("xn--bcher-kva.example")
        );
        for bad in [
            "",
            "localhost",
            "foo.localhost",
            "printer.local",
            "db.internal",
            "singlelabel",
            "127.1",
            "2130706433",
            "1.2.3.4",
            "-bad.example.com",
            "bad-.example.com",
            "exa mple.com",
            "ünicode.example",
            "a..b.com",
        ] {
            assert_eq!(
                validate_hostname(bad),
                Err(PolicyError::InvalidHostname),
                "{bad:?}"
            );
        }
        let too_long_label = format!("{}.example.com", "a".repeat(64));
        assert!(validate_hostname(&too_long_label).is_err());
    }
}
