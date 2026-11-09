//! DNS lookups: one question to one resolver, with the answer read back in full.
//!
//! The wire format is small and fixed, so the node speaks it directly instead of pulling in a
//! resolver library: build one query (with EDNS0 so answers rarely need TCP), send it over UDP, check
//! that the reply really answers *that* question, and fall back to TCP if the reply was cut short.
//! Everything read from the network is untrusted: names are followed only backwards (no loops),
//! lengths are checked, and the number and size of records are capped.
//!
//! This module only asks; deciding who may be asked and what may be shown is the runner's job.

use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout_at};

use crate::protocol::error_code;

/// The record types a check can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
    Soa,
}

impl RecordType {
    pub const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Txt => "TXT",
            Self::Soa => "SOA",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_uppercase().as_str() {
            "A" => Some(Self::A),
            "AAAA" => Some(Self::Aaaa),
            "CNAME" => Some(Self::Cname),
            "MX" => Some(Self::Mx),
            "NS" => Some(Self::Ns),
            "TXT" => Some(Self::Txt),
            "SOA" => Some(Self::Soa),
            _ => None,
        }
    }

    fn from_code(code: u16) -> Option<Self> {
        [
            Self::A,
            Self::Aaaa,
            Self::Cname,
            Self::Mx,
            Self::Ns,
            Self::Txt,
            Self::Soa,
        ]
        .into_iter()
        .find(|t| t.code() == code)
    }
}

/// Who to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolver {
    /// The resolvers this host is configured with (`/etc/resolv.conf`).
    System,
    /// A specific resolver, on port 53.
    Server(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRequest {
    pub name: String,
    pub record_type: RecordType,
    pub resolver: Resolver,
    pub timeout: Duration,
    /// Ask over HTTPS (DNS over HTTPS) instead of UDP: the resolver is `Resolver::Server(ip)`, on port 443.
    pub doh: Option<super::doh::DohTarget>,
}

/// One record of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub kind: RecordType,
    pub ttl: u32,
    /// The record's value as text: an address, a name, `10 mail.example.com`, the text of a TXT.
    pub data: String,
    /// Set for A and AAAA, so the runner can judge the address.
    pub address: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    /// From sending the question to reading the reply (both transports, if it came to that).
    pub rtt: Duration,
    pub rcode: u8,
    pub authoritative: bool,
    /// The answer arrived over TCP because the UDP one was cut short.
    pub via_tcp: bool,
    /// The answer is still cut short (TCP failed too); the records may be incomplete.
    pub truncated: bool,
    pub records: Vec<Record>,
}

impl DnsAnswer {
    pub fn rcode_name(&self) -> String {
        match self.rcode {
            0 => "NOERROR".into(),
            1 => "FORMERR".into(),
            2 => "SERVFAIL".into(),
            3 => "NXDOMAIN".into(),
            4 => "NOTIMP".into(),
            5 => "REFUSED".into(),
            other => format!("RCODE{other}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsOutcome {
    /// A well-formed reply, whatever it says. "No such name" is an answer.
    Answer(DnsAnswer),
    /// Nothing came back in time.
    Timeout,
    /// The question could not be asked or the reply could not be read; the value is a protocol
    /// error code.
    Failed(&'static str),
}

/// Most records of one answer that are kept, and the longest text kept for one of them.
pub const MAX_RECORDS: usize = 32;
const MAX_DATA_CHARS: usize = 512;
const MAX_TCP_MESSAGE: usize = 16 * 1024;
/// What this node tells resolvers it can receive over UDP (the commonly safe value).
const EDNS_PAYLOAD: u16 = 1232;
const MAX_SYSTEM_RESOLVERS: usize = 3;

/// Ask `request.resolver` the question and return what came back.
pub async fn lookup(request: &DnsRequest) -> DnsOutcome {
    match request.resolver {
        Resolver::Server(ip) => {
            query_server(
                SocketAddr::new(ip, 53),
                &request.name,
                request.record_type,
                request.timeout,
            )
            .await
        }
        Resolver::System => query_system(&request.name, request.record_type, request.timeout).await,
    }
}

/// Ask each of the host's resolvers in turn, the way its own programs would, sharing the time.
pub async fn query_system(name: &str, record_type: RecordType, limit: Duration) -> DnsOutcome {
    let servers = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(text) => parse_resolv_conf(&text),
        Err(_) => vec![],
    };
    if servers.is_empty() {
        return DnsOutcome::Failed(error_code::DNS_FAILURE);
    }
    let share = (limit / u32::try_from(servers.len()).unwrap_or(1)).max(Duration::from_millis(300));
    let deadline = Instant::now() + limit;
    let mut last = DnsOutcome::Timeout;
    for ip in servers {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match query_server(SocketAddr::new(ip, 53), name, record_type, share.min(left)).await {
            answer @ DnsOutcome::Answer(_) => return answer,
            // A silent resolver is worth a retry elsewhere; a failure is only reported if nothing
            // else answers.
            DnsOutcome::Timeout => {
                if !matches!(last, DnsOutcome::Failed(_)) {
                    last = DnsOutcome::Timeout;
                }
            }
            failed @ DnsOutcome::Failed(_) => last = failed,
        }
    }
    last
}

/// The nameservers of a `resolv.conf`, in order, at most three. A link-local IPv6 server needs an
/// interface name this node would have to guess, so it is skipped.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(address) = words.next() else {
            continue;
        };
        if address.contains('%') {
            continue;
        }
        if let Ok(ip) = address.parse::<IpAddr>()
            && !servers.contains(&ip)
        {
            servers.push(ip);
        }
        if servers.len() == MAX_SYSTEM_RESOLVERS {
            break;
        }
    }
    servers
}

/// Ask one server (UDP first, TCP if the reply was cut short).
pub async fn query_server(
    server: SocketAddr,
    name: &str,
    record_type: RecordType,
    limit: Duration,
) -> DnsOutcome {
    let id: u16 = rand::random();
    let Some(query) = encode_query(id, name, record_type) else {
        return DnsOutcome::Failed(error_code::INTERNAL_ERROR);
    };
    let started = Instant::now();
    let deadline = started + limit;

    let udp = match udp_exchange(server, &query, id, name, record_type, deadline).await {
        Ok(parsed) => parsed,
        Err(Exchange::Timeout) => return DnsOutcome::Timeout,
        Err(Exchange::Failed(code)) => return DnsOutcome::Failed(code),
    };
    if !udp.truncated {
        return DnsOutcome::Answer(answer(udp, started, false));
    }
    match tcp_exchange(server, &query, id, name, record_type, deadline).await {
        Ok(parsed) => DnsOutcome::Answer(answer(parsed, started, true)),
        // The cut-short answer is still an answer; say it is incomplete.
        Err(_) => DnsOutcome::Answer(answer(udp, started, false)),
    }
}

fn answer(parsed: Parsed, started: Instant, via_tcp: bool) -> DnsAnswer {
    DnsAnswer {
        rtt: started.elapsed(),
        rcode: parsed.rcode,
        authoritative: parsed.authoritative,
        via_tcp,
        truncated: parsed.truncated,
        records: parsed.records,
    }
}

enum Exchange {
    Timeout,
    Failed(&'static str),
}

fn io_code(error: &io::Error) -> &'static str {
    use io::ErrorKind::*;
    match error.kind() {
        // On a connected UDP socket an ICMP "port unreachable" arrives as a refusal.
        ConnectionRefused => error_code::CONNECTION_REFUSED,
        ConnectionReset | ConnectionAborted => error_code::CONNECTION_RESET,
        HostUnreachable => error_code::HOST_UNREACHABLE,
        NetworkUnreachable | AddrNotAvailable => error_code::UNSUPPORTED_FAMILY,
        PermissionDenied => error_code::PERMISSION_DENIED,
        _ => error_code::INTERNAL_ERROR,
    }
}

async fn udp_exchange(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    name: &str,
    record_type: RecordType,
    deadline: Instant,
) -> Result<Parsed, Exchange> {
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| Exchange::Failed(io_code(&e)))?;
    // Connecting makes the kernel drop datagrams from anywhere else.
    socket
        .connect(server)
        .await
        .map_err(|e| Exchange::Failed(io_code(&e)))?;
    socket
        .send(query)
        .await
        .map_err(|e| Exchange::Failed(io_code(&e)))?;

    let mut buffer = [0u8; 4096];
    loop {
        let read = match timeout_at(deadline, socket.recv(&mut buffer)).await {
            Err(_) => return Err(Exchange::Timeout),
            Ok(Err(e)) => return Err(Exchange::Failed(io_code(&e))),
            Ok(Ok(n)) => n,
        };
        match parse_response(&buffer[..read], id, name, record_type) {
            Ok(parsed) => return Ok(parsed),
            // Not the answer to our question (late, stray or forged): keep waiting for the real one.
            Err(ParseError::Mismatch) => continue,
            Err(ParseError::Malformed) => return Err(Exchange::Failed(error_code::PROTOCOL_ERROR)),
        }
    }
}

async fn tcp_exchange(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    name: &str,
    record_type: RecordType,
    deadline: Instant,
) -> Result<Parsed, Exchange> {
    let work = async {
        let mut stream = TcpStream::connect(server).await?;
        let length = u16::try_from(query.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query too long"))?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(query);
        stream.write_all(&framed).await?;
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await?;
        let size = usize::from(u16::from_be_bytes(prefix));
        if size > MAX_TCP_MESSAGE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "reply too long"));
        }
        let mut body = vec![0u8; size];
        stream.read_exact(&mut body).await?;
        Ok::<_, io::Error>(body)
    };
    let body = match timeout_at(deadline, work).await {
        Err(_) => return Err(Exchange::Timeout),
        Ok(Err(e)) if e.kind() == io::ErrorKind::InvalidData => {
            return Err(Exchange::Failed(error_code::PROTOCOL_ERROR));
        }
        Ok(Err(e)) => return Err(Exchange::Failed(io_code(&e))),
        Ok(Ok(body)) => body,
    };
    parse_response(&body, id, name, record_type)
        .map_err(|_| Exchange::Failed(error_code::PROTOCOL_ERROR))
}

/// The question, with an EDNS0 OPT record so a resolver may answer in more than 512 bytes.
/// `None` if the name cannot be encoded.
/// Base64 with the URL-safe alphabet and no padding (RFC 4648 section 5), as DNS over HTTPS wants it.
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

pub fn encode_query(id: u16, name: &str, record_type: RecordType) -> Option<Vec<u8>> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100u16.to_be_bytes()); // a query, recursion desired
    message.extend_from_slice(&1u16.to_be_bytes()); // one question
    message.extend_from_slice(&[0, 0, 0, 0]); // no answer or authority records
    message.extend_from_slice(&1u16.to_be_bytes()); // one additional: the OPT record
    encode_name(name, &mut message)?;
    message.extend_from_slice(&record_type.code().to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes()); // class IN
    // OPT: root name, type 41, UDP payload size in the class field, no flags, no options.
    message.push(0);
    message.extend_from_slice(&41u16.to_be_bytes());
    message.extend_from_slice(&EDNS_PAYLOAD.to_be_bytes());
    message.extend_from_slice(&[0, 0, 0, 0]);
    message.extend_from_slice(&0u16.to_be_bytes());
    Some(message)
}

fn encode_name(name: &str, out: &mut Vec<u8>) -> Option<()> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 || !label.is_ascii() {
            return None;
        }
        out.push(u8::try_from(bytes.len()).ok()?);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    Some(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Well-formed enough, but not the answer to our question.
    Mismatch,
    /// Not a DNS message we can read.
    Malformed,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    pub rcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub records: Vec<Record>,
}

/// Read a reply, requiring that it answers the question asked (same id, same name and type).
pub fn parse_response(
    buffer: &[u8],
    id: u16,
    name: &str,
    record_type: RecordType,
) -> Result<Parsed, ParseError> {
    if buffer.len() < 12 {
        return Err(ParseError::Mismatch);
    }
    if u16::from_be_bytes([buffer[0], buffer[1]]) != id {
        return Err(ParseError::Mismatch);
    }
    let flags = u16::from_be_bytes([buffer[2], buffer[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xF;
    if !is_response || opcode != 0 {
        return Err(ParseError::Mismatch);
    }
    let questions = usize::from(u16::from_be_bytes([buffer[4], buffer[5]]));
    let answers = usize::from(u16::from_be_bytes([buffer[6], buffer[7]]));
    if questions != 1 {
        return Err(ParseError::Mismatch);
    }

    let (asked, mut position) = read_name(buffer, 12).map_err(|_| ParseError::Mismatch)?;
    let fixed = buffer
        .get(position..position + 4)
        .ok_or(ParseError::Mismatch)?;
    let qtype = u16::from_be_bytes([fixed[0], fixed[1]]);
    let qclass = u16::from_be_bytes([fixed[2], fixed[3]]);
    position += 4;
    if !asked.eq_ignore_ascii_case(name.trim_end_matches('.'))
        || qtype != record_type.code()
        || qclass != 1
    {
        return Err(ParseError::Mismatch);
    }

    let mut records = Vec::new();
    for _ in 0..answers {
        let (record_name, after) = read_name(buffer, position)?;
        let header = buffer.get(after..after + 10).ok_or(ParseError::Malformed)?;
        let rtype = u16::from_be_bytes([header[0], header[1]]);
        let class = u16::from_be_bytes([header[2], header[3]]);
        let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let start = after + 10;
        let end = start + length;
        if end > buffer.len() {
            return Err(ParseError::Malformed);
        }
        position = end;
        let Some(kind) = RecordType::from_code(rtype).filter(|_| class == 1) else {
            continue;
        };
        if records.len() >= MAX_RECORDS {
            continue;
        }
        let (data, address) = read_data(buffer, kind, start, end)?;
        records.push(Record {
            name: record_name,
            kind,
            ttl,
            data,
            address,
        });
    }

    Ok(Parsed {
        rcode: (flags & 0xF) as u8,
        authoritative: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        records,
    })
}

fn read_data(
    buffer: &[u8],
    kind: RecordType,
    start: usize,
    end: usize,
) -> Result<(String, Option<IpAddr>), ParseError> {
    let data = &buffer[start..end];
    let bad = ParseError::Malformed;
    let within = |next: usize| {
        if next <= end {
            Ok(())
        } else {
            Err(ParseError::Malformed)
        }
    };
    match kind {
        RecordType::A => {
            let octets: [u8; 4] = data.try_into().map_err(|_| bad)?;
            let ip = Ipv4Addr::from(octets);
            Ok((ip.to_string(), Some(IpAddr::V4(ip))))
        }
        RecordType::Aaaa => {
            let octets: [u8; 16] = data.try_into().map_err(|_| bad)?;
            let ip = Ipv6Addr::from(octets);
            Ok((ip.to_string(), Some(IpAddr::V6(ip))))
        }
        RecordType::Cname | RecordType::Ns => {
            let (target, next) = read_name(buffer, start)?;
            within(next)?;
            Ok((target, None))
        }
        RecordType::Mx => {
            if data.len() < 3 {
                return Err(bad);
            }
            let preference = u16::from_be_bytes([data[0], data[1]]);
            let (exchange, next) = read_name(buffer, start + 2)?;
            within(next)?;
            Ok((format!("{preference} {exchange}"), None))
        }
        RecordType::Txt => {
            // One or more length-prefixed strings; the convention is to read them as one.
            let mut text = Vec::new();
            let mut at = 0;
            while at < data.len() {
                let size = usize::from(data[at]);
                let chunk = data.get(at + 1..at + 1 + size).ok_or(bad)?;
                text.extend_from_slice(chunk);
                at += 1 + size;
            }
            let mut text = String::from_utf8_lossy(&text).into_owned();
            if text.chars().count() > MAX_DATA_CHARS {
                text = text.chars().take(MAX_DATA_CHARS).collect::<String>() + "…";
            }
            Ok((text, None))
        }
        RecordType::Soa => {
            let (primary, next) = read_name(buffer, start)?;
            let (mailbox, next) = read_name(buffer, next)?;
            let numbers = buffer.get(next..next + 20).ok_or(bad)?;
            within(next + 20)?;
            let mut text = format!("{primary} {mailbox}");
            for chunk in numbers.as_chunks::<4>().0 {
                let _ = write!(text, " {}", u32::from_be_bytes(*chunk));
            }
            Ok((text, None))
        }
    }
}

/// Read a (possibly compressed) name starting at `start`. Returns the name without its trailing
/// dot and the position just after it in the message. A compression pointer may only point to
/// earlier bytes, which makes loops impossible.
fn read_name(buffer: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let mut name = String::new();
    let mut position = start;
    let mut resume: Option<usize> = None;
    loop {
        let length = usize::from(*buffer.get(position).ok_or(ParseError::Malformed)?);
        if length == 0 {
            position += 1;
            break;
        }
        match length & 0xC0 {
            0xC0 => {
                let low = usize::from(*buffer.get(position + 1).ok_or(ParseError::Malformed)?);
                let target = ((length & 0x3F) << 8) | low;
                if target >= position {
                    return Err(ParseError::Malformed);
                }
                resume.get_or_insert(position + 2);
                position = target;
                continue;
            }
            0 => {}
            // 0x40 and 0x80 are reserved label types.
            _ => return Err(ParseError::Malformed),
        }
        let label = buffer
            .get(position + 1..position + 1 + length)
            .ok_or(ParseError::Malformed)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &byte in label {
            if byte.is_ascii_graphic() && byte != b'.' && byte != b'\\' {
                name.push(char::from(byte));
            } else {
                let _ = write!(name, "\\{byte:03}");
            }
        }
        if name.len() > 255 * 2 {
            return Err(ParseError::Malformed);
        }
        position += 1 + length;
    }
    Ok((name, resume.unwrap_or(position)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply under construction: header, the question, then whatever the test appends.
    struct Reply(Vec<u8>);

    impl Reply {
        fn new(id: u16, name: &str, record_type: RecordType, flags: u16, answers: u16) -> Self {
            let mut buffer = Vec::new();
            buffer.extend_from_slice(&id.to_be_bytes());
            buffer.extend_from_slice(&(0x8000 | flags).to_be_bytes());
            buffer.extend_from_slice(&1u16.to_be_bytes());
            buffer.extend_from_slice(&answers.to_be_bytes());
            buffer.extend_from_slice(&[0; 4]);
            encode_name(name, &mut buffer).unwrap();
            buffer.extend_from_slice(&record_type.code().to_be_bytes());
            buffer.extend_from_slice(&1u16.to_be_bytes());
            Self(buffer)
        }

        /// A record named by a pointer to the question (offset 12).
        fn record(mut self, rtype: u16, ttl: u32, data: &[u8]) -> Self {
            self.0.extend_from_slice(&[0xC0, 12]);
            self.0.extend_from_slice(&rtype.to_be_bytes());
            self.0.extend_from_slice(&1u16.to_be_bytes());
            self.0.extend_from_slice(&ttl.to_be_bytes());
            self.0
                .extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            self.0.extend_from_slice(data);
            self
        }
    }

    #[test]
    fn the_question_has_the_expected_shape() {
        let query = encode_query(0xBEEF, "example.com", RecordType::Mx).unwrap();
        assert_eq!(&query[..2], &[0xBE, 0xEF]);
        assert_eq!(&query[2..4], &[0x01, 0x00], "a query that wants recursion");
        assert_eq!(&query[4..6], &[0, 1], "one question");
        assert_eq!(&query[10..12], &[0, 1], "one additional record: EDNS");
        assert_eq!(
            &query[12..25],
            b"\x07example\x03com\x00",
            "the name as labels"
        );
        assert_eq!(&query[25..29], &[0, 15, 0, 1], "MX, class IN");
        assert_eq!(query.len(), 29 + 11, "the OPT record is 11 bytes");
    }

    #[test]
    fn names_that_cannot_be_encoded_are_refused() {
        assert!(encode_query(1, "", RecordType::A).is_none());
        assert!(encode_query(1, "a..b", RecordType::A).is_none());
        assert!(encode_query(1, &format!("{}.com", "a".repeat(64)), RecordType::A).is_none());
        assert!(encode_query(1, &format!("{}.com", "a.".repeat(130)), RecordType::A).is_none());
        assert!(encode_query(1, "bücher.example", RecordType::A).is_none());
    }

    #[test]
    fn a_and_aaaa_answers_are_read() {
        let reply = Reply::new(7, "example.com", RecordType::A, 0x0400, 2)
            .record(1, 300, &[93, 184, 216, 34])
            .record(1, 60, &[10, 0, 0, 5]);
        let parsed = parse_response(&reply.0, 7, "EXAMPLE.com", RecordType::A).unwrap();
        assert_eq!(parsed.rcode, 0);
        assert!(parsed.authoritative && !parsed.truncated);
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].name, "example.com");
        assert_eq!(parsed.records[0].data, "93.184.216.34");
        assert_eq!(parsed.records[0].ttl, 300);
        assert_eq!(parsed.records[1].address, Some("10.0.0.5".parse().unwrap()));

        let v6 = Reply::new(8, "example.com", RecordType::Aaaa, 0, 1).record(
            28,
            30,
            &"2606:2800:220:1:248:1893:25c8:1946"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        let parsed = parse_response(&v6.0, 8, "example.com", RecordType::Aaaa).unwrap();
        assert_eq!(parsed.records[0].data, "2606:2800:220:1:248:1893:25c8:1946");
    }

    #[test]
    fn mx_txt_ns_cname_and_soa_are_read() {
        let mut mx = vec![0, 10];
        encode_name("mail.example.com", &mut mx).unwrap();
        let mut txt = vec![5];
        txt.extend_from_slice(b"v=spf");
        txt.push(6);
        txt.extend_from_slice(b"1 -all");
        let mut ns = Vec::new();
        encode_name("ns1.example.com", &mut ns).unwrap();
        let mut soa = Vec::new();
        encode_name("ns1.example.com", &mut soa).unwrap();
        encode_name("hostmaster.example.com", &mut soa).unwrap();
        for value in [2024u32, 7200, 900, 1_209_600, 300] {
            soa.extend_from_slice(&value.to_be_bytes());
        }

        let reply = Reply::new(9, "example.com", RecordType::Mx, 0, 5)
            .record(15, 3600, &mx)
            .record(16, 60, &txt)
            .record(2, 86400, &ns)
            .record(5, 60, &ns)
            .record(6, 300, &soa);
        let parsed = parse_response(&reply.0, 9, "example.com", RecordType::Mx).unwrap();
        let data: Vec<&str> = parsed.records.iter().map(|r| r.data.as_str()).collect();
        assert_eq!(
            data,
            [
                "10 mail.example.com",
                "v=spf1 -all",
                "ns1.example.com",
                "ns1.example.com",
                "ns1.example.com hostmaster.example.com 2024 7200 900 1209600 300",
            ]
        );
    }

    #[test]
    fn a_reply_to_another_question_is_a_mismatch_not_an_answer() {
        let reply = Reply::new(7, "example.com", RecordType::A, 0, 0);
        assert_eq!(
            parse_response(&reply.0, 8, "example.com", RecordType::A),
            Err(ParseError::Mismatch),
            "wrong id"
        );
        assert_eq!(
            parse_response(&reply.0, 7, "example.org", RecordType::A),
            Err(ParseError::Mismatch),
            "wrong name"
        );
        assert_eq!(
            parse_response(&reply.0, 7, "example.com", RecordType::Aaaa),
            Err(ParseError::Mismatch),
            "wrong type"
        );
        let mut not_a_response = reply.0.clone();
        not_a_response[2] &= 0x7F;
        assert_eq!(
            parse_response(&not_a_response, 7, "example.com", RecordType::A),
            Err(ParseError::Mismatch)
        );
        assert_eq!(
            parse_response(&[1, 2, 3], 7, "example.com", RecordType::A),
            Err(ParseError::Mismatch)
        );
    }

    #[test]
    fn an_error_code_is_an_answer() {
        let reply = Reply::new(7, "nope.example.com", RecordType::A, 3, 0);
        let parsed = parse_response(&reply.0, 7, "nope.example.com", RecordType::A).unwrap();
        assert_eq!(parsed.rcode, 3);
        assert!(parsed.records.is_empty());
        let answer = DnsAnswer {
            rtt: Duration::ZERO,
            rcode: parsed.rcode,
            authoritative: false,
            via_tcp: false,
            truncated: false,
            records: vec![],
        };
        assert_eq!(answer.rcode_name(), "NXDOMAIN");
    }

    #[test]
    fn a_compression_loop_or_forward_pointer_is_refused() {
        // The record's name points at itself.
        let mut reply = Reply::new(7, "example.com", RecordType::A, 0, 1);
        let here = reply.0.len();
        reply
            .0
            .extend_from_slice(&[0xC0, u8::try_from(here).unwrap()]);
        reply
            .0
            .extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert_eq!(
            parse_response(&reply.0, 7, "example.com", RecordType::A),
            Err(ParseError::Malformed)
        );
    }

    #[test]
    fn cut_off_data_is_refused() {
        let reply = Reply::new(7, "example.com", RecordType::A, 0, 1).record(1, 60, &[1, 2, 3]);
        assert_eq!(
            parse_response(&reply.0, 7, "example.com", RecordType::A),
            Err(ParseError::Malformed),
            "an A record needs four bytes"
        );
        let mut short = Reply::new(7, "example.com", RecordType::A, 0, 1)
            .record(1, 60, &[1, 2, 3, 4])
            .0;
        short.truncate(short.len() - 2);
        assert_eq!(
            parse_response(&short, 7, "example.com", RecordType::A),
            Err(ParseError::Malformed),
            "the message ends inside the record"
        );
    }

    #[test]
    fn the_number_of_records_kept_is_capped() {
        let mut reply = Reply::new(7, "example.com", RecordType::A, 0, 40);
        for n in 0..40u8 {
            reply = reply.record(1, 60, &[1, 1, 1, n]);
        }
        let parsed = parse_response(&reply.0, 7, "example.com", RecordType::A).unwrap();
        assert_eq!(parsed.records.len(), MAX_RECORDS);
    }

    #[test]
    fn a_long_txt_is_shortened() {
        let mut txt = Vec::new();
        for _ in 0..4 {
            txt.push(255);
            txt.extend(std::iter::repeat_n(b'x', 255));
        }
        let reply = Reply::new(7, "example.com", RecordType::Txt, 0, 1).record(16, 60, &txt);
        let parsed = parse_response(&reply.0, 7, "example.com", RecordType::Txt).unwrap();
        assert_eq!(parsed.records[0].data.chars().count(), MAX_DATA_CHARS + 1);
        assert!(parsed.records[0].data.ends_with('…'));
    }

    #[test]
    fn resolv_conf_is_read_like_a_resolver_would() {
        let text = "# generated\nsearch example.org\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nnameserver 2606:4700:4700::1111\nnameserver 192.168.1.1\nnameserver 9.9.9.9\nnameserver 8.8.8.8\noptions edns0\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1111".parse().unwrap(),
                "9.9.9.9".parse().unwrap(),
            ]
        );
        assert!(parse_resolv_conf("nameserver\nnameserver not-an-address\n").is_empty());
    }

    #[test]
    fn record_types_round_trip() {
        for kind in ["A", "aaaa", "Cname", "MX", "ns", "TXT", "soa"] {
            let parsed = RecordType::parse(kind).unwrap();
            assert_eq!(RecordType::from_code(parsed.code()), Some(parsed));
            assert_eq!(parsed.name(), kind.to_ascii_uppercase());
        }
        assert!(RecordType::parse("ANY").is_none());
        assert!(RecordType::parse("AXFR").is_none());
    }
}

#[cfg(test)]
mod base64url_tests {
    use super::base64url;

    #[test]
    fn it_matches_the_rfc_4648_vectors_without_padding() {
        for (input, expected) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url(input), expected);
        }
        // the two characters that differ from standard base64
        assert_eq!(base64url(&[0xfb, 0xff, 0xbf]), "-_-_");
    }
}
