//! The DNS client against a real (fake) server on loopback: UDP answers, replies that are not for
//! this question, truncation and the TCP fallback, silence, and a closed port.

use std::net::SocketAddr;
use std::time::Duration;

use ipping_node::probes::dns::{DnsOutcome, RecordType, query_server};
use ipping_node::protocol::error_code;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Where the question of `query` ends (the 12-byte header, a name, type and class).
fn question_end(query: &[u8]) -> usize {
    let mut at = 12;
    while query[at] != 0 {
        at += 1 + usize::from(query[at]);
    }
    at + 1 + 4
}

/// A reply to `query`: same id, same question, `flags`, and the given records (type, ttl, data),
/// each named by a pointer to the question.
fn reply(query: &[u8], flags: u16, records: &[(u16, u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&query[..2]);
    out.extend_from_slice(&(0x8000 | flags).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&query[12..question_end(query)]);
    for (rtype, ttl, data) in records {
        out.extend_from_slice(&[0xC0, 12]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

const A_RECORD: (u16, u32, &[u8]) = (1, 300, &[93, 184, 216, 34]);

async fn udp_server() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr)
}

#[tokio::test]
async fn a_udp_answer_is_read() {
    let (socket, addr) = udp_server().await;
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        let (n, from) = socket.recv_from(&mut buffer).await.unwrap();
        // 0x0400: authoritative
        socket
            .send_to(&reply(&buffer[..n], 0x0400, &[A_RECORD]), from)
            .await
            .unwrap();
    });
    let outcome = query_server(addr, "example.com", RecordType::A, Duration::from_secs(2)).await;
    let DnsOutcome::Answer(answer) = outcome else {
        panic!("expected an answer, got {outcome:?}");
    };
    assert_eq!(answer.rcode_name(), "NOERROR");
    assert!(answer.authoritative && !answer.via_tcp && !answer.truncated);
    assert_eq!(answer.records.len(), 1);
    assert_eq!(answer.records[0].data, "93.184.216.34");
    assert_eq!(answer.records[0].ttl, 300);
    assert!(answer.rtt < Duration::from_secs(1));
}

#[tokio::test]
async fn no_such_name_is_an_answer() {
    let (socket, addr) = udp_server().await;
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        let (n, from) = socket.recv_from(&mut buffer).await.unwrap();
        socket
            .send_to(&reply(&buffer[..n], 3, &[]), from)
            .await
            .unwrap();
    });
    let outcome = query_server(
        addr,
        "nope.example.com",
        RecordType::A,
        Duration::from_secs(2),
    )
    .await;
    let DnsOutcome::Answer(answer) = outcome else {
        panic!("expected an answer, got {outcome:?}");
    };
    assert_eq!(answer.rcode_name(), "NXDOMAIN");
    assert!(answer.records.is_empty());
}

#[tokio::test]
async fn a_forged_reply_is_ignored_and_the_real_one_is_waited_for() {
    let (socket, addr) = udp_server().await;
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        let (n, from) = socket.recv_from(&mut buffer).await.unwrap();
        let query = buffer[..n].to_vec();
        // wrong id, claiming a different address
        let mut forged = reply(&query, 0, &[(1, 60, &[6, 6, 6, 6])]);
        forged[0] ^= 0xFF;
        socket.send_to(&forged, from).await.unwrap();
        // a reply for another name under the right id
        let mut other = reply(&query, 0, &[(1, 60, &[7, 7, 7, 7])]);
        other[13] = b'X';
        socket.send_to(&other, from).await.unwrap();
        socket
            .send_to(&reply(&query, 0, &[A_RECORD]), from)
            .await
            .unwrap();
    });
    let outcome = query_server(addr, "example.com", RecordType::A, Duration::from_secs(2)).await;
    let DnsOutcome::Answer(answer) = outcome else {
        panic!("expected an answer, got {outcome:?}");
    };
    assert_eq!(answer.records.len(), 1);
    assert_eq!(answer.records[0].data, "93.184.216.34");
}

#[tokio::test]
async fn a_cut_short_answer_is_fetched_again_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // the same port number for UDP, which is a different socket
    let socket = UdpSocket::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        let (n, from) = socket.recv_from(&mut buffer).await.unwrap();
        socket
            .send_to(&reply(&buffer[..n], 0x0200, &[]), from)
            .await
            .unwrap();
    });
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut query).await.unwrap();
        let body = reply(&query, 0, &[A_RECORD, (1, 300, &[93, 184, 216, 35])]);
        stream
            .write_all(&u16::try_from(body.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&body).await.unwrap();
    });
    let outcome = query_server(addr, "example.com", RecordType::A, Duration::from_secs(2)).await;
    let DnsOutcome::Answer(answer) = outcome else {
        panic!("expected an answer, got {outcome:?}");
    };
    assert!(answer.via_tcp && !answer.truncated);
    assert_eq!(answer.records.len(), 2);
}

#[tokio::test]
async fn a_cut_short_answer_without_tcp_is_reported_as_incomplete() {
    // Nothing listens on TCP at this port.
    let (socket, addr) = udp_server().await;
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        let (n, from) = socket.recv_from(&mut buffer).await.unwrap();
        socket
            .send_to(&reply(&buffer[..n], 0x0200, &[A_RECORD]), from)
            .await
            .unwrap();
    });
    let outcome = query_server(addr, "example.com", RecordType::A, Duration::from_secs(2)).await;
    let DnsOutcome::Answer(answer) = outcome else {
        panic!("expected an answer, got {outcome:?}");
    };
    assert!(answer.truncated && !answer.via_tcp);
}

#[tokio::test]
async fn a_silent_server_is_a_timeout() {
    let (_socket, addr) = udp_server().await;
    let started = std::time::Instant::now();
    let outcome = query_server(
        addr,
        "example.com",
        RecordType::A,
        Duration::from_millis(300),
    )
    .await;
    assert_eq!(outcome, DnsOutcome::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn a_closed_port_is_a_refusal() {
    let (socket, addr) = udp_server().await;
    drop(socket);
    let outcome = query_server(addr, "example.com", RecordType::A, Duration::from_secs(2)).await;
    assert_eq!(outcome, DnsOutcome::Failed(error_code::CONNECTION_REFUSED));
}

#[tokio::test]
async fn garbage_under_the_right_id_is_a_protocol_error() {
    let (socket, addr) = udp_server().await;
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        let (n, from) = socket.recv_from(&mut buffer).await.unwrap();
        // the right header and question, then an answer that ends in the middle of its data
        let mut bad = reply(&buffer[..n], 0, &[A_RECORD]);
        bad.truncate(bad.len() - 2);
        socket.send_to(&bad, from).await.unwrap();
    });
    let outcome = query_server(addr, "example.com", RecordType::A, Duration::from_secs(2)).await;
    assert_eq!(outcome, DnsOutcome::Failed(error_code::PROTOCOL_ERROR));
}
