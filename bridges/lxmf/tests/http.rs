//! The HTTP server against a fake sender: real sockets, no Reticulum.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lxmf_bridge::alert::Alert;
use lxmf_bridge::config::Hash;
use lxmf_bridge::http::{Server, Settings, unix_now};
use lxmf_bridge::queue::{self, QUEUE_LEN, Retry, Sender};
use lxmf_bridge::verify::sign;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const SECRET: &[u8] = b"integration-test-secret";
/// A well-formed signature (not a right one).
const SIG: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const BODY: &str = r#"{"event":"down","host":"a:1","name":"Front","message":"Front (a:1) is down since 12:03 UTC."}"#;

#[derive(Default)]
struct Fake {
    sent: Mutex<Vec<(Hash, Alert)>>,
    /// Never finishes a send, so the queue fills up.
    stuck: bool,
}

impl Sender for Fake {
    async fn send(&self, to: Hash, alert: &Alert) -> Result<(), String> {
        if self.stuck {
            std::future::pending::<()>().await;
        }
        self.sent.lock().unwrap().push((to, alert.clone()));
        Ok(())
    }
}

struct Bridge {
    addr: std::net::SocketAddr,
    fake: Arc<Fake>,
}

async fn start(fake: Fake, recipients: Vec<Hash>, max_body: usize, timeout: Duration) -> Bridge {
    start_with(fake, recipients, max_body, timeout, vec![]).await
}

async fn start_with(fake: Fake, recipients: Vec<Hash>, max_body: usize, timeout: Duration, allow_from: Vec<std::net::IpAddr>) -> Bridge {
    let fake = Arc::new(fake);
    let (alerts, queued) = mpsc::channel(QUEUE_LEN);
    let mut settings = Settings::new(SECRET.to_vec(), 300, max_body);
    (settings.head_timeout, settings.body_timeout, settings.allow_from) = (timeout, timeout, allow_from);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(queue::run(queued, fake.clone(), recipients, Retry { waits: vec![] }));
    tokio::spawn(Server::new(settings, alerts).serve(listener));
    Bridge { addr, fake }
}

async fn bridge() -> Bridge {
    start(Fake::default(), vec![[1; 16], [2; 16]], 16 * 1024, Duration::from_secs(5)).await
}

/// Sends `bytes` and returns the status line's code and the body.
async fn exchange(addr: std::net::SocketAddr, bytes: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    read_answer(stream).await
}

async fn read_answer(mut stream: TcpStream) -> (u16, String) {
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await.expect("the server closes the connection").ok();
    let text = String::from_utf8_lossy(&answer).into_owned();
    let code = text.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (code, text.split_once("\r\n\r\n").map(|(_, body)| body.to_string()).unwrap_or_default())
}

fn request(timestamp: &str, signature: &str, body: &str) -> Vec<u8> {
    format!(
        "POST /alert HTTP/1.1\r\nHost: bridge\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Rettui-Timestamp: {timestamp}\r\nX-Rettui-Signature: {signature}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn signed(body: &str, timestamp: u64) -> Vec<u8> {
    let timestamp = timestamp.to_string();
    request(&timestamp, &sign(SECRET, &timestamp, body.as_bytes()), body)
}

async fn sent_count(fake: &Fake, wanted: usize) -> usize {
    for _ in 0..200 {
        if fake.sent.lock().unwrap().len() >= wanted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // A moment more, to see that nothing extra comes.
    tokio::time::sleep(Duration::from_millis(50)).await;
    fake.sent.lock().unwrap().len()
}

#[tokio::test]
async fn a_signed_alert_is_sent_to_every_recipient() {
    let bridge = bridge().await;
    assert_eq!(exchange(bridge.addr, &signed(BODY, unix_now())).await, (202, String::new()));
    assert_eq!(sent_count(&bridge.fake, 2).await, 2);
    let sent = bridge.fake.sent.lock().unwrap();
    let mut to: Vec<Hash> = sent.iter().map(|(to, _)| *to).collect();
    to.sort();
    assert_eq!(to, [[1; 16], [2; 16]]);
    assert!(sent.iter().all(|(_, alert)| alert.title == "down" && alert.content == "Front (a:1) is down since 12:03 UTC."));
}

#[tokio::test]
async fn a_replayed_request_is_not_sent_twice() {
    let bridge = bridge().await;
    let now = unix_now();
    let once = signed(BODY, now);
    assert_eq!(exchange(bridge.addr, &once).await.0, 202);
    assert_eq!(exchange(bridge.addr, &once).await, (409, String::new()));
    assert_eq!(sent_count(&bridge.fake, 2).await, 2);
    // Another time, so another signature, is a new alert.
    assert_eq!(exchange(bridge.addr, &signed(BODY, now - 5)).await.0, 202);
    assert_eq!(sent_count(&bridge.fake, 4).await, 4);
}

#[tokio::test]
async fn requests_that_are_not_authentic_send_nothing_and_say_nothing() {
    let bridge = bridge().await;
    let now = unix_now();
    let ts = now.to_string();
    let good = sign(SECRET, &ts, BODY.as_bytes());
    let other = |ts: u64| {
        let ts = ts.to_string();
        request(&ts, &sign(SECRET, &ts, BODY.as_bytes()), BODY)
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("wrong secret", request(&ts, &sign(b"another-secret-entirely", &ts, BODY.as_bytes()), BODY)),
        ("tampered body", request(&ts, &good, &BODY.replace("down", "up"))),
        ("stale", other(now - 301)),
        ("future", other(now + 120)),
        ("no headers", b"POST /alert HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}".to_vec()),
        ("no signature", format!("POST /alert HTTP/1.1\r\nContent-Length: 2\r\nX-Rettui-Timestamp: {ts}\r\n\r\n{{}}").into_bytes()),
        ("no timestamp", format!("POST /alert HTTP/1.1\r\nContent-Length: 2\r\nX-Rettui-Signature: {good}\r\n\r\n{{}}").into_bytes()),
        ("junk timestamp", request("yesterday", &good, BODY)),
        ("junk signature", request(&ts, "sha256=nothex", BODY)),
        ("signature without prefix", request(&ts, &good[7..], BODY)),
    ];
    for (what, bytes) in cases {
        assert_eq!(exchange(bridge.addr, &bytes).await, (401, String::new()), "{what}");
    }
    assert_eq!(sent_count(&bridge.fake, 1).await, 0);
}

#[tokio::test]
async fn a_signed_body_that_is_not_an_alert_is_a_bad_request() {
    let bridge = bridge().await;
    for body in ["not json", "{}", r#"{"event":"down"}"#, r#"{"event":"down","message":""}"#] {
        assert_eq!(exchange(bridge.addr, &signed(body, unix_now())).await, (400, String::new()), "{body}");
    }
    assert_eq!(sent_count(&bridge.fake, 1).await, 0);
}

#[tokio::test]
async fn a_long_message_arrives_cut_to_a_thousand_characters() {
    let bridge = bridge().await;
    let body = serde_json::json!({"event": "still_down", "message": "m".repeat(5000)}).to_string();
    assert_eq!(exchange(bridge.addr, &signed(&body, unix_now())).await.0, 202);
    sent_count(&bridge.fake, 2).await;
    assert!(bridge.fake.sent.lock().unwrap().iter().all(|(_, alert)| alert.content.chars().count() == 1000));
}

#[tokio::test]
async fn healthz_answers_and_everything_else_is_refused_plainly() {
    let bridge = bridge().await;
    assert_eq!(exchange(bridge.addr, b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n").await, (200, "ok\n".into()));
    let cases: [(&[u8], u16); 8] = [
        (b"GET /alert HTTP/1.1\r\n\r\n", 405),
        (b"POST /healthz HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 405),
        (b"DELETE /alert HTTP/1.1\r\n\r\n", 405),
        (b"GET / HTTP/1.1\r\n\r\n", 404),
        (b"POST /alerts HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 404),
        (b"GET /../etc/passwd HTTP/1.1\r\n\r\n", 404),
        (b"nonsense\r\n\r\n", 400),
        (b"POST /alert HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400),
    ];
    for (bytes, code) in cases {
        assert_eq!(exchange(bridge.addr, bytes).await, (code, String::new()), "{}", String::from_utf8_lossy(bytes));
    }
}

#[tokio::test]
async fn size_limits_are_enforced_before_the_body_is_read() {
    let bridge = start(Fake::default(), vec![[1; 16]], 1024, Duration::from_secs(5)).await;
    let ts = unix_now().to_string();
    // Over the limit: refused from the header alone, without sending the body.
    let head =
        format!("POST /alert HTTP/1.1\r\nContent-Length: 1025\r\nX-Rettui-Timestamp: {ts}\r\nX-Rettui-Signature: sha256={SIG}\r\n\r\n");
    assert_eq!(exchange(bridge.addr, head.as_bytes()).await.0, 413);
    let huge = format!(
        "POST /alert HTTP/1.1\r\nContent-Length: 99999999999999999999\r\nX-Rettui-Timestamp: {ts}\r\nX-Rettui-Signature: sha256={SIG}\r\n\r\n"
    );
    assert_eq!(exchange(bridge.addr, huge.as_bytes()).await.0, 413);
    // No length at all.
    let none = format!("POST /alert HTTP/1.1\r\nX-Rettui-Timestamp: {ts}\r\nX-Rettui-Signature: sha256={SIG}\r\n\r\n{{}}");
    assert_eq!(exchange(bridge.addr, none.as_bytes()).await.0, 411);
    // Headers that never end.
    let mut long = b"GET /healthz HTTP/1.1\r\nX-Long: ".to_vec();
    long.extend(std::iter::repeat_n(b'a', 20_000));
    assert_eq!(exchange(bridge.addr, &long).await.0, 431);
}

#[tokio::test]
async fn a_client_that_stalls_or_leaves_early_is_let_go() {
    let bridge = start(Fake::default(), vec![[1; 16]], 1024, Duration::from_millis(300)).await;
    // Headers that stop in the middle.
    let mut stream = TcpStream::connect(bridge.addr).await.unwrap();
    stream.write_all(b"POST /alert HTTP/1.1\r\nContent-Le").await.unwrap();
    assert_eq!(read_answer(stream).await.0, 408);
    // A body that does not arrive.
    let ts = unix_now().to_string();
    let head =
        format!("POST /alert HTTP/1.1\r\nContent-Length: 100\r\nX-Rettui-Timestamp: {ts}\r\nX-Rettui-Signature: sha256={SIG}\r\n\r\nabc");
    let mut stream = TcpStream::connect(bridge.addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    assert_eq!(read_answer(stream).await.0, 408);
    // A client that closes in the middle of its body.
    let mut stream = TcpStream::connect(bridge.addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(read_answer(stream).await.0, 400);
    // And the server is still there.
    assert_eq!(exchange(bridge.addr, &signed(BODY, unix_now())).await.0, 202);
}

#[tokio::test]
async fn garbage_does_not_hurt_the_server() {
    let bridge = bridge().await;
    for junk in [&[0u8; 64][..], &[0xff; 5000], b"\r\n\r\n", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03", b""] {
        let mut stream = TcpStream::connect(bridge.addr).await.unwrap();
        stream.write_all(junk).await.unwrap();
        stream.shutdown().await.unwrap();
        let (code, body) = read_answer(stream).await;
        assert!(code == 400 || code == 431, "{code}");
        assert_eq!(body, "");
    }
    assert_eq!(exchange(bridge.addr, &signed(BODY, unix_now())).await.0, 202);
}

#[tokio::test]
async fn a_full_queue_is_told_to_try_again_later() {
    let bridge = start(Fake { stuck: true, ..Fake::default() }, vec![[1; 16]], 16 * 1024, Duration::from_secs(5)).await;
    let now = unix_now();
    let mut codes = Vec::new();
    // 32 deliveries stuck, one held by the dispatcher and 100 waiting: the 134th alert has nowhere to go.
    for i in 0..140 {
        let body = format!(r#"{{"event":"down","message":"alert {i}"}}"#);
        codes.push(exchange(bridge.addr, &signed(&body, now)).await.0);
        tokio::task::yield_now().await;
    }
    assert_eq!(codes.iter().filter(|c| **c == 202).count(), 133, "{codes:?}");
    assert!(codes[133..].iter().all(|c| *c == 503), "{codes:?}");
    assert_eq!(exchange(bridge.addr, b"GET /healthz HTTP/1.1\r\n\r\n").await.0, 200);
}

#[tokio::test]
async fn what_can_be_refused_without_the_body_is_refused_before_waiting_for_it() {
    // A long timeout: an answer that comes at once did not wait for the body.
    let bridge = start(Fake::default(), vec![[1; 16]], 1024, Duration::from_secs(30)).await;
    let now = unix_now();
    let head = |ts: u64, sig: &str| {
        format!("POST /alert HTTP/1.1\r\nContent-Length: 50\r\nX-Rettui-Timestamp: {ts}\r\nX-Rettui-Signature: {sig}\r\n\r\n").into_bytes()
    };
    let good = format!("sha256={SIG}");
    let cases = [
        ("stale", head(now - 400, &good)),
        ("future", head(now + 400, &good)),
        ("no prefix", head(now, SIG)),
        ("short", head(now, "sha256=abcd")),
        ("long", head(now, &format!("sha256={SIG}00"))),
        ("not hex", head(now, &format!("sha256={}", "z".repeat(64)))),
    ];
    for (what, bytes) in cases {
        let started = std::time::Instant::now();
        assert_eq!(exchange(bridge.addr, &bytes).await.0, 401, "{what}");
        assert!(started.elapsed() < Duration::from_secs(5), "{what} waited for the body");
    }
}

#[tokio::test]
async fn only_the_listed_addresses_may_connect() {
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let other: std::net::IpAddr = "10.9.8.7".parse().unwrap();
    let open = start_with(Fake::default(), vec![[1; 16]], 1024, Duration::from_secs(5), vec![loopback]).await;
    assert_eq!(exchange(open.addr, &signed(BODY, unix_now())).await.0, 202);
    // Another address is closed on without an answer, even for /healthz.
    let shut = start_with(Fake::default(), vec![[1; 16]], 1024, Duration::from_secs(5), vec![other]).await;
    let mut stream = TcpStream::connect(shut.addr).await.unwrap();
    let _ = stream.write_all(&signed(BODY, unix_now())).await;
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer).await;
    assert!(answer.is_empty());
    assert_eq!(sent_count(&shut.fake, 1).await, 0);
}

#[tokio::test]
async fn stalled_connections_do_not_hold_the_server() {
    // With the real limits: a head that never arrives is let go after a few seconds.
    let bridge = start(Fake::default(), vec![[1; 16]], 1024, lxmf_bridge::http::HEAD_TIMEOUT).await;
    let mut stalled = Vec::new();
    for _ in 0..60 {
        stalled.push(TcpStream::connect(bridge.addr).await.unwrap());
    }
    let started = std::time::Instant::now();
    for stream in stalled {
        assert_eq!(read_answer(stream).await.0, 408);
    }
    assert!(started.elapsed() < Duration::from_secs(8));
    assert_eq!(exchange(bridge.addr, &signed(BODY, unix_now())).await.0, 202);
}
