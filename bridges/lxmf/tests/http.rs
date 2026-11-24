//! The HTTP server against a fake sender: real sockets, no Reticulum.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lxmf_bridge::alert::Alert;
use lxmf_bridge::config::Hash;
use lxmf_bridge::http::{Server, Settings, unix_now};
use lxmf_bridge::queue::{self, DEFAULT_NAMED_QUEUE, Job, Named, QUEUE_LEN, Retry, Sender};
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
    /// The address this sender says it sends from.
    own: Option<Hash>,
    /// Never finishes a send to this address, but sends to others.
    stuck_to: Option<Hash>,
}

impl Sender for Fake {
    async fn send(&self, to: Hash, alert: &Alert) -> Result<(), String> {
        if self.stuck || self.stuck_to == Some(to) {
            std::future::pending::<()>().await;
        }
        self.sent.lock().unwrap().push((to, alert.clone()));
        Ok(())
    }

    fn own_address(&self) -> Option<Hash> {
        self.own
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
    start_configured(fake, recipients, move |settings| {
        (settings.max_body_bytes, settings.head_timeout, settings.body_timeout, settings.allow_from) =
            (max_body, timeout, timeout, allow_from);
    })
    .await
}

async fn start_configured(fake: Fake, recipients: Vec<Hash>, configure: impl FnOnce(&mut Settings)) -> Bridge {
    start_named(fake, recipients, configure, Named::default(), DEFAULT_NAMED_QUEUE).await
}

async fn start_named(fake: Fake, recipients: Vec<Hash>, configure: impl FnOnce(&mut Settings), named: Named, named_queue: usize) -> Bridge {
    let fake = Arc::new(fake);
    let (alerts, queued) = mpsc::channel::<Job>(QUEUE_LEN);
    let (named_alerts, named_queued) = mpsc::channel::<Job>(named_queue);
    let mut settings = Settings::new(SECRET.to_vec(), 300, 16 * 1024);
    settings.has_recipients = !recipients.is_empty();
    configure(&mut settings);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(queue::run(queued, named_queued, fake.clone(), recipients, Retry { waits: vec![] }, named));
    tokio::spawn(Server::new(settings, alerts, named_alerts).serve(listener));
    Bridge { addr, fake }
}

async fn bridge() -> Bridge {
    start(Fake::default(), vec![[1; 16], [2; 16]], 16 * 1024, Duration::from_secs(5)).await
}

/// Sends `bytes` and returns the whole answer, head and body.
async fn exchange_head(addr: std::net::SocketAddr, bytes: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await.expect("the server closes the connection").ok();
    String::from_utf8_lossy(&answer).into_owned()
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

// The addresses the website names.

const ME: Hash = [7; 16];
const THEM: Hash = [9; 16];

fn alert_to(to: &str, message: &str) -> String {
    serde_json::json!({"event": "down", "message": message, "to": to}).to_string()
}

fn on(settings: &mut Settings) {
    settings.website_recipients = true;
    settings.own_address = Some(ME);
}

async fn sent_to(fake: &Fake, wanted: usize) -> Vec<Hash> {
    sent_count(fake, wanted).await;
    let mut to: Vec<Hash> = fake.sent.lock().unwrap().iter().map(|(to, _)| *to).collect();
    to.sort();
    to
}

fn retry_after(answer: &str) -> u64 {
    let line = answer.lines().find_map(|line| line.strip_prefix("Retry-After: ")).expect("a Retry-After header");
    line.parse().unwrap()
}

#[tokio::test]
async fn with_website_recipients_off_a_body_that_names_an_address_is_refused() {
    let bridge = bridge().await;
    let (code, reason) = exchange(bridge.addr, &signed(&alert_to(&hex::encode(THEM), "x"), unix_now())).await;
    assert_eq!(code, 403);
    assert!(reason.contains("website_recipients is off"), "{reason}");
    // Whatever it says: a bad address is no different.
    assert_eq!(exchange(bridge.addr, &signed(&alert_to("nonsense", "x"), unix_now() - 1)).await.0, 403);
    assert_eq!(sent_count(&bridge.fake, 1).await, 0);
    // A body without one goes to the list as before.
    assert_eq!(exchange(bridge.addr, &signed(BODY, unix_now())).await.0, 202);
    assert_eq!(sent_to(&bridge.fake, 2).await, [[1; 16], [2; 16]]);
}

#[tokio::test]
async fn with_website_recipients_on_an_alert_goes_to_the_named_address_only() {
    let bridge = start_configured(Fake::default(), vec![[1; 16], [2; 16]], on).await;
    let now = unix_now();
    // As 32 digits, in angle brackets and in capitals: one address.
    for (i, to) in [hex::encode(THEM), format!("<{}>", hex::encode(THEM)), hex::encode(THEM).to_uppercase()].iter().enumerate() {
        assert_eq!(exchange(bridge.addr, &signed(&alert_to(to, "named"), now - i as u64)).await, (202, String::new()), "{to}");
    }
    assert_eq!(sent_to(&bridge.fake, 3).await, [THEM; 3]);
    assert!(bridge.fake.sent.lock().unwrap().iter().all(|(_, alert)| alert.title == "down" && alert.content == "named"));
    // Without a `to` (or a null one) the list gets it, and the named address does not.
    assert_eq!(exchange(bridge.addr, &signed(BODY, now - 10)).await.0, 202);
    let null = r#"{"event":"down","message":"listed","to":null}"#;
    assert_eq!(exchange(bridge.addr, &signed(null, now - 11)).await.0, 202);
    assert_eq!(sent_to(&bridge.fake, 7).await, [[1; 16], [1; 16], [2; 16], [2; 16], THEM, THEM, THEM]);
}

#[tokio::test]
async fn a_bad_address_is_refused_and_nothing_is_sent() {
    let bridge = start_configured(Fake::default(), vec![[1; 16]], on).await;
    let long = "a".repeat(34);
    let bad =
        ["", "abc", "zz23456789abcdef0123456789abcdef", &long, "<0123456789abcdef0123456789abcde>", "0123456789abcdef0123456789abcdef00"];
    for (i, to) in bad.iter().enumerate() {
        let (code, reason) = exchange(bridge.addr, &signed(&alert_to(to, "x"), unix_now() - i as u64)).await;
        assert_eq!(code, 400, "{to:?}");
        assert!(reason.contains("\"to\""), "{reason}");
    }
    // Not even text.
    let number = r#"{"event":"down","message":"x","to":5}"#;
    assert_eq!(exchange(bridge.addr, &signed(number, unix_now() - 20)).await, (400, String::new()));
    assert_eq!(sent_count(&bridge.fake, 1).await, 0);
}

#[tokio::test]
async fn the_bridges_own_address_is_refused() {
    let bridge = start_configured(Fake::default(), vec![[1; 16]], on).await;
    let (code, reason) = exchange(bridge.addr, &signed(&alert_to(&format!("<{}>", hex::encode(ME)), "x"), unix_now())).await;
    assert_eq!(code, 422);
    assert!(reason.contains("own address"), "{reason}");
    assert_eq!(sent_count(&bridge.fake, 1).await, 0);
}

#[tokio::test]
async fn an_address_gets_only_so_many_alerts_an_hour() {
    let bridge = start_configured(Fake::default(), vec![], |settings| {
        on(settings);
        settings.per_recipient_per_hour = 2;
    })
    .await;
    let now = unix_now();
    for i in 0..2 {
        assert_eq!(exchange(bridge.addr, &signed(&alert_to(&hex::encode(THEM), "x"), now - i)).await.0, 202);
    }
    let answer = exchange_head(bridge.addr, &signed(&alert_to(&hex::encode(THEM), "x"), now - 2)).await;
    assert!(answer.starts_with("HTTP/1.1 429 Too Many Requests\r\n"), "{answer}");
    assert!(answer.ends_with("too many alerts to that address this hour\n"), "{answer}");
    assert!((3590..=3600).contains(&retry_after(&answer)), "{answer}");
    // Again, and the refusals count for nothing: still waiting.
    let again = exchange_head(bridge.addr, &signed(&alert_to(&hex::encode(THEM), "x"), now - 3)).await;
    assert!(again.starts_with("HTTP/1.1 429 "), "{again}");
    // Another address is not held back by it.
    assert_eq!(exchange(bridge.addr, &signed(&alert_to(&hex::encode([5; 16]), "x"), now - 4)).await.0, 202);
    assert_eq!(sent_to(&bridge.fake, 3).await, [[5; 16], THEM, THEM]);
}

#[tokio::test]
async fn only_so_many_different_addresses_get_alerts_an_hour() {
    let bridge = start_configured(Fake::default(), vec![[1; 16]], |settings| {
        on(settings);
        settings.recipients_per_hour = 2;
    })
    .await;
    let now = unix_now();
    for (i, to) in [[3; 16], [4; 16]].iter().enumerate() {
        assert_eq!(exchange(bridge.addr, &signed(&alert_to(&hex::encode(to), "x"), now - i as u64)).await.0, 202);
    }
    let answer = exchange_head(bridge.addr, &signed(&alert_to(&hex::encode([5; 16]), "x"), now - 2)).await;
    assert!(answer.starts_with("HTTP/1.1 429 Too Many Requests\r\n"), "{answer}");
    assert!(answer.ends_with("too many different addresses this hour\n"), "{answer}");
    assert!((3590..=3600).contains(&retry_after(&answer)), "{answer}");
    // An address already served still gets its alerts, and the list is not part of the limit.
    assert_eq!(exchange(bridge.addr, &signed(&alert_to(&hex::encode([3; 16]), "x"), now - 3)).await.0, 202);
    assert_eq!(exchange(bridge.addr, &signed(BODY, now - 4)).await.0, 202);
    assert_eq!(sent_to(&bridge.fake, 4).await, [[1; 16], [3; 16], [3; 16], [4; 16]]);
}

#[tokio::test]
async fn a_full_queue_does_not_use_up_an_addresss_hour() {
    let bridge = start_configured(Fake { stuck: true, ..Fake::default() }, vec![], |settings| {
        on(settings);
        (settings.per_recipient_per_hour, settings.recipients_per_hour) = (1, 1000);
    })
    .await;
    let now = unix_now();
    let mut codes = Vec::new();
    // Each alert goes to its own address, so only the queue can refuse.
    for i in 0..140u32 {
        let to = hex::encode([&i.to_le_bytes()[..], &[0; 12]].concat());
        codes.push(exchange(bridge.addr, &signed(&alert_to(&to, &format!("alert {i}")), now)).await.0);
        tokio::task::yield_now().await;
    }
    assert!(codes[133..].iter().all(|c| *c == 503), "{codes:?}");
    // The addresses that found the queue full have their message still to come: not 429.
    let to = hex::encode([&139u32.to_le_bytes()[..], &[0; 12]].concat());
    assert_eq!(exchange(bridge.addr, &signed(&alert_to(&to, "again"), now - 1)).await.0, 503);
}

#[tokio::test]
async fn without_a_list_an_alert_must_name_an_address() {
    let bridge = start_configured(Fake::default(), vec![], on).await;
    let (code, reason) = exchange(bridge.addr, &signed(BODY, unix_now())).await;
    assert_eq!(code, 400);
    assert!(reason.contains("no recipients list"), "{reason}");
    assert_eq!(exchange(bridge.addr, &signed(&alert_to(&hex::encode(THEM), "x"), unix_now() - 1)).await.0, 202);
    assert_eq!(sent_to(&bridge.fake, 1).await, [THEM]);
}

#[tokio::test]
async fn the_signature_covers_the_address() {
    let bridge = start_configured(Fake::default(), vec![[1; 16]], on).await;
    let now = unix_now();
    let ts = now.to_string();
    let signed_for_them = sign(SECRET, &ts, alert_to(&hex::encode(THEM), "x").as_bytes());
    // The same signature on a body with another address, or with one added, or one taken away.
    let cases = [
        ("changed", alert_to(&hex::encode([5; 16]), "x")),
        ("added", BODY.to_string()),
        ("removed", r#"{"event":"down","message":"x"}"#.to_string()),
    ];
    for (what, body) in cases {
        assert_eq!(exchange(bridge.addr, &request(&ts, &signed_for_them, &body)).await, (401, String::new()), "{what}");
    }
    assert_eq!(sent_count(&bridge.fake, 1).await, 0);
    // The body it was made for goes through.
    assert_eq!(exchange(bridge.addr, &request(&ts, &signed_for_them, &alert_to(&hex::encode(THEM), "x"))).await.0, 202);
    assert_eq!(sent_to(&bridge.fake, 1).await, [THEM]);
}

#[tokio::test]
async fn run_wires_the_settings_and_the_senders_own_address() {
    let dir = std::env::temp_dir();
    let config = lxmf_bridge::config::Config::parse(
        "secret_file = \"s\"\nidentity_file = \"i\"\nwebsite_recipients = true\nper_recipient_per_hour = 1\n",
        &dir,
    )
    .unwrap();
    assert!(config.recipients.is_empty());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let fake = Arc::new(Fake { own: Some(ME), ..Fake::default() });
    let sender = fake.clone();
    tokio::spawn(async move {
        lxmf_bridge::run(&config, SECRET.to_vec(), listener, sender, Retry { waits: vec![] }, std::future::pending::<()>()).await
    });
    let now = unix_now();
    assert_eq!(exchange(addr, &signed(&alert_to(&hex::encode(ME), "x"), now)).await.0, 422);
    assert_eq!(exchange(addr, &signed(&alert_to(&hex::encode(THEM), "x"), now - 1)).await.0, 202);
    assert_eq!(exchange(addr, &signed(&alert_to(&hex::encode(THEM), "x"), now - 2)).await.0, 429);
    assert_eq!(sent_to(&fake, 1).await, [THEM]);
}

// Addresses the website names have a pool and a queue of their own.

fn named_to(i: u32) -> String {
    hex::encode([&i.to_le_bytes()[..], &[0; 12]].concat())
}

#[tokio::test]
async fn named_deliveries_that_hold_every_named_slot_do_not_hold_up_the_list() {
    // Every named address is stuck: 4 slots, one job held by the dispatcher, 20 waiting.
    let bridge = start_named(
        Fake { stuck_to: Some(THEM), ..Fake::default() },
        vec![[1; 16], [2; 16]],
        |settings| {
            on(settings);
            settings.per_recipient_per_hour = 100;
        },
        Named::default(),
        DEFAULT_NAMED_QUEUE,
    )
    .await;
    let now = unix_now();
    let mut codes = Vec::new();
    for i in 0..40 {
        codes.push(exchange(bridge.addr, &signed(&alert_to(&hex::encode(THEM), &format!("named {i}")), now - i)).await.0);
        tokio::task::yield_now().await;
    }
    // Only the named queue is full: 4 in slots, 1 in the dispatcher's hands and 20 waiting.
    assert_eq!(codes.iter().filter(|c| **c == 202).count(), 25, "{codes:?}");
    assert!(codes[25..].iter().all(|c| *c == 503), "{codes:?}");
    // The list still has its slots and its queue room: taken and delivered.
    assert_eq!(exchange(bridge.addr, &signed(BODY, now - 50)).await.0, 202);
    assert_eq!(sent_to(&bridge.fake, 2).await, [[1; 16], [2; 16]]);
}

#[tokio::test]
async fn a_full_named_queue_is_503_for_named_alerts_only() {
    let bridge = start_named(
        Fake { stuck_to: Some(THEM), ..Fake::default() },
        vec![[1; 16]],
        |settings| {
            on(settings);
            settings.per_recipient_per_hour = 100;
        },
        Named { slots: 1, ..Named::default() },
        2,
    )
    .await;
    let now = unix_now();
    let mut codes = Vec::new();
    for i in 0..6 {
        let (code, reason) = exchange(bridge.addr, &signed(&alert_to(&hex::encode(THEM), "x"), now - i)).await;
        assert_eq!(reason.is_empty(), code == 202, "{code} {reason}");
        codes.push(code);
        tokio::task::yield_now().await;
    }
    // 1 slot, 1 held by the dispatcher, 2 waiting.
    assert_eq!(codes, [202, 202, 202, 202, 503, 503]);
    // The list is not told to wait, and an address that is not stuck is refused as well while the queue is full.
    assert_eq!(exchange(bridge.addr, &signed(BODY, now - 10)).await.0, 202);
    assert_eq!(exchange(bridge.addr, &signed(&alert_to(&named_to(1), "y"), now - 11)).await.0, 503);
    assert_eq!(sent_to(&bridge.fake, 1).await, [[1; 16]]);
}

#[tokio::test]
async fn a_named_delivery_that_takes_too_long_gives_its_slot_back() {
    let bridge = start_named(
        Fake { stuck_to: Some(THEM), ..Fake::default() },
        vec![],
        on,
        Named { slots: 1, deadline: Duration::from_millis(300), max_stamp_cost: 12.0 },
        DEFAULT_NAMED_QUEUE,
    )
    .await;
    let now = unix_now();
    let other = hex::encode([5; 16]);
    assert_eq!(exchange(bridge.addr, &signed(&alert_to(&hex::encode(THEM), "stuck"), now)).await.0, 202);
    assert_eq!(exchange(bridge.addr, &signed(&alert_to(&other, "waits"), now - 1)).await.0, 202);
    // The one slot is held until the deadline, and then the second alert is sent.
    assert_eq!(sent_to(&bridge.fake, 1).await, [[5; 16]]);
}
