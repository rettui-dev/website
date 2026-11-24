//! A small HTTP/1.1 server for the one thing the bridge does.
//!
//! `POST /alert` takes a signed alert and `GET /healthz` says the bridge is running. Everything
//! else is refused with a bare status line. A connection carries one request and is then closed.
//! Requests are read with fixed limits and time limits, and an alert is not looked at as JSON
//! until its time and signature have been checked.

use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};

use crate::alert::Alert;
use crate::config::{Hash, parse_hash};
use crate::limits::{Limited, Limits, Log, Scope};
use crate::queue::{Job, short};
use crate::verify::{self, Reject, Replay};

/// The most a request line and its headers may take.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;
/// How long a client has to send its headers, and then its body. Short, as anyone can connect.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(3);
pub const BODY_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
/// Connections served at once; more are closed at once.
const MAX_CONNECTIONS: usize = 64;

/// What the server needs to know.
pub struct Settings {
    pub secret: Vec<u8>,
    pub max_age_seconds: u64,
    pub max_body_bytes: usize,
    /// How long the headers may take to arrive, and then the body.
    pub head_timeout: Duration,
    pub body_timeout: Duration,
    /// The addresses that may connect; empty means any. Others are closed as soon as they connect.
    pub allow_from: Vec<IpAddr>,
    /// Whether a body may name the address it goes to (`to`). If not, one that does is refused.
    pub website_recipients: bool,
    /// Whether there is a configured list for alerts that name nobody.
    pub has_recipients: bool,
    /// The bridge's own address, which is never sent to.
    pub own_address: Option<Hash>,
    /// The most messages an hour to one named address, and the most named addresses an hour.
    pub per_recipient_per_hour: usize,
    pub recipients_per_hour: usize,
}

// By hand, so that the secret is never printed.
impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("secret", &"<hidden>")
            .field("max_age_seconds", &self.max_age_seconds)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("head_timeout", &self.head_timeout)
            .field("body_timeout", &self.body_timeout)
            .field("allow_from", &self.allow_from)
            .field("website_recipients", &self.website_recipients)
            .finish()
    }
}

impl Settings {
    pub fn new(secret: Vec<u8>, max_age_seconds: u64, max_body_bytes: usize) -> Self {
        Self {
            secret,
            max_age_seconds,
            max_body_bytes,
            head_timeout: HEAD_TIMEOUT,
            body_timeout: BODY_TIMEOUT,
            allow_from: Vec::new(),
            website_recipients: false,
            has_recipients: true,
            own_address: None,
            per_recipient_per_hour: 10,
            recipients_per_hour: 50,
        }
    }
}

/// A server's settings, what it has seen, and where alerts go.
pub struct Server {
    settings: Settings,
    replay: Mutex<Replay>,
    /// What named addresses have been sent lately.
    limits: Mutex<Limits>,
    /// Alerts for the configured list.
    alerts: mpsc::Sender<Job>,
    /// Alerts for addresses the website names: a queue of their own, so they cannot crowd out the list's.
    named_alerts: mpsc::Sender<Job>,
}

/// An answer other than success: the status, a plain reason to send with it, and for a 429 how long
/// to wait.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Answer {
    status: u16,
    reason: &'static str,
    retry_after: Option<u64>,
}

impl Answer {
    fn because(status: u16, reason: &'static str) -> Self {
        Self { status, reason, retry_after: None }
    }
}

impl From<u16> for Answer {
    fn from(status: u16) -> Self {
        Self::because(status, "")
    }
}

/// The seconds since 1970.
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Server {
    pub fn new(settings: Settings, alerts: mpsc::Sender<Job>, named_alerts: mpsc::Sender<Job>) -> Arc<Self> {
        let limits = Limits::new(settings.per_recipient_per_hour, settings.recipients_per_hour);
        Arc::new(Self { settings, replay: Mutex::new(Replay::default()), limits: Mutex::new(limits), alerts, named_alerts })
    }

    /// Serves connections from `listener` until it fails.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                // A failed accept (out of descriptors, say) is not the end of the server.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            // Others than the listed addresses are let go before they cost anything.
            let allowed = &self.settings.allow_from;
            if !allowed.is_empty() && !allowed.contains(&peer.ip().to_canonical()) {
                continue;
            }
            let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
            let server = self.clone();
            tokio::spawn(async move {
                server.connection(stream).await;
                drop(slot);
            });
        }
    }

    /// One request on `stream`, and its answer.
    pub async fn connection<T: AsyncRead + AsyncWrite + Unpin>(&self, mut stream: T) {
        let Answer { status, reason: body, retry_after } = match self.request(&mut stream).await {
            Ok((status, body)) => Answer::because(status, body),
            Err(answer) => answer,
        };
        let reason = match status {
            200 => "OK",
            202 => "Accepted",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            409 => "Conflict",
            411 => "Length Required",
            413 => "Content Too Large",
            422 => "Unprocessable Content",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            _ => "Service Unavailable",
        };
        let retry_after = retry_after.map(|seconds| format!("Retry-After: {seconds}\r\n")).unwrap_or_default();
        let answer = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n{retry_after}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        // The client may be gone already: nothing to do about that.
        let _ = tokio::time::timeout(WRITE_TIMEOUT, async {
            stream.write_all(answer.as_bytes()).await?;
            stream.shutdown().await
        })
        .await;
    }

    /// Reads one request and decides: the status and the text to answer with.
    async fn request<T: AsyncRead + Unpin>(&self, stream: &mut T) -> Result<(u16, &'static str), Answer> {
        let (head, mut body) = read_head(stream, self.settings.head_timeout).await?;
        let head = Head::parse(&head)?;
        match (head.method, head.path) {
            ("GET", "/healthz") => return Ok((200, "ok\n")),
            ("POST", "/alert") => {}
            (_, "/healthz" | "/alert") => return Err(405u16.into()),
            _ => return Err(404u16.into()),
        }
        let now = unix_now();
        let (Some(timestamp), Some(signature)) = (head.timestamp, head.signature) else { return Err(401u16.into()) };
        let sent = verify::check_timestamp(timestamp, now, self.settings.max_age_seconds).map_err(|why| refuse(why, "timestamp"))?;
        // Everything that can be refused without the body is, before waiting for it.
        verify::parse_signature(signature).map_err(|why| refuse(why, "signature"))?;
        let length = head.length.ok_or(411u16)?;
        if length > self.settings.max_body_bytes {
            return Err(413u16.into());
        }
        // What came with the headers may be more than the body (a client that does not wait for us).
        body.truncate(length);
        let missing = length - body.len();
        if missing > 0 {
            let start = body.len();
            body.resize(length, 0);
            tokio::time::timeout(self.settings.body_timeout, stream.read_exact(&mut body[start..]))
                .await
                .map_err(|_| 408u16)?
                .map_err(|_| 400u16)?;
        }
        let signature =
            verify::check_signature(&self.settings.secret, timestamp, &body, signature).map_err(|why| refuse(why, "signature"))?;
        self.replay
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(sent, signature, now, self.settings.max_age_seconds)
            .map_err(|why| refuse(why, "replay"))?;
        let (alert, to) = Alert::parse_with_to(&body).map_err(|_| 400u16)?;
        let to = self.target(to.as_deref())?;
        // The limits and the queue are looked at under one lock, so that a burst of requests cannot
        // all pass the check before any of them is counted.
        let mut limits = self.limits.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(to) = to {
            limits.check(to, now).map_err(|limited| self.limited(to, limited))?;
        }
        let queue = if to.is_some() { &self.named_alerts } else { &self.alerts };
        match queue.try_send(Job { alert, to }) {
            Ok(()) => {
                if let Some(to) = to {
                    limits.record(to, now);
                }
                Ok((202, ""))
            }
            Err(_) if to.is_some() => {
                tracing::warn!("alert to a named address refused: its queue is full");
                Err(Answer::because(503, "too many alerts to named addresses are waiting\n"))
            }
            Err(_) => {
                tracing::warn!("alert refused: the queue is full");
                Err(503u16.into())
            }
        }
    }

    /// The address a body names, if it names one, once it is known to be allowed.
    fn target(&self, to: Option<&str>) -> Result<Option<Hash>, Answer> {
        let Some(text) = to else {
            if !self.settings.has_recipients {
                return Err(Answer::because(400, "this bridge has no recipients list: the alert must name an address in \"to\"\n"));
            }
            return Ok(None);
        };
        if !self.settings.website_recipients {
            tracing::warn!("alert refused: it names an address and website_recipients is off");
            return Err(Answer::because(403, "this bridge does not send to addresses the website names (website_recipients is off)\n"));
        }
        let Some(hash) = parse_hash(text) else {
            return Err(Answer::because(400, "\"to\" is not a 32 digit hex address\n"));
        };
        if self.settings.own_address == Some(hash) {
            tracing::warn!("alert refused: it names the bridge's own address");
            return Err(Answer::because(422, "\"to\" is the bridge's own address\n"));
        }
        Ok(Some(hash))
    }

    /// The answer for an address that is over a limit, and the log line for it, once an hour.
    fn limited(&self, to: Hash, limited: Limited) -> Answer {
        match limited.log {
            Log::Quiet => {}
            Log::Line => match limited.scope {
                Scope::Address => tracing::warn!(
                    "alerts to {} refused: over {} an hour for that address (more are refused quietly for an hour)",
                    short(to),
                    self.settings.per_recipient_per_hour
                ),
                Scope::Addresses => tracing::warn!(
                    "alerts to {} refused: over {} different addresses an hour (more are refused quietly for an hour)",
                    short(to),
                    self.settings.recipients_per_hour
                ),
            },
            Log::Overflow => tracing::warn!("alerts to many more addresses refused; not logging each one for the next hour"),
        }
        tracing::debug!("the refused address was {}", hex::encode(to));
        let reason = match limited.scope {
            Scope::Address => "too many alerts to that address this hour\n",
            Scope::Addresses => "too many different addresses this hour\n",
        };
        Answer { status: 429, reason, retry_after: Some(limited.retry_after) }
    }
}

/// The status for a request that did not pass, and a line in the log (the reason only: never the
/// signature, the body or the secret).
fn refuse(why: Reject, what: &str) -> u16 {
    tracing::warn!("request refused: {what} check failed ({why:?})");
    match why {
        Reject::Replay => 409,
        Reject::Busy => 503,
        Reject::Malformed | Reject::Stale | Reject::Future | Reject::BadSignature => 401,
    }
}

/// Reads up to the blank line after the headers: the head, and whatever came after it.
async fn read_head<T: AsyncRead + Unpin>(stream: &mut T, timeout: Duration) -> Result<(Vec<u8>, Vec<u8>), u16> {
    let read = async {
        let mut buffer = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                let rest = buffer.split_off(end + 4);
                return Ok((buffer, rest));
            }
            if buffer.len() > MAX_HEAD_BYTES {
                return Err(431u16);
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return Err(400),
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        }
    };
    tokio::time::timeout(timeout, read).await.map_err(|_| 408u16)?
}

/// A request's line and the headers the bridge looks at.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Head<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub length: Option<usize>,
    pub timestamp: Option<&'a str>,
    pub signature: Option<&'a str>,
}

impl<'a> Head<'a> {
    /// Reads a request head (without its closing blank line). A header that is repeated, a
    /// `Transfer-Encoding` of any kind, and a head that is not text are refused: 400.
    pub fn parse(head: &'a [u8]) -> Result<Self, u16> {
        let text = std::str::from_utf8(head).map_err(|_| 400u16)?;
        let mut lines = text.split("\r\n");
        let mut line = lines.next().unwrap_or_default().split(' ');
        let (Some(method), Some(path), Some(version), None) = (line.next(), line.next(), line.next(), line.next()) else {
            return Err(400);
        };
        if !matches!(version, "HTTP/1.1" | "HTTP/1.0") || !path.starts_with('/') {
            return Err(400);
        }
        // Only the path matters: a query string is not looked at.
        let path = path.split_once('?').map_or(path, |(path, _)| path);
        let mut out = Head { method, path, ..Head::default() };
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').ok_or(400u16)?;
            let value = value.trim_matches([' ', '\t']);
            match name.to_ascii_lowercase().as_str() {
                "content-length" => {
                    if out.length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(400);
                    }
                    // Too long a number is too long a body, not a bad request.
                    out.length = Some(value.parse().unwrap_or(usize::MAX));
                }
                "x-rettui-timestamp" if out.timestamp.replace(value).is_some() => return Err(400),
                "x-rettui-signature" if out.signature.replace(value).is_some() => return Err(400),
                "transfer-encoding" => return Err(400),
                _ => {}
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_is_never_printed() {
        let settings = Settings::new(b"very-secret-value-1234".to_vec(), 300, 1024);
        let shown = format!("{settings:?} {settings:#?}");
        assert!(!shown.contains("very-secret") && !shown.contains("118, 101"), "{shown}");
        assert!(shown.contains("max_age_seconds"));
    }

    #[test]
    fn a_head_is_read() {
        let head = Head::parse(
            b"POST /alert?x=1 HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\nx-rettui-timestamp:  1700000000\r\nX-Rettui-Signature: sha256=ab\r\n",
        )
        .unwrap();
        assert_eq!(
            head,
            Head { method: "POST", path: "/alert", length: Some(12), timestamp: Some("1700000000"), signature: Some("sha256=ab") }
        );
    }

    #[test]
    fn a_head_that_is_not_one_is_refused() {
        let cases: [&[u8]; 14] = [
            b"",
            b"POST",
            b"POST /alert",
            b"POST /alert HTTP/1.1 extra",
            b"POST /alert HTTP/2",
            b"POST alert HTTP/1.1",
            b"POST /alert HTTP/1.1\r\nno colon here",
            b"POST /alert HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1",
            b"POST /alert HTTP/1.1\r\nContent-Length: -1",
            b"POST /alert HTTP/1.1\r\nContent-Length: 1 2",
            b"POST /alert HTTP/1.1\r\nTransfer-Encoding: chunked",
            b"POST /alert HTTP/1.1\r\nX-Rettui-Timestamp: 1\r\nx-rettui-timestamp: 1",
            b"POST /alert HTTP/1.1\r\nX-Rettui-Signature: a\r\nX-RETTUI-SIGNATURE: a",
            b"POST /al\xffert HTTP/1.1",
        ];
        for case in cases {
            assert_eq!(Head::parse(case), Err(400), "{}", String::from_utf8_lossy(case));
        }
    }

    #[test]
    fn a_huge_length_is_kept_as_one_for_the_size_check_to_refuse() {
        let head = Head::parse(b"POST /alert HTTP/1.1\r\nContent-Length: 99999999999999999999999999").unwrap();
        assert_eq!(head.length, Some(usize::MAX));
    }
}
