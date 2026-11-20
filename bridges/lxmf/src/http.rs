//! A small HTTP/1.1 server for the one thing the bridge does.
//!
//! `POST /alert` takes a signed alert and `GET /healthz` says the bridge is running. Everything
//! else is refused with a bare status line. A connection carries one request and is then closed.
//! Requests are read with fixed limits and time limits, and an alert is not looked at as JSON
//! until its time and signature have been checked.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};

use crate::alert::Alert;
use crate::verify::{self, Reject, Replay};

/// The most a request line and its headers may take.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;
/// How long a client has to send its headers, and then its body.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections served at once; more are closed at once.
const MAX_CONNECTIONS: usize = 64;

/// What the server needs to know.
#[derive(Debug)]
pub struct Settings {
    pub secret: Vec<u8>,
    pub max_age_seconds: u64,
    pub max_body_bytes: usize,
    /// How long the headers may take to arrive, and then the body.
    pub read_timeout: Duration,
}

impl Settings {
    pub fn new(secret: Vec<u8>, max_age_seconds: u64, max_body_bytes: usize) -> Self {
        Self { secret, max_age_seconds, max_body_bytes, read_timeout: READ_TIMEOUT }
    }
}

/// A server's settings, what it has seen, and where alerts go.
pub struct Server {
    settings: Settings,
    replay: Mutex<Replay>,
    alerts: mpsc::Sender<Alert>,
}

/// The seconds since 1970.
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Server {
    pub fn new(settings: Settings, alerts: mpsc::Sender<Alert>) -> Arc<Self> {
        Arc::new(Self { settings, replay: Mutex::new(Replay::default()), alerts })
    }

    /// Serves connections from `listener` until it fails.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                // A failed accept (out of descriptors, say) is not the end of the server.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
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
        let (status, body) = match self.request(&mut stream).await {
            Ok(body) => body,
            Err(status) => (status, ""),
        };
        let reason = match status {
            200 => "OK",
            202 => "Accepted",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            409 => "Conflict",
            411 => "Length Required",
            413 => "Content Too Large",
            431 => "Request Header Fields Too Large",
            _ => "Service Unavailable",
        };
        let answer = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    async fn request<T: AsyncRead + Unpin>(&self, stream: &mut T) -> Result<(u16, &'static str), u16> {
        let (head, mut body) = read_head(stream, self.settings.read_timeout).await?;
        let head = Head::parse(&head)?;
        match (head.method, head.path) {
            ("GET", "/healthz") => return Ok((200, "ok\n")),
            ("POST", "/alert") => {}
            (_, "/healthz" | "/alert") => return Err(405),
            _ => return Err(404),
        }
        let now = unix_now();
        let (Some(timestamp), Some(signature)) = (head.timestamp, head.signature) else { return Err(401) };
        let sent = verify::check_timestamp(timestamp, now, self.settings.max_age_seconds).map_err(|why| refuse(why, "timestamp"))?;
        let length = head.length.ok_or(411u16)?;
        if length > self.settings.max_body_bytes {
            return Err(413);
        }
        // What came with the headers may be more than the body (a client that does not wait for us).
        body.truncate(length);
        let missing = length - body.len();
        if missing > 0 {
            let start = body.len();
            body.resize(length, 0);
            tokio::time::timeout(self.settings.read_timeout, stream.read_exact(&mut body[start..]))
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
        let alert = Alert::parse(&body).map_err(|_| 400u16)?;
        match self.alerts.try_send(alert) {
            Ok(()) => Ok((202, "")),
            Err(_) => {
                tracing::warn!("alert refused: the queue is full");
                Err(503)
            }
        }
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
