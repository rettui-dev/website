//! The whole way: a signed request to the bridge's HTTP server, an LXMF message over Reticulum
//! (the bridge connects as a client to a local TCP interface), and a receiver, another Reticulum
//! instance in this process, that checks what arrives. No network outside this computer is used.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use lxmf_bridge::config::Config;
use lxmf_bridge::http::unix_now;
use lxmf_bridge::lxmf::Lxmf;
use lxmf_bridge::queue::Retry;
use lxmf_bridge::verify::sign;
use lxmf_core::handlers::get_announce_app_data;
use lxmf_core::message_api::LxMessage;
use rns_runtime::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SECRET: &[u8] = b"end-to-end-test-secret";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn post_alert(addr: std::net::SocketAddr, body: &str) -> String {
    let ts = unix_now().to_string();
    let request = format!(
        "POST /alert HTTP/1.1\r\nContent-Length: {}\r\nX-Rettui-Timestamp: {ts}\r\nX-Rettui-Signature: {}\r\n\r\n{body}",
        body.len(),
        sign(SECRET, &ts, body.as_bytes())
    );
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    answer.lines().next().unwrap_or_default().to_string()
}

/// The first message the receiver is given, and who from.
async fn next_message(destination: &mut RegisteredDestination, address: [u8; 16]) -> LxMessage {
    let wait = async {
        loop {
            let data = tokio::select! {
                Some((data, _)) = destination.events.link_packets.recv() => data,
                Some(done) = destination.events.resource_completions.recv() => done.data,
            };
            // Over a Link the message arrives whole; as a bare packet it would lack the destination hash.
            let wire = if data.starts_with(&address) { data } else { [address.as_slice(), &data].concat() };
            if let Ok(message) = LxMessage::unpack(&wire) {
                return message;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(60), wait).await.expect("a message arrives")
}

async fn receiver(dir: &Path, port: u16) -> (ReticulumHandle, RegisteredDestination, [u8; 16]) {
    let config = dir.join("receiver");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("config"),
        format!(
            "[reticulum]\n  enable_transport = False\n  share_instance = No\n[logging]\n  loglevel = 3\n[interfaces]\n  [[Local]]\n    type = TCPServerInterface\n    enabled = Yes\n    listen_ip = 127.0.0.1\n    listen_port = {port}\n"
        ),
    )
    .unwrap();
    let runtime = rns_runtime::reticulum::init_with_options(
        config.to_str(),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
        InitOptions::default(),
    )
    .await
    .unwrap();
    let options = DestinationRuntimeOptions {
        proof_strategy: ProofStrategy::ProveAll,
        resource_strategy: ResourceStrategy::AcceptAll,
        default_app_data: Some(get_announce_app_data(Some("test receiver"), None)),
        ..DestinationRuntimeOptions::default()
    };
    let destination = runtime.register_destination(Identity::new(), "lxmf.delivery", options).await.unwrap();
    let address = destination.handle.destination_hash();
    (runtime, destination, address)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_alert_posted_to_the_bridge_arrives_as_an_lxmf_message() {
    let dir = std::env::temp_dir().join(format!("lxmf-bridge-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let (receiver_runtime, mut inbox, address) = receiver(&dir, port).await;

    let config = Config::parse(
        &format!(
            "secret_file = \"secret\"\nidentity_file = \"data/identity\"\ndisplay_name = \"Bridge test\"\nrecipients = [\"{}\"]\nentry_points = [\"127.0.0.1:{port}\"]\n",
            hex::encode(address)
        ),
        &dir,
    )
    .unwrap();
    let lxmf = Arc::new(Lxmf::start(&config).await.unwrap());
    // The receiver announces itself (as a real client does), so the bridge knows its key.
    let announce = DestinationAnnounceOptions { app_data: Some(get_announce_app_data(Some("test receiver"), None)), ..Default::default() };
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if inbox.handle.announce(announce.clone()).await.is_ok() {
            break;
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let bridge = {
        let (config, lxmf) = (config.clone(), lxmf.clone());
        tokio::spawn(async move {
            lxmf_bridge::run(&config, SECRET.to_vec(), listener, lxmf, Retry::default(), stopped).await;
        })
    };

    // A short alert goes as one packet over a Link.
    let body = r#"{"event":"down","host":"front:4242","name":"Front","message":"Front (front:4242) is down since 12:03 UTC."}"#;
    assert_eq!(post_alert(http, body).await, "HTTP/1.1 202 Accepted");
    let message = next_message(&mut inbox, address).await;
    assert_eq!(message.title_text(), "down");
    assert_eq!(message.content_text(), "Front (front:4242) is down since 12:03 UTC.");
    assert_eq!(message.source_hash(), lxmf.address());
    assert_eq!(message.destination_hash(), address);

    // A long one is cut to 1000 characters, and goes as a Resource.
    let long = serde_json::json!({"event": "still_down", "message": "w".repeat(3000)}).to_string();
    assert_eq!(post_alert(http, &long).await, "HTTP/1.1 202 Accepted");
    let message = next_message(&mut inbox, address).await;
    assert_eq!(message.title_text(), "still_down");
    assert_eq!(message.content_text().chars().count(), 1000);

    let _ = stop.send(());
    bridge.await.unwrap();
    lxmf.shutdown().await;
    receiver_runtime.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(&dir);
}
