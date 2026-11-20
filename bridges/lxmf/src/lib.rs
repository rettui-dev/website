//! A bridge from the rettui website's alert webhook to LXMF messages over Reticulum.
//!
//! The website signs each alert and posts it to `/alert` ([`http`]); the bridge checks the
//! signature and the time ([`verify`]), turns the alert into a short message ([`alert`]) and sends
//! it to each recipient ([`queue`], with [`lxmf`] as the sender that talks to Reticulum).

pub mod alert;
pub mod config;
pub mod http;
pub mod lxmf;
pub mod queue;
pub mod verify;

use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::mpsc;

use config::Config;
use queue::{QUEUE_LEN, Retry, Sender};

/// Serves alerts from `listener` and sends them with `sender` to the recipients in `config`, until
/// `stop` finishes.
pub async fn run<S: Sender>(config: &Config, secret: Vec<u8>, listener: TcpListener, sender: Arc<S>, retry: Retry, stop: impl Future) {
    let (alerts, queued) = mpsc::channel(QUEUE_LEN);
    let settings = http::Settings::new(secret, config.max_age_seconds, config.max_body_bytes);
    let server = http::Server::new(settings, alerts);
    tokio::spawn(queue::run(queued, sender, config.recipients.clone(), retry));
    tokio::select! {
        () = server.serve(listener) => {}
        _ = stop => {}
    }
}
