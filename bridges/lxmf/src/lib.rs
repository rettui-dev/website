//! A bridge from the rettui website's alert webhook to LXMF messages over Reticulum.
//!
//! The website signs each alert and posts it to `/alert` ([`http`]); the bridge checks the
//! signature and the time ([`verify`]), turns the alert into a short message ([`alert`]) and sends
//! it to each recipient ([`queue`], with [`lxmf`] as the sender that talks to Reticulum), or, if the
//! alert names one and the settings allow it, to that address only (in a pool and queue of its own), within the hourly [`limits`].

pub mod alert;
pub mod config;
pub mod http;
pub mod limits;
pub mod lxmf;
pub mod queue;
pub mod verify;

use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::mpsc;

use config::Config;
use queue::{Named, QUEUE_LEN, Retry, Sender};

/// Serves alerts from `listener` and sends them with `sender` to the recipients in `config`, until
/// `stop` finishes.
pub async fn run<S: Sender>(config: &Config, secret: Vec<u8>, listener: TcpListener, sender: Arc<S>, retry: Retry, stop: impl Future) {
    let (alerts, queued) = mpsc::channel(QUEUE_LEN);
    // Alerts to addresses the website names wait and are sent apart from the list's.
    let (named_alerts, named_queued) = mpsc::channel(config.website_queue as usize);
    let mut settings = http::Settings::new(secret, config.max_age_seconds, config.max_body_bytes);
    settings.allow_from = config.allow_from.clone();
    settings.website_recipients = config.website_recipients;
    settings.has_recipients = !config.recipients.is_empty();
    settings.own_address = sender.own_address();
    settings.per_recipient_per_hour = config.per_recipient_per_hour as usize;
    settings.recipients_per_hour = config.recipients_per_hour as usize;
    let server = http::Server::new(settings, alerts, named_alerts);
    let named = Named {
        slots: config.website_slots as usize,
        deadline: std::time::Duration::from_secs(config.website_delivery_seconds),
        max_stamp_cost: f64::from(config.website_max_stamp_cost),
    };
    tokio::spawn(queue::run(queued, named_queued, sender, config.recipients.clone(), retry, named));
    tokio::select! {
        () = server.serve(listener) => {}
        _ = stop => {}
    }
}
