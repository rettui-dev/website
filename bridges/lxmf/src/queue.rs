//! Sending: alerts wait in a small queue and go to each recipient, with a few tries.
//!
//! A failed delivery is logged (the recipient's address, never a secret or the text) and given up
//! on after the last try. It never stops the bridge, and a slow recipient does not hold up the
//! others.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc};

use crate::alert::Alert;
use crate::config::Hash;

/// Alerts waiting to be sent; a request that finds the queue full is told to try again.
pub const QUEUE_LEN: usize = 100;
/// Deliveries going on at once, waits between tries included.
const MAX_DELIVERIES: usize = 32;

/// Something that can send one message to one destination.
pub trait Sender: Send + Sync + 'static {
    /// Sends `alert` to `to`; an `Err` says why not, in words with no secrets in them.
    fn send(&self, to: Hash, alert: &Alert) -> impl Future<Output = Result<(), String>> + Send;
}

/// How often a delivery is tried: once, and again after each wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retry {
    pub waits: Vec<Duration>,
}

impl Default for Retry {
    /// Three tries, after 5 and 30 seconds, as the website tries its own sends.
    fn default() -> Self {
        Self { waits: vec![Duration::from_secs(5), Duration::from_secs(30)] }
    }
}

/// Sends what comes in on `alerts` to every recipient, until the sending end is closed.
pub async fn run<S: Sender>(mut alerts: mpsc::Receiver<Alert>, sender: Arc<S>, recipients: Vec<Hash>, retry: Retry) {
    let slots = Arc::new(Semaphore::new(MAX_DELIVERIES));
    while let Some(alert) = alerts.recv().await {
        let alert = Arc::new(alert);
        for &to in &recipients {
            // Waiting here for a slot lets the queue fill, which is the signal to slow down.
            let Ok(slot) = slots.clone().acquire_owned().await else { return };
            let (sender, alert, retry) = (sender.clone(), alert.clone(), retry.clone());
            tokio::spawn(async move {
                deliver(&*sender, to, &alert, &retry).await;
                drop(slot);
            });
        }
    }
}

/// One alert to one recipient, tried as often as `retry` says. Whether it got there.
pub async fn deliver<S: Sender>(sender: &S, to: Hash, alert: &Alert, retry: &Retry) -> bool {
    let tries = retry.waits.len() + 1;
    for attempt in 1..=tries {
        match sender.send(to, alert).await {
            Ok(()) => {
                tracing::info!("alert sent to {}", hex::encode(to));
                return true;
            }
            Err(why) => {
                tracing::warn!("alert to {} failed (try {attempt} of {tries}): {why}", hex::encode(to));
                if let Some(wait) = retry.waits.get(attempt - 1) {
                    tokio::time::sleep(*wait).await;
                }
            }
        }
    }
    tracing::error!("alert to {} given up after {tries} tries", hex::encode(to));
    false
}

#[cfg(test)]
pub mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A sender that fails a set number of times for each destination, and keeps what it was given.
    #[derive(Default)]
    pub struct Fake {
        pub fail_first: usize,
        pub sent: Mutex<Vec<(Hash, Alert)>>,
        pub tries: Mutex<Vec<Hash>>,
    }

    impl Sender for Fake {
        async fn send(&self, to: Hash, alert: &Alert) -> Result<(), String> {
            let mut tries = self.tries.lock().unwrap();
            tries.push(to);
            if tries.iter().filter(|t| **t == to).count() <= self.fail_first {
                return Err("no path".into());
            }
            self.sent.lock().unwrap().push((to, alert.clone()));
            Ok(())
        }
    }

    fn alert() -> Alert {
        Alert { title: "down".into(), content: "Front is down.".into() }
    }

    fn quick(tries: usize) -> Retry {
        Retry { waits: vec![Duration::from_millis(1); tries - 1] }
    }

    #[tokio::test]
    async fn a_failed_send_is_tried_again_up_to_the_last_try() {
        let fake = Fake { fail_first: 2, ..Fake::default() };
        assert!(deliver(&fake, [1; 16], &alert(), &quick(3)).await);
        assert_eq!(fake.tries.lock().unwrap().len(), 3);
        assert_eq!(fake.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_delivery_that_keeps_failing_is_given_up() {
        let fake = Fake { fail_first: 99, ..Fake::default() };
        assert!(!deliver(&fake, [1; 16], &alert(), &quick(3)).await);
        assert_eq!(fake.tries.lock().unwrap().len(), 3);
        assert!(fake.sent.lock().unwrap().is_empty());
        // One try only, when no waits are set.
        assert!(!deliver(&fake, [2; 16], &alert(), &Retry { waits: vec![] }).await);
        assert_eq!(fake.tries.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn every_recipient_gets_the_alert_and_one_failing_does_not_stop_the_rest() {
        struct Picky(Fake);
        impl Sender for Picky {
            async fn send(&self, to: Hash, alert: &Alert) -> Result<(), String> {
                if to == [1; 16] { Err("unreachable".into()) } else { self.0.send(to, alert).await }
            }
        }
        let sender = Arc::new(Picky(Fake::default()));
        let (tx, rx) = mpsc::channel(QUEUE_LEN);
        let worker = tokio::spawn(run(rx, sender.clone(), vec![[1; 16], [2; 16], [3; 16]], quick(2)));
        tx.send(alert()).await.unwrap();
        tx.send(alert()).await.unwrap();
        drop(tx);
        worker.await.unwrap();
        // The deliveries run on their own tasks: wait for them.
        for _ in 0..200 {
            if sender.0.sent.lock().unwrap().len() == 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut got: Vec<Hash> = sender.0.sent.lock().unwrap().iter().map(|(to, _)| *to).collect();
        got.sort();
        assert_eq!(got, [[2; 16], [2; 16], [3; 16], [3; 16]]);
    }

    #[tokio::test]
    async fn a_panicking_sender_does_not_stop_the_queue() {
        struct Panics(Fake);
        impl Sender for Panics {
            async fn send(&self, to: Hash, alert: &Alert) -> Result<(), String> {
                if alert.title == "boom" {
                    panic!("sender bug");
                }
                self.0.send(to, alert).await
            }
        }
        let sender = Arc::new(Panics(Fake::default()));
        let (tx, rx) = mpsc::channel(QUEUE_LEN);
        let worker = tokio::spawn(run(rx, sender.clone(), vec![[1; 16]], quick(1)));
        tx.send(Alert { title: "boom".into(), content: "x".into() }).await.unwrap();
        tx.send(alert()).await.unwrap();
        drop(tx);
        worker.await.unwrap();
        for _ in 0..200 {
            if !sender.0.sent.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(sender.0.sent.lock().unwrap().len(), 1);
    }
}
