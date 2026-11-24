//! Sending: alerts wait in a small queue and go to each recipient, with a few tries.
//!
//! A failed delivery is logged (the recipient's address, never a secret or the text) and given up
//! on after the last try. It never stops the bridge, and a slow recipient does not hold up the
//! others.

use std::any::Any;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::alert::Alert;
use crate::config::Hash;

/// Alerts waiting for the configured list; a request that finds the queue full is told to try again.
pub const QUEUE_LEN: usize = 100;
/// Deliveries to the configured list going on at once, waits between tries included.
const MAX_DELIVERIES: usize = 32;

/// Something that can send one message to one destination.
pub trait Sender: Send + Sync + 'static {
    /// Sends `alert` to `to`; an `Err` says why not, in words with no secrets in them.
    fn send(&self, to: Hash, alert: &Alert) -> impl Future<Output = Result<(), String>> + Send;

    /// [`Sender::send`] for one delivery, with what the delivery carries from one try to the next and
    /// the limits it is under. A sender with no use for them leaves this as it is.
    fn send_with(&self, to: Hash, alert: &Alert, _delivery: &Delivery) -> impl Future<Output = Result<(), String>> + Send {
        self.send(to, alert)
    }

    /// The address messages are sent from, if there is one. The server refuses to send to it.
    fn own_address(&self) -> Option<Hash> {
        None
    }
}

/// An alert and where it goes: to the one address the website named, or to the configured list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub alert: Alert,
    pub to: Option<Hash>,
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

/// Alerts waiting for addresses the website names, unless set otherwise.
pub const DEFAULT_NAMED_QUEUE: usize = 20;

/// What addresses the website names get: a pool of their own, so that they cannot hold up the list.
#[derive(Debug, Clone, PartialEq)]
pub struct Named {
    /// Deliveries going on at once. Also the most stamp threads that may be left running by
    /// deliveries that were given up on: with that many, no new delivery starts.
    pub slots: usize,
    /// The longest a whole delivery may take, all tries included.
    pub deadline: Duration,
    /// The highest stamp cost worked out for such an address.
    pub max_stamp_cost: f64,
}

impl Default for Named {
    fn default() -> Self {
        Self { slots: 4, deadline: Duration::from_secs(300), max_stamp_cost: 12.0 }
    }
}

/// The first 8 hex digits of an address: what the log shows of an address the website named.
pub fn short(to: Hash) -> String {
    hex::encode(&to[..4])
}

/// One delivery: the limits it is under, and what the sender keeps for its next try.
#[derive(Default)]
pub struct Delivery {
    max_stamp_cost: Option<f64>,
    label: String,
    stamp_slot: Mutex<Option<OwnedSemaphorePermit>>,
    kept: Mutex<Option<Box<dyn Any + Send>>>,
    refused: AtomicBool,
}

impl Delivery {
    /// A delivery to the configured list: no limits of its own.
    fn listed(to: Hash) -> Self {
        Self { label: hex::encode(to), ..Self::default() }
    }

    /// A delivery with its own highest stamp cost and no stamp permit (for tests of the checks).
    pub fn capped(max_stamp_cost: f64) -> Self {
        Self { max_stamp_cost: Some(max_stamp_cost), ..Self::default() }
    }

    /// A delivery to an address the website named.
    fn named(to: Hash, max_stamp_cost: f64, stamp_slot: OwnedSemaphorePermit) -> Self {
        Self { max_stamp_cost: Some(max_stamp_cost), label: short(to), stamp_slot: Mutex::new(Some(stamp_slot)), ..Self::default() }
    }

    /// The highest stamp cost to work out, if the delivery has a lower one than the sender's own.
    pub fn max_stamp_cost(&self) -> Option<f64> {
        self.max_stamp_cost
    }

    /// The address as the log shows it: all of it for the list, a prefix for one the website named.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Takes the right to run one stamp thread, if the delivery has one. A sender moves it into the
    /// thread, so it is only given back when the thread has stopped, whatever became of the delivery.
    pub fn take_stamp_slot(&self) -> Option<OwnedSemaphorePermit> {
        self.stamp_slot.lock().unwrap_or_else(PoisonError::into_inner).take()
    }

    /// Gives back what [`Delivery::take_stamp_slot`] took, for a next stamp.
    pub fn put_stamp_slot(&self, slot: Option<OwnedSemaphorePermit>) {
        *self.stamp_slot.lock().unwrap_or_else(PoisonError::into_inner) = slot;
    }

    /// Says that more tries would fail the same way: the delivery ends after this one.
    pub fn refuse(&self) {
        self.refused.store(true, Ordering::Relaxed);
    }

    /// Whether [`Delivery::refuse`] was called.
    pub fn refused(&self) -> bool {
        self.refused.load(Ordering::Relaxed)
    }

    /// Runs `f` on what the sender kept, which starts as `T::default()` (or when it kept another type).
    pub fn with_kept<T: Any + Send + Default, R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        if !kept.as_ref().is_some_and(|k| k.is::<T>()) {
            *kept = Some(Box::new(T::default()));
        }
        match kept.as_mut().and_then(|k| k.downcast_mut::<T>()) {
            Some(value) => f(value),
            // Just set to a `T` above.
            None => f(&mut T::default()),
        }
    }
}

/// Sends what comes in on `alerts` to every recipient, until the sending end is closed; and what comes
/// in on `named_alerts` (jobs that name one address) to that address only, with its own slots, under the
/// limits in `named`.
pub async fn run<S: Sender>(
    alerts: mpsc::Receiver<Job>,
    named_alerts: mpsc::Receiver<Job>,
    sender: Arc<S>,
    recipients: Vec<Hash>,
    retry: Retry,
    named: Named,
) {
    tokio::join!(run_listed(alerts, sender.clone(), recipients, retry.clone()), run_named(named_alerts, sender, retry, named));
}

async fn run_listed<S: Sender>(mut alerts: mpsc::Receiver<Job>, sender: Arc<S>, recipients: Vec<Hash>, retry: Retry) {
    let slots = Arc::new(Semaphore::new(MAX_DELIVERIES));
    while let Some(Job { alert, to }) = alerts.recv().await {
        // A job with an address belongs to the named pool: the server sends those there.
        if to.is_some() {
            continue;
        }
        let alert = Arc::new(alert);
        for to in recipients.iter().copied() {
            // Waiting here for a slot lets the queue fill, which is the signal to slow down.
            let Ok(slot) = slots.clone().acquire_owned().await else { return };
            let (sender, alert, retry) = (sender.clone(), alert.clone(), retry.clone());
            tokio::spawn(async move {
                deliver_with(&*sender, to, &alert, &retry, &Delivery::listed(to)).await;
                drop(slot);
            });
        }
    }
}

async fn run_named<S: Sender>(mut alerts: mpsc::Receiver<Job>, sender: Arc<S>, retry: Retry, named: Named) {
    let slots = Arc::new(Semaphore::new(named.slots));
    // A delivery given up on at its deadline may leave a stamp thread behind that cannot be called back
    // at once. It keeps its permit here until it stops, so that there are never more than `named.slots`.
    let stamping = Arc::new(Semaphore::new(named.slots));
    while let Some(Job { alert, to }) = alerts.recv().await {
        // Only a job with an address comes here: the server sends the others to the list.
        let Some(to) = to else { continue };
        let alert = Arc::new(alert);
        let Ok(slot) = slots.clone().acquire_owned().await else { return };
        let Ok(stamp_slot) = stamping.clone().acquire_owned().await else { return };
        let (sender, retry, named) = (sender.clone(), retry.clone(), named.clone());
        tokio::spawn(async move {
            let delivery = Delivery::named(to, named.max_stamp_cost, stamp_slot);
            let sending = deliver_with(&*sender, to, &alert, &retry, &delivery);
            // The slot goes back at the deadline even if a stamp thread is still running: the thread is
            // told to stop, and holds its own permit until it has.
            if tokio::time::timeout(named.deadline, sending).await.is_err() {
                tracing::error!("alert to {} given up: not delivered within {} seconds", short(to), named.deadline.as_secs());
                tracing::debug!("the address was {}", hex::encode(to));
            }
            drop(slot);
        });
    }
}

/// One alert to one recipient, tried as often as `retry` says. Whether it got there.
pub async fn deliver<S: Sender>(sender: &S, to: Hash, alert: &Alert, retry: &Retry) -> bool {
    deliver_with(sender, to, alert, retry, &Delivery::listed(to)).await
}

/// [`deliver`] for a [`Delivery`] with its own limits and log label.
pub async fn deliver_with<S: Sender>(sender: &S, to: Hash, alert: &Alert, retry: &Retry, delivery: &Delivery) -> bool {
    let tries = retry.waits.len() + 1;
    let label = delivery.label();
    for attempt in 1..=tries {
        match sender.send_with(to, alert, delivery).await {
            Ok(()) => {
                tracing::info!("alert sent to {label}");
                tracing::debug!("the address was {}", hex::encode(to));
                return true;
            }
            Err(why) => {
                tracing::warn!("alert to {label} failed (try {attempt} of {tries}): {why}");
                if delivery.refused() {
                    tracing::error!("alert to {label} given up: {why}");
                    return false;
                }
                if let Some(wait) = retry.waits.get(attempt - 1) {
                    tokio::time::sleep(*wait).await;
                }
            }
        }
    }
    tracing::error!("alert to {label} given up after {tries} tries");
    tracing::debug!("the address was {}", hex::encode(to));
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

    fn job() -> Job {
        Job { alert: alert(), to: None }
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
        let (_, named_rx) = mpsc::channel(1);
        let worker = tokio::spawn(run(rx, named_rx, sender.clone(), vec![[1; 16], [2; 16], [3; 16]], quick(2), Named::default()));
        tx.send(job()).await.unwrap();
        tx.send(job()).await.unwrap();
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
        let worker = tokio::spawn(run(rx, closed(), sender.clone(), vec![[1; 16]], quick(1), Named::default()));
        tx.send(Job { alert: Alert { title: "boom".into(), content: "x".into() }, to: None }).await.unwrap();
        tx.send(job()).await.unwrap();
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

    /// A queue that nothing is sent on.
    fn closed() -> mpsc::Receiver<Job> {
        mpsc::channel(1).1
    }

    async fn wait_for(what: &str, done: impl Fn() -> bool) {
        for _ in 0..300 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{what}");
    }

    #[tokio::test]
    async fn a_job_that_names_an_address_goes_there_only() {
        let sender = Arc::new(Fake::default());
        let (tx, rx) = mpsc::channel(QUEUE_LEN);
        let (named_tx, named_rx) = mpsc::channel(QUEUE_LEN);
        let worker = tokio::spawn(run(rx, named_rx, sender.clone(), vec![[1; 16], [2; 16]], quick(1), Named::default()));
        named_tx.send(Job { alert: alert(), to: Some([9; 16]) }).await.unwrap();
        drop((tx, named_tx));
        worker.await.unwrap();
        wait_for("the alert is sent", || !sender.sent.lock().unwrap().is_empty()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let got: Vec<Hash> = sender.sent.lock().unwrap().iter().map(|(to, _)| *to).collect();
        assert_eq!(got, [[9; 16]]);
    }

    /// A sender that never finishes sending to some addresses.
    struct Stuck(Fake, Vec<Hash>);
    impl Sender for Stuck {
        async fn send(&self, to: Hash, alert: &Alert) -> Result<(), String> {
            if self.1.contains(&to) {
                std::future::pending::<()>().await;
            }
            self.0.send(to, alert).await
        }
    }

    fn small(slots: usize, deadline: Duration) -> Named {
        Named { slots, deadline, max_stamp_cost: 12.0 }
    }

    #[tokio::test]
    async fn the_deadline_gives_the_slot_back() {
        let sender = Arc::new(Stuck(Fake::default(), vec![[8; 16]]));
        let (tx, rx) = mpsc::channel(QUEUE_LEN);
        let (named_tx, named_rx) = mpsc::channel(QUEUE_LEN);
        tokio::spawn(run(rx, named_rx, sender.clone(), vec![], quick(1), small(1, Duration::from_millis(100))));
        let stuck = |to| Job { alert: alert(), to: Some(to) };
        named_tx.send(stuck([8; 16])).await.unwrap();
        named_tx.send(stuck([9; 16])).await.unwrap();
        // The only slot is held by the first alert until its deadline, and then the second is sent.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(sender.0.sent.lock().unwrap().is_empty());
        wait_for("the second alert is sent", || !sender.0.sent.lock().unwrap().is_empty()).await;
        assert_eq!(sender.0.sent.lock().unwrap()[0].0, [9; 16]);
        drop(tx);
    }

    #[tokio::test]
    async fn no_named_delivery_starts_while_given_up_stamp_threads_fill_the_pool() {
        // Stands in for a stamp thread that outlives its delivery: it holds the stamp permit for 400 ms.
        struct Stamps(Fake);
        impl Sender for Stamps {
            async fn send(&self, to: Hash, alert: &Alert) -> Result<(), String> {
                self.0.send(to, alert).await
            }
            async fn send_with(&self, to: Hash, alert: &Alert, delivery: &Delivery) -> Result<(), String> {
                if to == [8; 16] {
                    let slot = delivery.take_stamp_slot();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                        drop(slot);
                    });
                    std::future::pending::<()>().await;
                }
                self.0.send(to, alert).await
            }
        }
        let sender = Arc::new(Stamps(Fake::default()));
        let (tx, rx) = mpsc::channel(QUEUE_LEN);
        let (named_tx, named_rx) = mpsc::channel(QUEUE_LEN);
        tokio::spawn(run(rx, named_rx, sender.clone(), vec![], quick(1), small(1, Duration::from_millis(50))));
        for to in [[8; 16], [9; 16]] {
            named_tx.send(Job { alert: alert(), to: Some(to) }).await.unwrap();
        }
        // The slot is free after 50 ms, but the thread is still running: the next delivery waits for it.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(sender.0.sent.lock().unwrap().is_empty());
        wait_for("the second alert is sent", || !sender.0.sent.lock().unwrap().is_empty()).await;
        drop(tx);
    }

    #[tokio::test]
    async fn a_refusing_delivery_is_not_tried_again() {
        struct Refuses(Fake);
        impl Sender for Refuses {
            async fn send(&self, to: Hash, alert: &Alert) -> Result<(), String> {
                self.0.send(to, alert).await
            }
            async fn send_with(&self, to: Hash, _alert: &Alert, delivery: &Delivery) -> Result<(), String> {
                self.0.tries.lock().unwrap().push(to);
                delivery.refuse();
                Err("stamp cost too high".into())
            }
        }
        let sender = Refuses(Fake::default());
        assert!(!deliver(&sender, [1; 16], &alert(), &quick(3)).await);
        assert_eq!(sender.0.tries.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_delivery_keeps_what_the_sender_gives_it() {
        let delivery = Delivery::default();
        assert_eq!(delivery.with_kept(|n: &mut u32| std::mem::replace(n, 5)), 0);
        assert_eq!(delivery.with_kept(|n: &mut u32| *n), 5);
        // Another type replaces it instead of panicking.
        assert_eq!(delivery.with_kept(|s: &mut String| s.len()), 0);
    }

    #[test]
    fn a_named_address_is_shown_as_8_digits() {
        assert_eq!(short([0xab; 16]), "abababab");
        assert_eq!(Delivery::listed([0xab; 16]).label().len(), 32);
        assert_eq!(Delivery::named([0xab; 16], 12.0, Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap()).label(), "abababab");
    }
}
