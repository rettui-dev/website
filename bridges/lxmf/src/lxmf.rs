//! The part that talks to Reticulum: an identity, a delivery address announced on the network, and
//! LXMF messages sent to a destination hash, directly over a Link or through a propagation node.
//!
//! This follows what rettui does to send (a Link to the recipient, the message as one packet or as a
//! Resource when it is too big for one, and a propagation node when the recipient cannot be
//! reached); it receives nothing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use lxmf_core::handlers::{compression_support_from_app_data, get_announce_app_data, parse_pn_announce_data, stamp_cost_from_app_data};
use lxmf_core::message_api::{DeliveryMethod, LxMessage, LxMessageDraft, MessageError, SignedLxMessage};
use lxmf_core::propagation_send::{AdvertisedNodePolicy, EncryptionBinding, PreparedNode, PropagationEnvelope};
use rns_runtime::prelude::*;

use crate::alert::Alert;
use crate::config::{Config, EntryPoint, Hash};
use crate::http::unix_now;
use crate::queue::Sender;

const DELIVERY_ASPECT: &str = "lxmf.delivery";
/// A delivery proof or a transfer that takes longer than this has failed.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(120);
/// Path requests: a few tries, each given this long.
const PATH_TRIES: u32 = 3;
const PATH_TRY: Duration = Duration::from_secs(15);
/// The most a stamp may cost to work out, as in rettui.
const MAX_STAMP_COST: f64 = 28.0;
/// How often the address is announced again.
const REANNOUNCE: Duration = Duration::from_secs(3 * 60 * 60);

/// The identity in `path`: read if there is a file, made and saved (private to this user) if not.
pub fn load_or_create_identity(path: &Path) -> Result<Identity, String> {
    if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0) {
                tracing::warn!("identity_file {} can be read by other users; chmod 600 it", path.display());
            }
        }
        return Identity::from_file(path).map_err(|e| format!("identity_file {}: {e}", path.display()));
    }
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("identity_file {}: cannot make its folder: {e}", path.display()))?;
    }
    let identity = Identity::new();
    // Written atomically and readable by this user only.
    identity.to_file(path).map_err(|e| format!("identity_file {}: cannot save it: {e}", path.display()))?;
    tracing::info!("made a new identity in {}", path.display());
    Ok(identity)
}

/// Makes the folder Reticulum keeps its files in (with what it has heard, and its keys for
/// links) readable by this user only, and warns if one that was there already is not.
pub fn make_private_dir(dir: &Path) -> Result<(), String> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(dir).is_ok_and(|m| m.permissions().mode() & 0o077 != 0) {
            tracing::warn!("{} can be read by other users; chmod 700 it", dir.display());
        }
    }
    Ok(())
}

/// Writes a file that only this user can read (on Unix; the mode of one that is there already is
/// set too).
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    #[cfg(unix)]
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    file.write_all(data)
}

/// The Reticulum config for a bridge: no sharing with other programs, no transport, and a TCP
/// client for each entry point. (Entry points are checked words and numbers, so nothing here can
/// start another section.)
pub fn reticulum_config(entry_points: &[EntryPoint]) -> String {
    let mut text =
        String::from("[reticulum]\n  enable_transport = False\n  share_instance = No\n\n[logging]\n  loglevel = 3\n\n[interfaces]\n");
    for (i, EntryPoint { host, port }) in entry_points.iter().enumerate() {
        text.push_str(&format!(
            "  [[Entry point {}]]\n    type = TCPClientInterface\n    enabled = Yes\n    target_host = {host}\n    target_port = {port}\n",
            i + 1
        ));
    }
    text
}

/// A running Reticulum instance with this bridge's address on it.
pub struct Lxmf {
    runtime: ReticulumHandle,
    identity: Identity,
    source: Hash,
    propagation_node: Option<Hash>,
}

impl Lxmf {
    /// Starts Reticulum on the entry points, and announces the address once one is connected.
    /// Reticulum keeps its files in a `reticulum` folder next to the identity file.
    pub async fn start(config: &Config) -> Result<Self, String> {
        let identity = load_or_create_identity(&config.identity_file)?;
        let dir: PathBuf = config.identity_file.parent().unwrap_or(Path::new(".")).join("reticulum");
        make_private_dir(&dir)?;
        write_private(&dir.join("config"), reticulum_config(&config.entry_points).as_bytes())
            .map_err(|e| format!("cannot write the Reticulum config: {e}"))?;

        let mut options = InitOptions::default();
        // An entry point that is down for now is tried again; it does not stop the bridge.
        options.keep_starting_after_interface_failure = true;
        options.start_interfaces_concurrently = true;
        let dir = dir.to_str().ok_or("the identity_file folder is not UTF-8")?;
        let runtime =
            rns_runtime::reticulum::init_with_options(Some(dir), None, ShutdownSignal::new(), Arc::new(AtomicBool::new(true)), options)
                .await
                .map_err(|e| format!("Reticulum failed to start: {e}"))?;
        for (name, why) in runtime.startup_interface_failures() {
            tracing::warn!("entry point {name} did not connect (it is tried again): {why}");
        }

        let delivery_options = DestinationRuntimeOptions {
            proof_strategy: ProofStrategy::ProveAll,
            default_app_data: Some(get_announce_app_data(Some(&config.display_name), None)),
            ..DestinationRuntimeOptions::default()
        };
        let registered = runtime
            .register_destination(identity.clone(), DELIVERY_ASPECT, delivery_options)
            .await
            .map_err(|e| format!("could not register the delivery address: {e}"))?;
        let handle = registered.handle.clone();
        let source = handle.destination_hash();
        tracing::info!("delivery address <{}>", hex::encode(source));
        tokio::spawn(drain(registered));
        tokio::spawn(announce(runtime.clone(), handle, get_announce_app_data(Some(&config.display_name), None)));
        Ok(Self { runtime, identity, source, propagation_node: config.propagation_node })
    }

    /// Stops Reticulum.
    pub async fn shutdown(&self) {
        self.runtime.shutdown_and_wait().await;
    }

    /// The address messages come from.
    pub fn address(&self) -> Hash {
        self.source
    }

    /// Finds a path to `destination`, asking for one a few times.
    async fn find_path(&self, destination: Hash) -> Result<(), String> {
        for _ in 0..PATH_TRIES {
            if self.runtime.await_path(destination, PATH_TRY).await.is_ok() {
                return Ok(());
            }
        }
        Err("no path found: the destination has not been heard (it may be offline)".into())
    }

    /// The key and announce data of a destination, with a path asked for if it is not known.
    async fn recall(&self, destination: Hash) -> Result<RecalledDestination, String> {
        if let Ok(Some(known)) = self.runtime.recall(destination).await {
            return Ok(known);
        }
        self.find_path(destination).await?;
        match self.runtime.recall(destination).await {
            Ok(Some(known)) => Ok(known),
            _ => Err("the destination's key is unknown (no announce heard)".into()),
        }
    }

    fn message(&self, to: Hash, alert: &Alert, app_data: Option<&[u8]>) -> Result<SignedLxMessage, String> {
        let mut draft =
            LxMessageDraft::new(to, self.source, &alert.title, &alert.content, DeliveryMethod::Direct).map_err(|e| e.to_string())?;
        draft.stamp_cost = app_data.and_then(stamp_cost_from_app_data);
        if let Some(cost) = draft.stamp_cost.filter(|cost| *cost > MAX_STAMP_COST) {
            return Err(format!("the recipient asks for a stamp cost of {cost}, more than the bridge will work out ({MAX_STAMP_COST})"));
        }
        let key = self.identity.get_signing_key().ok_or("the identity has no signing key")?;
        draft.sign(&key).map_err(|e| e.to_string())
    }

    /// Direct delivery: a Link to the recipient, and the message over it.
    async fn direct(&self, to: Hash, alert: &Alert) -> Result<(), String> {
        self.find_path(to).await?;
        let recipient = self.recall(to).await?;
        let compress = recipient.app_data.as_deref().is_none_or(compression_support_from_app_data);
        let message = self.message(to, alert, recipient.app_data.as_deref())?;
        let packed = finish(message).await?;
        let options = LinkConnectOptions {
            path_timeout: Duration::from_secs(30),
            client_label: "lxmf-bridge".into(),
            ..LinkConnectOptions::default()
        };
        let LinkSession { handle, mut events, .. } =
            self.runtime.connect_link(to, Identity::new(), options).await.map_err(|e| format!("link failed: {e}"))?;
        let result = if packed.len() <= handle.mdu() {
            match handle.send_packet(packed).await {
                Ok(receipt) => wait_for_proof(&mut events, receipt.packet_hash).await,
                Err(e) => Err(e.to_string()),
            }
        } else {
            send_resource(&handle, packed, compress).await
        };
        handle.close().await;
        result
    }

    /// Store and forward: the message encrypted for the recipient and handed to the propagation node.
    async fn propagate(&self, node: Hash, to: Hash, alert: &Alert) -> Result<(), String> {
        // The recipient may be offline: only its key is needed, not a path.
        let recipient = self.recall(to).await?;
        self.find_path(node).await?;
        let node_info = self.recall(node).await?;
        let stamp_cost = node_info.app_data.as_deref().and_then(parse_pn_announce_data).map_or(0.0, |data| data.stamp_cost);
        if stamp_cost > MAX_STAMP_COST {
            return Err(format!("the propagation node asks for a stamp cost of {stamp_cost}, more than the bridge will work out"));
        }
        let message = self.message(to, alert, recipient.app_data.as_deref())?;
        let (public, ratchet) = (recipient.identity, recipient.ratchet);
        let packed = tokio::task::spawn_blocking(move || {
            let message = stamp(message)?;
            let binding = EncryptionBinding::for_recipient(&public.get_public_key(), ratchet.as_ref());
            let mut envelope = PropagationEnvelope::new(message, binding, stamp_cost, |plaintext| {
                public.encrypt(plaintext, ratchet.as_ref()).map_err(|e| MessageError::PackFailed(e.to_string()))
            })?;
            let policy = AdvertisedNodePolicy { stamp_cost, transfer_limit_kb: f64::MAX, recorded_at: 0. };
            envelope.pack_for(PreparedNode { node, policy }, unix_now() as f64)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
        let options = LinkConnectOptions {
            path_timeout: Duration::from_secs(30),
            client_label: "lxmf-bridge.propagation".into(),
            identify: true,
            ..LinkConnectOptions::default()
        };
        let LinkSession { handle, .. } = self
            .runtime
            .connect_link(node, self.identity.clone(), options)
            .await
            .map_err(|e| format!("link to the propagation node failed: {e}"))?;
        let result = send_resource(&handle, packed, true).await;
        handle.close().await;
        result
    }
}

impl Sender for Lxmf {
    async fn send(&self, to: Hash, alert: &Alert) -> Result<(), String> {
        let direct = self.direct(to, alert).await;
        match (direct, self.propagation_node) {
            (Ok(()), _) => Ok(()),
            (Err(e), Some(node)) => {
                tracing::info!("direct delivery to {} failed ({e}); trying the propagation node", hex::encode(to));
                self.propagate(node, to, alert).await.map_err(|pe| format!("direct: {e}; propagation: {pe}"))
            }
            (Err(e), None) => Err(e),
        }
    }
}

/// Stamps (if the recipient asks for one) and finishes a signed message.
fn stamp(message: SignedLxMessage) -> Result<LxMessage, MessageError> {
    let stamp = message.generate_recipient_stamp()?;
    message.finalize(stamp)
}

/// The message's bytes, ready to send. A stamp can take a while, so this runs off the async threads.
async fn finish(message: SignedLxMessage) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking(move || stamp(message).map(|message| message.wire_bytes().to_vec()))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

async fn send_resource(handle: &LinkSessionHandle, data: Vec<u8>, compress: bool) -> Result<(), String> {
    let options = ResourceOptions { auto_compress: compress, metadata: None };
    let transfer = handle.send_resource_bytes(data, options).await.map_err(|e| e.to_string())?;
    match tokio::time::timeout(DELIVERY_TIMEOUT, transfer.concluded()).await {
        Ok(result) => result.map(|_| ()).map_err(|e| format!("transfer failed: {e}")),
        Err(_) => Err("timed out waiting for the transfer".into()),
    }
}

async fn wait_for_proof(events: &mut tokio::sync::mpsc::Receiver<LinkSessionEvent>, packet_hash: [u8; 32]) -> Result<(), String> {
    let wait = async {
        while let Some(event) = events.recv().await {
            match event {
                LinkSessionEvent::PacketDelivered { packet_hash: h } if h == packet_hash => return Ok(()),
                LinkSessionEvent::Closed { reason } => return Err(format!("the link closed before delivery ({reason:?})")),
                _ => {}
            }
        }
        Err("the link closed before delivery".to_string())
    };
    tokio::time::timeout(DELIVERY_TIMEOUT, wait).await.unwrap_or_else(|_| Err("timed out waiting for the delivery proof".to_string()))
}

/// Announces the address once an entry point is connected, and again every few hours. Recipients
/// need the announce to know who a message is from.
async fn announce(runtime: ReticulumHandle, handle: DestinationHandle, app_data: Vec<u8>) {
    loop {
        // Not before an interface is up, or the announce goes nowhere.
        while !runtime.interface_stats().await.is_ok_and(|stats| stats.interfaces.iter().any(|i| i.online)) {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match handle
            .announce(DestinationAnnounceOptions { app_data: Some(app_data.clone()), ..DestinationAnnounceOptions::default() })
            .await
        {
            Ok(()) => tracing::info!("announced the delivery address"),
            Err(e) => tracing::warn!("announce failed: {e}"),
        }
        tokio::time::sleep(REANNOUNCE).await;
    }
}

/// Reads and drops what arrives at the address, so nothing piles up: the bridge only sends.
async fn drain(mut registered: RegisteredDestination) {
    let events = &mut registered.events;
    loop {
        tokio::select! {
            packet = events.packets.recv() => if packet.is_none() { return },
            packet = events.link_packets.recv() => if packet.is_none() { return },
            established = events.links_established.recv() => if established.is_none() { return },
            identified = events.links_identified.recv() => if identified.is_none() { return },
            proof = events.link_packet_proofs.recv() => if proof.is_none() { return },
            done = events.resource_completions.recv() => if done.is_none() { return },
            proof = events.resource_proofs.recv() => if proof.is_none() { return },
            event = events.resource_events.recv() => if event.is_none() { return },
            message = events.channel_messages.recv() => if message.is_none() { return },
            closed = events.links_closed.recv() => if closed.is_none() { return },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reticulum_config_has_one_tcp_client_for_each_entry_point() {
        let text = reticulum_config(&[EntryPoint { host: "a.example".into(), port: 4242 }, EntryPoint { host: "::1".into(), port: 7 }]);
        assert_eq!(text.matches("TCPClientInterface").count(), 2);
        assert!(text.contains("target_host = a.example\n    target_port = 4242\n"));
        assert!(text.contains("target_host = ::1\n    target_port = 7\n"));
        assert!(text.contains("share_instance = No") && text.contains("enable_transport = False"));
        // And rsReticulum reads it.
        assert!(rns_runtime::config::Config::parse(&text).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn reticulums_folder_and_config_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("lxmf-bridge-private-{}", std::process::id()));
        let folder = dir.join("reticulum");
        make_private_dir(&folder).unwrap();
        assert_eq!(std::fs::metadata(&folder).unwrap().permissions().mode() & 0o777, 0o700);
        let file = folder.join("config");
        std::fs::write(&file, "old").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&file, b"new").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        // A folder that is there already is kept as it is (and warned about), not an error.
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).unwrap();
        make_private_dir(&folder).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_new_identity_is_private_and_is_read_back_the_same() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("lxmf-bridge-identity-{}", std::process::id()));
        let file = dir.join("deeper").join("identity");
        let made = load_or_create_identity(&file).unwrap();
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        let again = load_or_create_identity(&file).unwrap();
        assert_eq!(made.hash, again.hash);
        std::fs::write(&file, b"not a key").unwrap();
        assert!(load_or_create_identity(&file).is_err());
    }
}
