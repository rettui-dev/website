//! The bridge's settings: `bridge.toml`, and the secret file it points to.
//!
//! Everything is checked at start. An error names the setting and what is wrong with it, and never
//! repeats the secret.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// An LXMF destination hash.
pub type Hash = [u8; 16];

pub const MAX_RECIPIENTS: usize = 16;
pub const MAX_ENTRY_POINTS: usize = 8;
pub const MAX_ALLOW_FROM: usize = 16;
/// The most a config file may hold. It is read whole, so it is capped first.
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// The most a secret file may hold. The website's secrets are 16 to 256 characters.
const MAX_SECRET_BYTES: u64 = 1024;
const DEFAULT_LISTEN: &str = "127.0.0.1:8742";
const DEFAULT_ENTRY_POINT: &str = "rns.rettui.dev:4242";
const DEFAULT_NAME: &str = "rettui alerts";
const DEFAULT_MAX_AGE: u64 = 300;
const DEFAULT_MAX_BODY: usize = 16 * 1024;

/// A configuration problem, in words fit to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn fail<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(message.into()))
}

/// A Reticulum TCP server to connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPoint {
    pub host: String,
    pub port: u16,
}

/// The file as written: what is left out gets its default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    listen: Option<String>,
    secret_file: String,
    identity_file: String,
    display_name: Option<String>,
    recipients: Vec<String>,
    entry_points: Option<Vec<String>>,
    propagation_node: Option<String>,
    max_age_seconds: Option<u64>,
    max_body_bytes: Option<usize>,
    allow_from: Option<Vec<String>>,
}

/// The checked settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    pub secret_file: PathBuf,
    pub identity_file: PathBuf,
    pub display_name: String,
    pub recipients: Vec<Hash>,
    pub entry_points: Vec<EntryPoint>,
    pub propagation_node: Option<Hash>,
    pub max_age_seconds: u64,
    pub max_body_bytes: usize,
    /// Addresses allowed to connect; empty means any.
    pub allow_from: Vec<IpAddr>,
}

impl Config {
    /// Reads and checks the file. Relative paths in it are relative to its folder.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = read_capped(path, MAX_CONFIG_BYTES).map_err(|e| ConfigError(format!("cannot read {}: {e}", path.display())))?;
        let text = String::from_utf8(text).map_err(|_| ConfigError(format!("{} is not UTF-8 text", path.display())))?;
        Self::parse(&text, path.parent().unwrap_or(Path::new(".")))
    }

    /// Checks the text of a config file; `base` is what relative paths in it are relative to.
    pub fn parse(text: &str, base: &Path) -> Result<Self, ConfigError> {
        let raw: Raw = toml::from_str(text).map_err(|e| ConfigError(format!("bridge.toml: {}", e.message())))?;
        let listen = raw.listen.as_deref().unwrap_or(DEFAULT_LISTEN);
        let listen = listen.parse().or_else(|_| fail(format!("listen: {listen:?} is not an address like 127.0.0.1:8742")))?;
        let display_name = raw.display_name.unwrap_or_else(|| DEFAULT_NAME.to_string());
        if display_name.is_empty() || display_name.chars().count() > 64 || display_name.chars().any(char::is_control) {
            return fail("display_name: 1 to 64 characters, no control characters");
        }
        if raw.recipients.is_empty() || raw.recipients.len() > MAX_RECIPIENTS {
            return fail(format!("recipients: give 1 to {MAX_RECIPIENTS} destination hashes"));
        }
        let mut recipients: Vec<Hash> = Vec::new();
        for (i, text) in raw.recipients.iter().enumerate() {
            let Some(hash) = parse_hash(text) else { return fail(format!("recipients[{i}]: not a 32 digit hex destination hash")) };
            if recipients.contains(&hash) {
                return fail(format!("recipients[{i}]: listed twice"));
            }
            recipients.push(hash);
        }
        let points = raw.entry_points.unwrap_or_else(|| vec![DEFAULT_ENTRY_POINT.to_string()]);
        if points.is_empty() || points.len() > MAX_ENTRY_POINTS {
            return fail(format!("entry_points: give 1 to {MAX_ENTRY_POINTS} addresses like host:port"));
        }
        let entry_points = points
            .iter()
            .enumerate()
            .map(|(i, text)| parse_entry_point(text).ok_or_else(|| ConfigError(format!("entry_points[{i}]: not a host:port"))))
            .collect::<Result<Vec<_>, _>>()?;
        let propagation_node = match raw.propagation_node.as_deref() {
            None => None,
            Some(text) => {
                Some(parse_hash(text).ok_or_else(|| ConfigError("propagation_node: not a 32 digit hex destination hash".into()))?)
            }
        };
        let max_age_seconds = raw.max_age_seconds.unwrap_or(DEFAULT_MAX_AGE);
        if !(1..=3600).contains(&max_age_seconds) {
            return fail("max_age_seconds: 1 to 3600");
        }
        let max_body_bytes = raw.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY);
        if !(256..=1024 * 1024).contains(&max_body_bytes) {
            return fail("max_body_bytes: 256 to 1048576");
        }
        let allow = raw.allow_from.unwrap_or_default();
        if allow.len() > MAX_ALLOW_FROM {
            return fail(format!("allow_from: at most {MAX_ALLOW_FROM} addresses"));
        }
        let allow_from = allow
            .iter()
            .enumerate()
            .map(|(i, text)| {
                text.parse::<IpAddr>().map(|ip| ip.to_canonical()).or_else(|_| fail(format!("allow_from[{i}]: not an IP address")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if raw.secret_file.is_empty() || raw.identity_file.is_empty() {
            return fail("secret_file and identity_file must be paths");
        }
        Ok(Self {
            listen,
            secret_file: base.join(raw.secret_file),
            identity_file: base.join(raw.identity_file),
            display_name,
            recipients,
            entry_points,
            propagation_node,
            max_age_seconds,
            max_body_bytes,
            allow_from,
        })
    }
}

/// A destination hash as 32 hex digits (Sideband and rettui show it between angle brackets).
pub fn parse_hash(text: &str) -> Option<Hash> {
    let text = text.trim().trim_start_matches('<').trim_end_matches('>');
    hex::decode(text).ok()?.try_into().ok()
}

/// `host:port`, where host is a name, an IPv4 address or an IPv6 address in brackets. Nothing else
/// is let through, as the name is written into a Reticulum config file.
pub fn parse_entry_point(text: &str) -> Option<EntryPoint> {
    let (host, port) = text.rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|port| *port != 0)?;
    let host = match host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        Some(inner) => inner.parse::<Ipv6Addr>().ok()?.to_string(),
        None => {
            let label = |part: &str| {
                !part.is_empty()
                    && part.len() <= 63
                    && !part.starts_with('-')
                    && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            };
            if host.len() > 253 || !host.split('.').all(label) {
                return None;
            }
            host.to_string()
        }
    };
    Some(EntryPoint { host, port })
}

/// Reads at most `max` bytes of a file; a longer one is an error, not a truncation.
pub fn read_capped(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::other(format!("larger than {max} bytes")));
    }
    Ok(bytes)
}

/// The shared secret: the file's text without its final line break. Like the website's, it is 16 to
/// 256 printable characters without spaces. A file other users can read gets a warning from `warn`.
pub fn read_secret(path: &Path, warn: impl FnOnce(String)) -> Result<Vec<u8>, ConfigError> {
    let mut bytes = read_capped(path, MAX_SECRET_BYTES).map_err(|e| ConfigError(format!("secret_file {}: {e}", path.display())))?;
    while bytes.last().is_some_and(|b| matches!(b, b'\n' | b'\r')) {
        bytes.pop();
    }
    if !(16..=256).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_graphic) {
        return fail(format!("secret_file {}: the secret must be 16 to 256 printable characters without spaces", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path)
            && meta.permissions().mode() & 0o077 != 0
        {
            warn(format!("secret_file {} can be read by other users; chmod 600 it", path.display()));
        }
    }
    #[cfg(not(unix))]
    let _ = warn;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef";

    fn parse(extra: &str) -> Result<Config, ConfigError> {
        Config::parse(&format!("secret_file = \"s\"\nidentity_file = \"/data/identity\"\n{extra}"), Path::new("/etc/bridge"))
    }

    fn with_recipient(extra: &str) -> Result<Config, ConfigError> {
        parse(&format!("recipients = [\"{HASH}\"]\n{extra}"))
    }

    #[test]
    fn defaults_apply_and_relative_paths_follow_the_file() {
        let config = with_recipient("").unwrap();
        assert_eq!(config.listen, "127.0.0.1:8742".parse().unwrap());
        assert_eq!(config.secret_file, Path::new("/etc/bridge/s"));
        assert_eq!(config.identity_file, Path::new("/data/identity"));
        assert_eq!(config.entry_points, [EntryPoint { host: "rns.rettui.dev".into(), port: 4242 }]);
        assert_eq!((config.max_age_seconds, config.max_body_bytes), (300, 16384));
        assert_eq!(config.recipients, [parse_hash(HASH).unwrap()]);
        assert_eq!(config.propagation_node, None);
        assert!(config.allow_from.is_empty());
    }

    #[test]
    fn allow_from_takes_exact_addresses_and_at_most_sixteen() {
        let config = with_recipient("allow_from = [\"172.28.0.5\", \"::ffff:10.0.0.1\", \"fd00::1\"]").unwrap();
        // An IPv4 address written in IPv6 form is the IPv4 address.
        assert_eq!(config.allow_from, ["172.28.0.5".parse::<IpAddr>().unwrap(), "10.0.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]);
        let many = (0..17).map(|i| format!("\"10.0.0.{i}\"")).collect::<Vec<_>>().join(", ");
        assert!(with_recipient(&format!("allow_from = [{many}]")).is_err());
    }

    #[test]
    fn a_full_file_is_read() {
        let config = with_recipient(&format!(
            "listen = \"0.0.0.0:9000\"\ndisplay_name = \"Ops\"\nentry_points = [\"a.example:1\", \"[::1]:2\"]\npropagation_node = \"<{HASH}>\"\nmax_age_seconds = 60\nmax_body_bytes = 1024"
        ))
        .unwrap();
        assert_eq!(config.entry_points[1], EntryPoint { host: "::1".into(), port: 2 });
        assert!(config.propagation_node.is_some());
        assert_eq!(
            (config.listen.port(), config.display_name.as_str(), config.max_age_seconds, config.max_body_bytes),
            (9000, "Ops", 60, 1024)
        );
    }

    #[test]
    fn bad_settings_are_refused_by_name() {
        let cases = [
            ("", "recipients"),
            ("recipients = []", "recipients"),
            ("recipients = [\"abc\"]", "recipients[0]"),
            ("recipients = [\"zz23456789abcdef0123456789abcdef\"]", "recipients[0]"),
            (&format!("recipients = [\"{HASH}\", \"{HASH}\"]"), "listed twice"),
            (&format!("recipients = [\"{HASH}\"]\nlisten = \"nowhere\""), "listen"),
            (&format!("recipients = [\"{HASH}\"]\nentry_points = []"), "entry_points"),
            (&format!("recipients = [\"{HASH}\"]\nentry_points = [\"host\"]"), "entry_points[0]"),
            (&format!("recipients = [\"{HASH}\"]\nentry_points = [\"a b:1\"]"), "entry_points[0]"),
            (&format!("recipients = [\"{HASH}\"]\npropagation_node = \"12\""), "propagation_node"),
            (&format!("recipients = [\"{HASH}\"]\nmax_age_seconds = 0"), "max_age_seconds"),
            (&format!("recipients = [\"{HASH}\"]\nmax_age_seconds = 99999"), "max_age_seconds"),
            (&format!("recipients = [\"{HASH}\"]\nmax_body_bytes = 10"), "max_body_bytes"),
            (&format!("recipients = [\"{HASH}\"]\ndisplay_name = \"\""), "display_name"),
            (&format!("recipients = [\"{HASH}\"]\ncolour = 1"), "colour"),
            (&format!("recipients = [\"{HASH}\"]\nallow_from = [\"10.0.0.0/8\"]"), "allow_from[0]"),
            (&format!("recipients = [\"{HASH}\"]\nallow_from = [\"nope\"]"), "allow_from[0]"),
        ];
        for (extra, wanted) in cases {
            let error = parse(extra).expect_err(extra).to_string();
            assert!(error.contains(wanted), "{extra:?} gave {error:?}");
        }
    }

    #[test]
    fn at_most_sixteen_recipients() {
        let hashes = |n: usize| (0..n).map(|i| format!("\"{i:032x}\"")).collect::<Vec<_>>().join(", ");
        assert_eq!(parse(&format!("recipients = [{}]", hashes(16))).unwrap().recipients.len(), 16);
        assert!(parse(&format!("recipients = [{}]", hashes(17))).is_err());
    }

    #[test]
    fn entry_points_cannot_carry_config_syntax() {
        assert!(parse_entry_point("host.example:4242").is_some());
        assert!(parse_entry_point("10.0.0.1:4242").is_some());
        for bad in ["", ":4242", "host:0", "host:70000", "host:x", "a\nb:1", "a]\n[[x:1", "-a:1", "a..b:1", "[::1:1", "[nope]:1", "a_b:1"] {
            assert_eq!(parse_entry_point(bad), None, "{bad:?}");
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lxmf-bridge-config-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_secret_is_read_without_its_line_break() {
        let dir = temp("secret");
        let file = dir.join("secret");
        std::fs::write(&file, "0123456789abcdefXYZ\n").unwrap();
        assert_eq!(read_secret(&file, |_| {}).unwrap(), b"0123456789abcdefXYZ");
    }

    #[test]
    fn a_bad_secret_is_refused_without_repeating_it() {
        let dir = temp("badsecret");
        let file = dir.join("secret");
        for (bytes, ok) in [
            (&b"short"[..], false),
            (b"has a space in it 1234", false),
            (b"0123456789abcdef\x00", false),
            (&[b'a'; 256][..], true),
            (&[b'a'; 257][..], false),
            (&[b'a'; 5000][..], false),
            (b"", false),
        ] {
            std::fs::write(&file, bytes).unwrap();
            let result = read_secret(&file, |_| {});
            assert_eq!(result.is_ok(), ok, "{} bytes", bytes.len());
            if let Err(e) = result {
                assert!(!e.to_string().contains("has a space") && !e.to_string().contains("short"), "{e}");
            }
        }
        assert!(read_secret(&dir.join("missing"), |_| {}).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_secret_others_can_read_gets_a_warning() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp("perm");
        let file = dir.join("secret");
        std::fs::write(&file, "0123456789abcdefXYZ").unwrap();
        for (mode, warned) in [(0o600, false), (0o640, true), (0o644, true)] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            let mut warning = None;
            read_secret(&file, |w| warning = Some(w)).unwrap();
            assert_eq!(warning.is_some(), warned, "{mode:o}");
            assert!(warning.is_none_or(|w| !w.contains("0123456789abcdefXYZ")));
        }
    }

    #[test]
    fn load_reads_a_file_and_caps_its_size() {
        let dir = temp("load");
        let file = dir.join("bridge.toml");
        std::fs::write(&file, format!("secret_file = \"s\"\nidentity_file = \"i\"\nrecipients = [\"{HASH}\"]\n")).unwrap();
        assert_eq!(Config::load(&file).unwrap().secret_file, dir.join("s"));
        std::fs::write(&file, vec![b'#'; 70_000]).unwrap();
        assert!(Config::load(&file).is_err());
        assert!(Config::load(&dir.join("missing.toml")).is_err());
    }
}
