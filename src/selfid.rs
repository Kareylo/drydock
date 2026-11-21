//! Detect the ID of the container Drydock runs in, so it never updates itself.

use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

static MOUNT_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"containers/([0-9a-f]{64})/").unwrap());

/// How Drydock recognises its own container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfId {
    /// Full 64-char ID.
    Full(String),
    /// Short ID prefix (default container hostname).
    Prefix(String),
}

impl SelfId {
    pub fn matches(&self, container_id: &str) -> bool {
        match self {
            SelfId::Full(id) => container_id == id,
            SelfId::Prefix(p) => container_id.starts_with(p.as_str()),
        }
    }

    pub fn short(&self) -> &str {
        let s = match self {
            SelfId::Full(id) | SelfId::Prefix(id) => id,
        };
        &s[..s.len().min(12)]
    }
}

/// Docker (`/var/lib/docker/containers/<id>/hostname`) and Podman
/// (`…/overlay-containers/<id>/userdata/hostname`) bind-mount per-container
/// files: the most frequent ID in mountinfo is ours.
pub fn from_mountinfo(mountinfo: &str) -> Option<String> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for c in MOUNT_ID_RE.captures_iter(mountinfo) {
        *counts.entry(c.get(1).unwrap().as_str()).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(id, _)| id.to_string())
}

/// Default hostname of a container: the 12-char short ID.
pub fn from_hostname(hostname: &str) -> Option<String> {
    let h = hostname.trim();
    (h.len() == 12 && h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        .then(|| h.to_string())
}

pub fn detect() -> Option<SelfId> {
    if let Ok(id) = std::env::var("DRYDOCK_CONTAINER_ID") {
        let id = id.trim().to_lowercase();
        if id.len() >= 12 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(if id.len() == 64 { SelfId::Full(id) } else { SelfId::Prefix(id) });
        }
    }
    if let Some(id) = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|m| from_mountinfo(&m))
    {
        return Some(SelfId::Full(id));
    }
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .and_then(|h| from_hostname(&h))
        .map(SelfId::Prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "b97bac321ad1f644527958ffbf1e89227439452f12f2019921c2d41a0ed11506";

    #[test]
    fn docker_mountinfo() {
        let m = format!(
            "100 90 0:50 / / rw - overlay overlay rw\n\
             110 100 8:1 /var/lib/docker/containers/{ID}/resolv.conf /etc/resolv.conf rw - ext4 /dev/sda1 rw\n\
             111 100 8:1 /var/lib/docker/containers/{ID}/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n"
        );
        assert_eq!(from_mountinfo(&m).as_deref(), Some(ID));
    }

    #[test]
    fn podman_mountinfo() {
        let m = format!(
            "120 100 0:40 /containers/storage/overlay-containers/{ID}/userdata/hostname /etc/hostname rw - tmpfs tmpfs rw\n"
        );
        assert_eq!(from_mountinfo(&m).as_deref(), Some(ID));
        assert_eq!(from_mountinfo("1 0 0:1 / / rw - overlay overlay rw\n"), None);
    }

    #[test]
    fn hostname_and_matching() {
        assert_eq!(from_hostname("b97bac321ad1\n").as_deref(), Some("b97bac321ad1"));
        assert_eq!(from_hostname("drydock"), None);
        assert!(SelfId::Prefix("b97bac321ad1".into()).matches(ID));
        assert!(SelfId::Full(ID.into()).matches(ID));
        assert!(!SelfId::Full(ID.into()).matches("b97bac321ad1"));
    }
}
