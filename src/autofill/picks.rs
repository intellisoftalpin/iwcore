//! Which login the user picked on which host, so the next fill there offers
//! it first (see [`super::suggest`]).
//!
//! The provider keeps this small file itself, next to the index, and seals it
//! under the **index key**: it can only be read where the index can, and a
//! key rotation simply starts it afresh. It never reaches the vault and holds
//! no secret, but it is still a browsing record (host to account), so the body
//! is sealed and padded like the index.
//!
//! # Layout
//!
//! ```text
//! "IWPK"     magic
//! u8         format version (1)
//! sealed(index_key, padded_json, aad = magic + version + database id)
//! padded_json = u32 LE json length + {"picks":[{"host","item_id","at"}]} + zero padding
//! ```
//!
//! The vault's database id is bound in as associated data, so a file left
//! over from another vault never applies. Anything unreadable opens as an
//! empty set: losing this costs one extra tap, never data.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::crypto::{self, KEY_LEN};
use super::domain;
use crate::error::{Result, WalletError};

/// Magic bytes at the start of a picks file.
pub const MAGIC: &[u8; 4] = b"IWPK";
/// Current picks format version.
pub const FORMAT_VERSION: u8 = 1;
/// Hosts remembered at most. The oldest pick is dropped beyond this.
pub const MAX_PICKS: usize = 256;
/// The body is padded up to a multiple of this before sealing.
pub const PAD_BLOCK: usize = 1024;
/// Longest host or item id stored. Longer ones are refused, so a hostile
/// caller cannot grow the file without bound.
const MAX_FIELD_LEN: usize = 255;

/// One remembered choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pick {
    /// Normalized host.
    pub host: String,
    pub item_id: String,
    /// Unix seconds of the pick.
    pub at: i64,
}

/// The remembered choices, at most one per host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Picks {
    picks: Vec<Pick>,
}

impl Picks {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a sealed picks file. Anything that does not open cleanly under
    /// this key and database id (missing, foreign, tampered, truncated, an
    /// unknown version) is an empty set, never an error.
    pub fn open(bytes: &[u8], index_key: &[u8; KEY_LEN], database_id: &str) -> Self {
        Self::try_open(bytes, index_key, database_id).unwrap_or_default()
    }

    fn try_open(bytes: &[u8], index_key: &[u8; KEY_LEN], database_id: &str) -> Option<Self> {
        let (head, sealed) = bytes.split_at_checked(MAGIC.len().checked_add(1)?)?;
        if head != aad_prefix().as_slice() {
            return None;
        }
        let padded = Zeroizing::new(crypto::open(index_key, sealed, &aad(database_id)).ok()?);
        let (len, rest) = padded.split_first_chunk::<4>()?;
        let json = rest.get(..usize::try_from(u32::from_le_bytes(*len)).ok()?)?;
        let mut picks: Picks = serde_json::from_slice(json).ok()?;
        // Hold an opened file to the same rules a fresh one is written under.
        picks.picks.retain(|p| valid(&p.host, &p.item_id));
        let mut seen = std::collections::HashSet::new();
        picks.picks.retain(|p| seen.insert(p.host.clone()));
        picks.trim();
        Some(picks)
    }

    /// Seal for writing, bound to `database_id`.
    pub fn seal(&self, index_key: &[u8; KEY_LEN], database_id: &str) -> Result<Vec<u8>> {
        let json = Zeroizing::new(
            serde_json::to_vec(self).map_err(|e| WalletError::EncryptionError(format!("picks encode failed: {e}")))?,
        );
        let len = u32::try_from(json.len()).map_err(|_| WalletError::EncryptionError("picks too large".into()))?;
        let body_len = json.len().checked_add(4).ok_or_else(|| WalletError::EncryptionError("picks too large".into()))?;
        let padded_len = body_len
            .div_ceil(PAD_BLOCK)
            .max(1)
            .checked_mul(PAD_BLOCK)
            .ok_or_else(|| WalletError::EncryptionError("picks too large".into()))?;
        let mut padded = Zeroizing::new(Vec::with_capacity(padded_len));
        padded.extend_from_slice(&len.to_le_bytes());
        padded.extend_from_slice(&json);
        padded.resize(padded_len, 0);
        let sealed = crypto::seal(index_key, &padded, &aad(database_id))?;
        let mut out = aad_prefix();
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// The item picked last on `host` (a URL or host; normalized here).
    pub fn get(&self, host: &str) -> Option<&str> {
        let host = domain::normalize_host(host)?;
        self.picks.iter().find(|p| p.host == host).map(|p| p.item_id.as_str())
    }

    /// Remember that `item_id` was picked on `host` at `at`. Replaces an
    /// earlier pick for the host and drops the oldest pick beyond
    /// [`MAX_PICKS`]. Returns false, changing nothing, when the host does not
    /// normalize or either value is empty or too long.
    pub fn record(&mut self, host: &str, item_id: &str, at: i64) -> bool {
        let Some(host) = domain::normalize_host(host) else { return false };
        if !valid(&host, item_id) {
            return false;
        }
        self.picks.retain(|p| p.host != host);
        self.picks.push(Pick { host, item_id: item_id.to_string(), at });
        self.trim();
        true
    }

    /// Keep only picks whose item is in `live`. Called after an index rebuild,
    /// so a deleted entry's picks do not linger.
    pub fn retain_items(&mut self, live: &[&str]) {
        self.picks.retain(|p| live.contains(&p.item_id.as_str()));
    }

    pub fn len(&self) -> usize {
        self.picks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.picks.is_empty()
    }

    /// The picks, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &Pick> {
        self.picks.iter()
    }

    /// Oldest first (stable, so equal times keep their order), at most
    /// [`MAX_PICKS`], the oldest dropped.
    fn trim(&mut self) {
        self.picks.sort_by_key(|p| p.at);
        let excess = self.picks.len().saturating_sub(MAX_PICKS);
        self.picks.drain(..excess);
    }
}

fn valid(host: &str, item_id: &str) -> bool {
    !host.is_empty() && !item_id.is_empty() && host.len() <= MAX_FIELD_LEN && item_id.len() <= MAX_FIELD_LEN
}

fn aad_prefix() -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.push(FORMAT_VERSION);
    v
}

fn aad(database_id: &str) -> Vec<u8> {
    let mut v = aad_prefix();
    v.extend_from_slice(database_id.as_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7; KEY_LEN];

    #[test]
    fn round_trips_and_normalizes_hosts() {
        let mut p = Picks::new();
        assert!(p.record("https://www.Auth.OxiSoft.net/login", "item-1", 10));
        let opened = Picks::open(&p.seal(&KEY, "db").unwrap(), &KEY, "db");
        assert_eq!(opened, p);
        assert_eq!(opened.get("auth.oxisoft.net"), Some("item-1"));
        assert_eq!(opened.get("https://auth.oxisoft.net:443/x"), Some("item-1"));
        assert_eq!(opened.get("chat.oxisoft.net"), None);
        assert_eq!(opened.get(""), None);
    }

    #[test]
    fn a_later_pick_replaces_the_earlier_one_for_the_host() {
        let mut p = Picks::new();
        p.record("example.com", "a", 1);
        p.record("example.com", "b", 2);
        assert_eq!(p.len(), 1);
        assert_eq!(p.get("example.com"), Some("b"));
    }

    #[test]
    fn bad_input_is_refused_and_changes_nothing() {
        let mut p = Picks::new();
        assert!(!p.record("", "a", 1));
        assert!(!p.record("javascript:alert(1)", "a", 1));
        assert!(!p.record("example.com", "", 1));
        assert!(!p.record("example.com", &"x".repeat(MAX_FIELD_LEN + 1), 1));
        assert!(p.record("example.com", &"x".repeat(MAX_FIELD_LEN), 1));
        assert!(!p.record(&format!("{}.com", "a".repeat(MAX_FIELD_LEN)), "a", 1));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn the_oldest_pick_is_dropped_beyond_the_cap() {
        let mut p = Picks::new();
        for i in 0..=MAX_PICKS {
            let at = i64::try_from(i).unwrap();
            assert!(p.record(&format!("h{i}.example.com"), "x", at));
        }
        assert_eq!(p.len(), MAX_PICKS);
        assert_eq!(p.get("h0.example.com"), None);
        assert_eq!(p.get(&format!("h{MAX_PICKS}.example.com")), Some("x"));
        assert_eq!(p.iter().next().map(|x| x.at), Some(1));
    }

    #[test]
    fn a_foreign_vault_wrong_key_tampering_or_junk_opens_empty() {
        let mut p = Picks::new();
        p.record("example.com", "a", 1);
        let sealed = p.seal(&KEY, "db").unwrap();
        assert!(Picks::open(&sealed, &KEY, "other-db").is_empty());
        assert!(Picks::open(&sealed, &[8; KEY_LEN], "db").is_empty());
        for i in 0..sealed.len() {
            let mut t = sealed.clone();
            t[i] ^= 1;
            assert!(Picks::open(&t, &KEY, "db").is_empty(), "byte {i}");
        }
        for len in 0..sealed.len() {
            assert!(Picks::open(&sealed[..len], &KEY, "db").is_empty(), "len {len}");
        }
        assert!(Picks::open(b"", &KEY, "db").is_empty());
    }

    #[test]
    fn size_is_padded_so_it_does_not_leak_the_count() {
        let one = {
            let mut p = Picks::new();
            p.record("example.com", "a", 1);
            p.seal(&KEY, "db").unwrap().len()
        };
        let five = {
            let mut p = Picks::new();
            for i in 0..5 {
                p.record(&format!("h{i}.example.com"), "a", i);
            }
            p.seal(&KEY, "db").unwrap().len()
        };
        assert_eq!(one, five);
        assert_eq!(Picks::new().seal(&KEY, "db").unwrap().len(), one);
        let header = MAGIC.len() + 1 + crypto::NONCE_LEN + crypto::TAG_LEN;
        assert_eq!((one - header) % PAD_BLOCK, 0);
    }

    fn seal_raw(json: &[u8]) -> Vec<u8> {
        let mut padded = u32::try_from(json.len()).unwrap().to_le_bytes().to_vec();
        padded.extend_from_slice(json);
        let mut out = aad_prefix();
        out.extend_from_slice(&crypto::seal(&KEY, &padded, &aad("db")).unwrap());
        out
    }

    #[test]
    fn an_opened_file_is_held_to_the_write_rules() {
        let long = "x".repeat(MAX_FIELD_LEN + 1);
        let json = format!(
            r#"{{"picks":[{{"host":"a.com","item_id":"1","at":5}},{{"host":"a.com","item_id":"2","at":6}},{{"host":"","item_id":"3","at":7}},{{"host":"b.com","item_id":"{long}","at":8}}]}}"#
        );
        let p = Picks::open(&seal_raw(json.as_bytes()), &KEY, "db");
        assert_eq!(p.len(), 1);
        assert_eq!(p.get("a.com"), Some("1"));
    }

    #[test]
    fn a_length_prefix_past_the_body_opens_empty() {
        let mut padded = 1000u32.to_le_bytes().to_vec();
        padded.extend_from_slice(b"{}");
        let mut out = aad_prefix();
        out.extend_from_slice(&crypto::seal(&KEY, &padded, &aad("db")).unwrap());
        assert!(Picks::open(&out, &KEY, "db").is_empty());
        assert!(Picks::open(&seal_raw(b"not json"), &KEY, "db").is_empty());
        assert!(Picks::open(&seal_raw(br#"{"picks":[]}"#), &KEY, "db").is_empty());
    }

    #[test]
    fn retain_items_drops_picks_of_deleted_entries() {
        let mut p = Picks::new();
        p.record("a.com", "1", 1);
        p.record("b.com", "2", 2);
        p.retain_items(&["2"]);
        assert_eq!((p.get("a.com"), p.get("b.com")), (None, Some("2")));
    }

    #[test]
    fn an_unknown_version_opens_empty() {
        let mut p = Picks::new();
        p.record("a.com", "1", 1);
        let mut sealed = p.seal(&KEY, "db").unwrap();
        sealed[MAGIC.len()] = FORMAT_VERSION + 1;
        assert!(Picks::open(&sealed, &KEY, "db").is_empty());
    }
}
