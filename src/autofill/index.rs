//! The credential index: a sealed snapshot of the vault's login entries.
//!
//! Built by the app while the vault is unlocked, read by the autofill provider
//! after a biometric check. The provider never opens the vault itself.
//!
//! # Layout
//!
//! ```text
//! header (plaintext, authenticated as AAD, never secret):
//!   "IWAF"            magic
//!   u8                format version
//!   u64 LE            generation counter
//!   i64 LE            build timestamp, unix seconds
//!   u8 + bytes        vault database id
//! body:
//!   sealed(index_key, padded_json, aad = header)
//! ```
//!
//! The body is sealed as **one** blob rather than per record, so the file
//! discloses nothing about record boundaries, and it is padded to a 4 KiB
//! boundary before sealing, so its size does not disclose the entry count. The
//! header deliberately carries no count for the same reason.
//!
//! # What goes in
//!
//! Only entries that have a password. Exactly one identity field per entry,
//! resolved `USER`, then `MAIL`, then `ACNT`. Nothing else: no notes, no seed
//! phrases, no card numbers, no PINs, no security answers. The index carries
//! the minimum needed to fill a login form and not one field more.

use serde::{Deserialize, Serialize};

use crate::database::models::{IWField, IWItem};
use crate::error::{Result, WalletError};

use super::crypto::{self, KEY_LEN};
use super::domain;
use super::identity::{IdentityKind, READ_PRIORITY};

/// Magic bytes at the start of every index file.
pub const MAGIC: &[u8; 4] = b"IWAF";
/// Current index format version.
pub const FORMAT_VERSION: u8 = 1;
/// The body is padded up to a multiple of this before sealing.
pub const PAD_BLOCK: usize = 4096;

/// One fillable login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub item_id: String,
    pub title: String,
    /// One of `MAIL`, `USER`, `ACNT`. Never two.
    pub identity_type: String,
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    /// Normalized hosts parsed from the entry's `LINK` fields.
    pub hosts: Vec<String>,
    /// Precomputed registrable domains, so the provider needs no public suffix
    /// list of its own and does plain string comparison.
    pub registrable: Vec<String>,
}

/// Plaintext header of an index file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexHeader {
    pub format_version: u8,
    pub generation: u64,
    pub built_at: i64,
    pub database_id: String,
}

/// What to include when building.
#[derive(Debug, Clone, Copy, Default)]
pub struct IndexOptions {
    /// Include `2FAC` secrets so the provider can offer one-time codes.
    /// Off until phase 4.
    pub include_totp: bool,
}

/// Seal an index.
pub fn build(
    entries: &[IndexEntry],
    index_key: &[u8; KEY_LEN],
    header: &IndexHeader,
) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(entries)
        .map_err(|e| WalletError::EncryptionError(format!("index encode failed: {e}")))?;

    let actual_len = u32::try_from(json.len())
        .map_err(|_| WalletError::EncryptionError("index is too large to frame".into()))?;
    let mut padded = Vec::with_capacity(4 + json.len());
    padded.extend_from_slice(&actual_len.to_le_bytes());
    padded.extend_from_slice(&json);
    let target = padded.len().div_ceil(PAD_BLOCK) * PAD_BLOCK;
    padded.resize(target, 0);

    let header_bytes = encode_header(header)?;
    let sealed = crypto::seal(index_key, &padded, &header_bytes)?;

    let mut out = Vec::with_capacity(header_bytes.len() + sealed.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a sealed index. Fails on a wrong key, an unknown format version, a
/// tampered header, or any modification to the body.
pub fn open(bytes: &[u8], index_key: &[u8; KEY_LEN]) -> Result<(IndexHeader, Vec<IndexEntry>)> {
    let (header, header_len) = decode_header(bytes)?;
    let sealed = &bytes[header_len..];

    let padded = crypto::open(index_key, sealed, &bytes[..header_len])?;
    if padded.len() < 4 {
        return Err(WalletError::DecryptionError("index body is truncated".into()));
    }
    let actual_len =
        u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    let json = padded
        .get(4..4 + actual_len)
        .ok_or_else(|| WalletError::DecryptionError("index body length is out of range".into()))?;

    let entries = serde_json::from_slice(json)
        .map_err(|e| WalletError::DecryptionError(format!("index decode failed: {e}")))?;
    Ok((header, entries))
}

/// Read the header without the key. The provider uses this to reject a format
/// it does not understand, and to show the sync age, before prompting for
/// biometrics.
pub fn peek_header(bytes: &[u8]) -> Result<IndexHeader> {
    decode_header(bytes).map(|(header, _)| header)
}

fn encode_header(header: &IndexHeader) -> Result<Vec<u8>> {
    let id = header.database_id.as_bytes();
    let id_len = u8::try_from(id.len())
        .map_err(|_| WalletError::EncryptionError("database id is too long".into()))?;

    let mut out = Vec::with_capacity(4 + 1 + 8 + 8 + 1 + id.len());
    out.extend_from_slice(MAGIC);
    out.push(header.format_version);
    out.extend_from_slice(&header.generation.to_le_bytes());
    out.extend_from_slice(&header.built_at.to_le_bytes());
    out.push(id_len);
    out.extend_from_slice(id);
    Ok(out)
}

fn decode_header(bytes: &[u8]) -> Result<(IndexHeader, usize)> {
    let malformed = || WalletError::DecryptionError("index header is malformed".into());

    if bytes.len() < 4 + 1 + 8 + 8 + 1 || &bytes[..4] != MAGIC {
        return Err(malformed());
    }
    let format_version = bytes[4];
    if format_version != FORMAT_VERSION {
        return Err(WalletError::InvalidVersion(format!(
            "unsupported autofill index format {format_version}"
        )));
    }
    let generation = u64::from_le_bytes(bytes[5..13].try_into().map_err(|_| malformed())?);
    let built_at = i64::from_le_bytes(bytes[13..21].try_into().map_err(|_| malformed())?);
    let id_len = bytes[21] as usize;
    let id = bytes.get(22..22 + id_len).ok_or_else(malformed)?;
    let database_id = String::from_utf8(id.to_vec()).map_err(|_| malformed())?;

    Ok((
        IndexHeader {
            format_version,
            generation,
            built_at,
            database_id,
        },
        22 + id_len,
    ))
}

/// Derive index entries from a vault's items and fields.
///
/// Pure, so the selection rules are testable without a database. Callers pass
/// everything; this filters.
pub fn entries_from_vault(
    items: &[IWItem],
    fields: &[IWField],
    options: IndexOptions,
) -> Vec<IndexEntry> {
    let mut out = Vec::new();

    for item in items {
        if item.folder || item.deleted || item.is_root() {
            continue;
        }

        let mut own: Vec<&IWField> = fields
            .iter()
            .filter(|f| f.item_id == item.item_id && !f.deleted && !f.value.trim().is_empty())
            .collect();
        // Lowest sort_weight wins within a field type.
        own.sort_by_key(|f| f.sort_weight);

        let Some(password) = own
            .iter()
            .find(|f| f.field_type == super::FIELD_PASSWORD)
            .map(|f| f.value.clone())
        else {
            continue;
        };

        // Exactly one identity field, by the documented priority.
        let Some((identity_type, username)) = READ_PRIORITY.iter().find_map(|kind| {
            own.iter()
                .find(|f| f.field_type == kind.field_type())
                .map(|f| (kind.field_type().to_string(), f.value.clone()))
        }) else {
            continue;
        };

        let mut hosts: Vec<String> = Vec::new();
        for field in own.iter().filter(|f| f.field_type == super::FIELD_LINK) {
            if let Some(host) = domain::normalize_host(&field.value)
                && !hosts.contains(&host)
            {
                hosts.push(host);
            }
        }
        let mut registrable: Vec<String> = Vec::new();
        for host in &hosts {
            if let Some(reg) = domain::registrable_domain(host)
                && !registrable.contains(&reg)
            {
                registrable.push(reg);
            }
        }

        let totp_secret = options
            .include_totp
            .then(|| {
                own.iter()
                    .find(|f| f.field_type == super::FIELD_TOTP)
                    .map(|f| f.value.clone())
            })
            .flatten();

        out.push(IndexEntry {
            item_id: item.item_id.clone(),
            title: item.name.clone(),
            identity_type,
            username,
            password,
            totp_secret,
            hosts,
            registrable,
        });
    }

    out
}

/// Rank an entry against the site being filled. `None` means the entry must not
/// be offered by domain at all; it stays reachable only through search.
pub fn rank(entry: &IndexEntry, query_host: &str) -> Option<domain::MatchTier> {
    entry
        .hosts
        .iter()
        .filter_map(|host| domain::match_tier(host, query_host))
        .max()
}

/// Identity kind of an entry, or `None` if it somehow carries an unrecognized
/// type (which `entries_from_vault` cannot produce, but a hand-edited or
/// future-format index could).
pub fn entry_identity_kind(entry: &IndexEntry) -> Option<IdentityKind> {
    IdentityKind::from_field_type(&entry.identity_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autofill::keys::generate_keys;
    use chrono::Utc;

    fn header() -> IndexHeader {
        IndexHeader {
            format_version: FORMAT_VERSION,
            generation: 7,
            built_at: 1_700_000_000,
            database_id: "db-id-0123456789".into(),
        }
    }

    fn entry(id: &str, host: &str) -> IndexEntry {
        IndexEntry {
            item_id: id.into(),
            title: "Example".into(),
            identity_type: "USER".into(),
            username: "bkv".into(),
            password: "hunter2".into(),
            totp_secret: None,
            hosts: vec![host.into()],
            registrable: domain::registrable_domain(host).into_iter().collect(),
        }
    }

    fn item(id: &str, name: &str, folder: bool, deleted: bool) -> IWItem {
        IWItem {
            item_id: id.into(),
            parent_id: Some(crate::ROOT_ID.into()),
            name: name.into(),
            icon: String::new(),
            folder,
            create_timestamp: Utc::now(),
            change_timestamp: Utc::now(),
            deleted,
        }
    }

    fn field(item_id: &str, field_id: &str, ty: &str, value: &str, weight: i32) -> IWField {
        IWField {
            item_id: item_id.into(),
            field_id: field_id.into(),
            field_type: ty.into(),
            value: value.into(),
            label: String::new(),
            icon: String::new(),
            value_type: String::new(),
            sort_weight: weight,
            change_timestamp: Utc::now(),
            deleted: false,
            expired: false,
            expiring: false,
        }
    }

    #[test]
    fn round_trip() {
        let keys = generate_keys().unwrap();
        let entries = vec![entry("i1", "example.com"), entry("i2", "example.co.uk")];
        let sealed = build(&entries, &keys.index_key, &header()).unwrap();
        let (got_header, got_entries) = open(&sealed, &keys.index_key).unwrap();
        assert_eq!(got_header, header());
        assert_eq!(got_entries, entries);
    }

    #[test]
    fn empty_index_round_trips() {
        let keys = generate_keys().unwrap();
        let sealed = build(&[], &keys.index_key, &header()).unwrap();
        let (_, entries) = open(&sealed, &keys.index_key).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let keys = generate_keys().unwrap();
        let other = generate_keys().unwrap();
        let sealed = build(&[entry("i1", "example.com")], &keys.index_key, &header()).unwrap();
        assert!(open(&sealed, &other.index_key).is_err());
    }

    #[test]
    fn every_header_field_is_authenticated() {
        let keys = generate_keys().unwrap();
        let sealed = build(&[entry("i1", "example.com")], &keys.index_key, &header()).unwrap();

        // Magic, version, generation, timestamp and database id all sit in the
        // AAD, so touching any byte of the header must break the open.
        for byte in 0..22 + header().database_id.len() {
            let mut tampered = sealed.clone();
            tampered[byte] ^= 0x01;
            assert!(
                open(&tampered, &keys.index_key).is_err(),
                "header byte {byte} is not authenticated"
            );
        }
    }

    #[test]
    fn body_tampering_is_detected() {
        let keys = generate_keys().unwrap();
        let sealed = build(&[entry("i1", "example.com")], &keys.index_key, &header()).unwrap();
        let header_len = 22 + header().database_id.len();
        for byte in header_len..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[byte] ^= 0x01;
            assert!(open(&tampered, &keys.index_key).is_err(), "body byte {byte}");
        }
    }

    #[test]
    fn truncation_at_every_length_is_detected() {
        let keys = generate_keys().unwrap();
        let sealed = build(&[entry("i1", "example.com")], &keys.index_key, &header()).unwrap();
        for len in 0..sealed.len() {
            assert!(open(&sealed[..len], &keys.index_key).is_err(), "length {len}");
        }
    }

    #[test]
    fn an_unknown_format_version_is_rejected_before_the_key_is_used() {
        let keys = generate_keys().unwrap();
        let mut sealed = build(&[entry("i1", "example.com")], &keys.index_key, &header()).unwrap();
        sealed[4] = 99;
        assert!(matches!(
            peek_header(&sealed),
            Err(WalletError::InvalidVersion(_))
        ));
        assert!(open(&sealed, &keys.index_key).is_err());
    }

    #[test]
    fn peek_header_needs_no_key() {
        let keys = generate_keys().unwrap();
        let sealed = build(&[entry("i1", "example.com")], &keys.index_key, &header()).unwrap();
        assert_eq!(peek_header(&sealed).unwrap(), header());
    }

    #[test]
    fn size_is_padded_so_it_does_not_leak_the_entry_count() {
        let keys = generate_keys().unwrap();
        let one = build(&[entry("i1", "a.com")], &keys.index_key, &header()).unwrap();
        let five: Vec<IndexEntry> = (0..5).map(|i| entry(&format!("i{i}"), "a.com")).collect();
        let five = build(&five, &keys.index_key, &header()).unwrap();

        assert_eq!(one.len(), five.len(), "small indexes must share a size class");
        let header_len = 22 + header().database_id.len();
        for sealed in [&one, &five] {
            let body = sealed.len() - header_len - crypto::NONCE_LEN - crypto::TAG_LEN;
            assert_eq!(body % PAD_BLOCK, 0, "body is not padded to a block");
        }
    }

    #[test]
    fn builds_are_stable_apart_from_nonce() {
        let keys = generate_keys().unwrap();
        let entries = vec![entry("i1", "example.com")];
        let a = build(&entries, &keys.index_key, &header()).unwrap();
        let b = build(&entries, &keys.index_key, &header()).unwrap();
        let header_len = 22 + header().database_id.len();
        assert_eq!(a[..header_len], b[..header_len], "headers must match");
        assert_ne!(a, b, "a fresh nonce must be drawn every build");
        assert_eq!(
            open(&a, &keys.index_key).unwrap(),
            open(&b, &keys.index_key).unwrap()
        );
    }

    // --- selection rules -------------------------------------------------

    #[test]
    fn only_entries_with_a_password_are_indexed() {
        let items = vec![item("i1", "Has password", false, false), item("i2", "No password", false, false)];
        let fields = vec![
            field("i1", "f1", "USER", "bkv", 0),
            field("i1", "f2", "PASS", "hunter2", 1),
            field("i2", "f3", "USER", "bkv", 0),
            field("i2", "f4", "NOTE", "just a note", 1),
        ];
        let entries = entries_from_vault(&items, &fields, IndexOptions::default());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].item_id, "i1");
    }

    #[test]
    fn folders_deleted_items_and_deleted_fields_are_excluded() {
        let mut deleted_field = field("i3", "f6", "PASS", "hunter2", 1);
        deleted_field.deleted = true;

        let items = vec![
            item("i1", "A folder", true, false),
            item("i2", "Deleted", false, true),
            item("i3", "Deleted password", false, false),
        ];
        let fields = vec![
            field("i1", "f1", "USER", "bkv", 0),
            field("i1", "f2", "PASS", "hunter2", 1),
            field("i2", "f3", "USER", "bkv", 0),
            field("i2", "f4", "PASS", "hunter2", 1),
            field("i3", "f5", "USER", "bkv", 0),
            deleted_field,
        ];
        assert!(entries_from_vault(&items, &fields, IndexOptions::default()).is_empty());
    }

    #[test]
    fn identity_priority_is_user_then_mail_then_account() {
        let items = vec![
            item("all", "All three", false, false),
            item("mail", "Mail and account", false, false),
            item("acnt", "Account only", false, false),
        ];
        let fields = vec![
            field("all", "a1", "ACNT", "12345", 0),
            field("all", "a2", "MAIL", "a@bkv.me", 1),
            field("all", "a3", "USER", "bkv", 2),
            field("all", "a4", "PASS", "p", 3),
            field("mail", "b1", "ACNT", "12345", 0),
            field("mail", "b2", "MAIL", "a@bkv.me", 1),
            field("mail", "b3", "PASS", "p", 2),
            field("acnt", "c1", "ACNT", "12345", 0),
            field("acnt", "c2", "PASS", "p", 1),
        ];
        let entries = entries_from_vault(&items, &fields, IndexOptions::default());
        let by_id = |id: &str| entries.iter().find(|e| e.item_id == id).unwrap().clone();

        // Note the priority is by field type, not by sort_weight: USER wins
        // even though it sits last in the entry.
        assert_eq!(by_id("all").identity_type, "USER");
        assert_eq!(by_id("all").username, "bkv");
        assert_eq!(by_id("mail").identity_type, "MAIL");
        assert_eq!(by_id("acnt").identity_type, "ACNT");
    }

    #[test]
    fn exactly_one_identity_field_is_ever_produced() {
        let items = vec![item("i1", "All three", false, false)];
        let fields = vec![
            field("i1", "f1", "USER", "bkv", 0),
            field("i1", "f2", "MAIL", "a@bkv.me", 1),
            field("i1", "f3", "ACNT", "12345", 2),
            field("i1", "f4", "PASS", "p", 3),
        ];
        let entries = entries_from_vault(&items, &fields, IndexOptions::default());
        assert_eq!(entries.len(), 1);
        assert!(entry_identity_kind(&entries[0]).is_some());
    }

    #[test]
    fn lowest_sort_weight_wins_within_a_field_type() {
        let items = vec![item("i1", "Two passwords", false, false)];
        let fields = vec![
            field("i1", "f1", "USER", "second", 5),
            field("i1", "f2", "USER", "first", 1),
            field("i1", "f3", "PASS", "second-pass", 9),
            field("i1", "f4", "PASS", "first-pass", 2),
        ];
        let entries = entries_from_vault(&items, &fields, IndexOptions::default());
        assert_eq!(entries[0].username, "first");
        assert_eq!(entries[0].password, "first-pass");
    }

    #[test]
    fn secrets_other_than_the_password_never_reach_the_index() {
        let items = vec![item("i1", "Loaded", false, false)];
        let fields = vec![
            field("i1", "f1", "USER", "bkv", 0),
            field("i1", "f2", "PASS", "hunter2", 1),
            field("i1", "f3", "SEED", "witch collapse practice feed", 2),
            field("i1", "f4", "NOTE", "my private note", 3),
            field("i1", "f5", "CARD", "4111111111111111", 4),
            field("i1", "f6", "PINC", "0000", 5),
            field("i1", "f7", "SANS", "my first pet", 6),
            field("i1", "f8", "2FAC", "JBSWY3DPEHPK3PXP", 7),
        ];
        let keys = generate_keys().unwrap();
        let entries = entries_from_vault(&items, &fields, IndexOptions::default());
        let sealed = build(&entries, &keys.index_key, &header()).unwrap();
        let (_, opened) = open(&sealed, &keys.index_key).unwrap();

        let json = serde_json::to_string(&opened).unwrap();
        for secret in [
            "witch collapse practice feed",
            "my private note",
            "4111111111111111",
            "0000",
            "my first pet",
            "JBSWY3DPEHPK3PXP",
        ] {
            assert!(!json.contains(secret), "{secret} leaked into the index");
        }
        assert!(json.contains("hunter2"));
        assert!(opened[0].totp_secret.is_none());
    }

    #[test]
    fn totp_is_included_only_when_asked_for() {
        let items = vec![item("i1", "With 2FA", false, false)];
        let fields = vec![
            field("i1", "f1", "USER", "bkv", 0),
            field("i1", "f2", "PASS", "p", 1),
            field("i1", "f3", "2FAC", "JBSWY3DPEHPK3PXP", 2),
        ];
        let off = entries_from_vault(&items, &fields, IndexOptions::default());
        assert_eq!(off[0].totp_secret, None);

        let on = entries_from_vault(&items, &fields, IndexOptions { include_totp: true });
        assert_eq!(on[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn hosts_are_normalized_deduplicated_and_given_registrable_domains() {
        let items = vec![item("i1", "Many links", false, false)];
        let fields = vec![
            field("i1", "f1", "USER", "bkv", 0),
            field("i1", "f2", "PASS", "p", 1),
            field("i1", "f3", "LINK", "https://www.Example.COM/login", 2),
            field("i1", "f4", "LINK", "example.com", 3),
            field("i1", "f5", "LINK", "https://login.example.co.uk:8443/", 4),
            field("i1", "f6", "LINK", "mailto:a@example.com", 5),
            field("i1", "f7", "LINK", "not a url at all", 6),
        ];
        let entries = entries_from_vault(&items, &fields, IndexOptions::default());
        assert_eq!(
            entries[0].hosts,
            vec!["example.com", "login.example.co.uk"],
            "duplicates collapse, junk and mailto are dropped"
        );
        assert_eq!(entries[0].registrable, vec!["example.com", "example.co.uk"]);
    }

    #[test]
    fn ranking_prefers_the_strongest_matching_host() {
        let mut e = entry("i1", "example.com");
        e.hosts = vec!["login.example.com".into(), "example.com".into()];
        e.registrable = vec!["example.com".into()];

        assert_eq!(rank(&e, "example.com"), Some(domain::MatchTier::ExactHost));
        assert_eq!(
            rank(&e, "checkout.example.com"),
            Some(domain::MatchTier::RegistrableDomain)
        );
        assert_eq!(rank(&e, "unrelated.org"), None);
    }

    #[test]
    fn an_entry_with_no_links_never_matches_by_domain() {
        let mut e = entry("i1", "example.com");
        e.hosts.clear();
        e.registrable.clear();
        assert_eq!(rank(&e, "example.com"), None);
    }
}
