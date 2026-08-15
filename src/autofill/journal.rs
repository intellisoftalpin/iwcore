//! The write-back journal: logins created in the autofill provider, waiting to
//! be drained into the vault.
//!
//! # Why records are wrapped twice
//!
//! Each record body is sealed under a fresh random key `K`, and `K` is wrapped
//! twice:
//!
//! - to the app's P-256 public key, which only the app can open;
//! - under the index key, which the provider already holds.
//!
//! The app wrap is what guarantees a staged login can always be drained, even
//! if the index key has since been rotated or invalidated. The index-key wrap
//! is what lets the provider show a login it created a moment ago: without it,
//! creating an account through the extension and returning to the same site
//! later would show nothing, which reads as the feature being broken.
//!
//! The security cost of the second wrap is small. An attacker holding only the
//! stored files can open neither, since the index key lives in the Keychain. An
//! attacker who has compromised the provider already holds the index key and
//! therefore the whole index, so a handful of staged records is marginal.
//!
//! # Framing
//!
//! ```text
//! record := u32 LE payload_len || payload
//! payload := u8 version
//!         || u8  eph_len  || eph_public
//!         || u16 LE len   || wrap_to_app      (K sealed to the app's key)
//!         || u16 LE len   || wrap_to_index    (K sealed under the index key)
//!         || u32 LE len   || body             (the record JSON, sealed under K)
//! ```
//!
//! Records are **independently** sealed and independently framed, and the file
//! is only ever appended to. A torn final write costs at most the last record;
//! every earlier one still opens. Both readers below stop at the first
//! malformed record and return everything they parsed before it, rather than
//! failing the whole file.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, WalletError};

use super::crypto::{self, KEY_LEN};

/// Current journal record format version.
pub const FORMAT_VERSION: u8 = 1;

/// Maximum records the provider may stage before it must refuse to save more.
pub const MAX_RECORDS: usize = 50;
/// Record count from which the provider warns on every invocation.
pub const WARN_AT_RECORDS: usize = 40;
/// Maximum journal size on disk.
pub const MAX_BYTES: usize = 64 * 1024;

/// HKDF domain separation for the app wrap.
const ECIES_INFO: &[u8] = b"iwcore/autofill/journal/v1/ecies";

/// What the provider is asking the app to do with a staged record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingOp {
    /// A brand new login. Imported into the `AutoFill` folder.
    Create,
    /// A password change for an entry that already exists. The old value moves
    /// into an `OLDP` field and the new one is written to `PASS`.
    UpdatePassword,
}

/// One staged login.
///
/// Note there is no expiry field, and readers never filter by age: staged
/// records fill until they are drained. That is a deliberate exemption from the
/// index's own expiry, because a record the user created moments ago has never
/// had a chance to reach the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecord {
    /// Random identifier, so a crash between "written to vault" and "journal
    /// deleted" cannot double-import on the next attempt.
    pub record_id: String,
    pub op: PendingOp,
    /// Target item for [`PendingOp::UpdatePassword`]. A record naming an item
    /// that no longer exists degrades to a create rather than being dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    /// Suggested item name.
    pub title: String,
    /// The site the credential was created for, stored verbatim in `LINK`.
    pub url: String,
    /// The login identity. Which field type it lands in is decided by
    /// [`super::identity::classify`], not by the provider.
    pub identity_value: String,
    /// Optional hint from the provider, used only when iOS told it the form
    /// field was specifically an email field. A hint naming anything other than
    /// `MAIL`, `USER` or `ACNT` is ignored, so a malformed hint cannot put an
    /// arbitrary field type into the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_hint: Option<String>,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    /// Unix seconds. Informational only; never used to expire a record.
    pub created_at: i64,
}

impl PendingRecord {
    /// The field type this record's identity value belongs in: the hint when it
    /// names a real identity type, the classifier otherwise.
    pub fn identity_kind(&self) -> super::identity::IdentityKind {
        self.identity_hint
            .as_deref()
            .and_then(super::identity::IdentityKind::from_field_type)
            .unwrap_or_else(|| super::identity::classify(&self.identity_value))
    }
}

/// Seal one record into its framed on-disk form. The provider appends the
/// returned bytes verbatim.
pub fn seal_record(
    record: &PendingRecord,
    journal_public: &[u8],
    index_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(record)
        .map_err(|e| WalletError::EncryptionError(format!("journal encode failed: {e}")))?;

    let record_key = crypto::random_key();

    // The app wrap carries its own ephemeral key, so it cannot be bound to a
    // header that contains that key. It is bound to the version instead; any
    // tampering with the ephemeral key makes the derivation fail regardless.
    let (eph_public, wrap_to_app) =
        crypto::ecies_seal(journal_public, record_key.as_slice(), &[FORMAT_VERSION], ECIES_INFO)?;

    // Everything else is bound to version + ephemeral key.
    let header = header_bytes(&eph_public);
    let wrap_to_index = crypto::seal(index_key, record_key.as_slice(), &header)?;
    let body = crypto::seal(&record_key, &json, &header)?;

    let mut payload = Vec::new();
    payload.push(FORMAT_VERSION);
    payload.push(u8::try_from(eph_public.len()).map_err(|_| too_long("ephemeral key"))?);
    payload.extend_from_slice(&eph_public);
    payload.extend_from_slice(&u16::try_from(wrap_to_app.len()).map_err(|_| too_long("app wrap"))?.to_le_bytes());
    payload.extend_from_slice(&wrap_to_app);
    payload.extend_from_slice(&u16::try_from(wrap_to_index.len()).map_err(|_| too_long("index wrap"))?.to_le_bytes());
    payload.extend_from_slice(&wrap_to_index);
    payload.extend_from_slice(&u32::try_from(body.len()).map_err(|_| too_long("body"))?.to_le_bytes());
    payload.extend_from_slice(&body);

    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&u32::try_from(payload.len()).map_err(|_| too_long("record"))?.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Open every record the app can read, using its private journal key. This is
/// the drain path, and it works regardless of the state of the index key.
pub fn open_with_journal_key(journal: &[u8], journal_secret: &[u8; 32]) -> Vec<PendingRecord> {
    parse(journal, |parsed| {
        let key = crypto::ecies_open(
            journal_secret,
            parsed.eph_public,
            parsed.wrap_to_app,
            &[FORMAT_VERSION],
            ECIES_INFO,
        )?;
        into_key(key)
    })
}

/// Open every record the provider can read, using the shared index key. This is
/// the read-back path that lets a just-created login appear in the provider's
/// list before the app has ever drained it.
pub fn open_with_index_key(journal: &[u8], index_key: &[u8; KEY_LEN]) -> Vec<PendingRecord> {
    parse(journal, |parsed| {
        let header = header_bytes(parsed.eph_public);
        let key = crypto::open(index_key, parsed.wrap_to_index, &header)?;
        into_key(key)
    })
}

/// Whether the provider may stage another record.
pub fn can_accept(current_len: usize, current_records: usize) -> bool {
    current_records < MAX_RECORDS && current_len < MAX_BYTES
}

/// Whether the provider should warn that the journal is filling up.
pub fn should_warn(current_records: usize) -> bool {
    current_records >= WARN_AT_RECORDS
}

/// Drop records whose `record_id` was already seen, preserving order. Applied
/// on drain so a crash mid-import cannot double-write.
pub fn dedupe(records: Vec<PendingRecord>) -> Vec<PendingRecord> {
    let mut seen = std::collections::HashSet::new();
    records
        .into_iter()
        .filter(|r| seen.insert(r.record_id.clone()))
        .collect()
}

fn header_bytes(eph_public: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(1 + eph_public.len());
    header.push(FORMAT_VERSION);
    header.extend_from_slice(eph_public);
    header
}

fn into_key(bytes: Vec<u8>) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if bytes.len() != KEY_LEN {
        return Err(WalletError::DecryptionError(
            "journal record key has the wrong length".into(),
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(Zeroizing::new(key))
}

fn too_long(what: &str) -> WalletError {
    WalletError::EncryptionError(format!("journal {what} is too long to frame"))
}

struct ParsedRecord<'a> {
    eph_public: &'a [u8],
    wrap_to_app: &'a [u8],
    wrap_to_index: &'a [u8],
    body: &'a [u8],
}

/// Walk the framed stream, unwrapping each record with `unwrap_key`.
///
/// Stops at the first structurally malformed record and returns everything
/// parsed so far. A record that is well-framed but fails to open (wrong key,
/// tampering) is skipped while parsing continues, so one bad record cannot hide
/// the ones after it.
fn parse<F>(journal: &[u8], unwrap_key: F) -> Vec<PendingRecord>
where
    F: Fn(&ParsedRecord<'_>) -> Result<Zeroizing<[u8; KEY_LEN]>>,
{
    let mut out = Vec::new();
    let mut cursor = 0usize;

    while cursor + 4 <= journal.len() {
        let len = u32::from_le_bytes([
            journal[cursor],
            journal[cursor + 1],
            journal[cursor + 2],
            journal[cursor + 3],
        ]) as usize;
        cursor += 4;
        if len == 0 || cursor + len > journal.len() {
            break; // truncated tail
        }
        let payload = &journal[cursor..cursor + len];
        cursor += len;

        let Some(parsed) = split_payload(payload) else {
            break; // structurally broken, cannot trust anything past here
        };
        let Ok(key) = unwrap_key(&parsed) else {
            continue; // not ours to read, or tampered; later records may be fine
        };
        let header = header_bytes(parsed.eph_public);
        let Ok(json) = crypto::open(&key, parsed.body, &header) else {
            continue;
        };
        if let Ok(record) = serde_json::from_slice::<PendingRecord>(&json) {
            out.push(record);
        }
    }

    out
}

fn split_payload(payload: &[u8]) -> Option<ParsedRecord<'_>> {
    let mut at = 0usize;
    let version = *payload.first()?;
    at += 1;
    if version != FORMAT_VERSION {
        return None;
    }

    let eph_len = *payload.get(at)? as usize;
    at += 1;
    let eph_public = payload.get(at..at + eph_len)?;
    at += eph_len;

    let wrap_app_len = read_u16(payload, at)?;
    at += 2;
    let wrap_to_app = payload.get(at..at + wrap_app_len)?;
    at += wrap_app_len;

    let wrap_idx_len = read_u16(payload, at)?;
    at += 2;
    let wrap_to_index = payload.get(at..at + wrap_idx_len)?;
    at += wrap_idx_len;

    let body_len = read_u32(payload, at)?;
    at += 4;
    let body = payload.get(at..at + body_len)?;

    Some(ParsedRecord {
        eph_public,
        wrap_to_app,
        wrap_to_index,
        body,
    })
}

fn read_u16(buf: &[u8], at: usize) -> Option<usize> {
    let bytes = buf.get(at..at + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
}

fn read_u32(buf: &[u8], at: usize) -> Option<usize> {
    let bytes = buf.get(at..at + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
}

#[cfg(test)]
mod tests {
    use super::super::identity::IdentityKind;
    use super::super::keys::generate_keys;
    use super::*;

    fn record(id: &str) -> PendingRecord {
        PendingRecord {
            record_id: id.to_string(),
            op: PendingOp::Create,
            item_id: None,
            title: "Example".into(),
            url: "https://example.com/signup".into(),
            identity_value: "bkv".into(),
            identity_hint: None,
            password: "correct horse battery staple".into(),
            totp_secret: None,
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn both_wraps_open_to_identical_plaintext() {
        let keys = generate_keys().unwrap();
        let original = record("r1");
        let sealed = seal_record(&original, &keys.journal_public, &keys.index_key).unwrap();

        let via_app = open_with_journal_key(&sealed, &keys.journal_secret);
        let via_index = open_with_index_key(&sealed, &keys.index_key);

        assert_eq!(via_app, vec![original.clone()]);
        assert_eq!(via_index, vec![original]);
        assert_eq!(via_app, via_index);
    }

    /// The property the whole design rests on: the drain path must survive an
    /// index key that has been rotated or invalidated.
    #[test]
    fn app_can_still_drain_when_the_index_wrap_is_unusable() {
        let keys = generate_keys().unwrap();
        let rotated = generate_keys().unwrap();
        let sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key).unwrap();

        // The provider has lost read-back...
        assert!(open_with_index_key(&sealed, &rotated.index_key).is_empty());
        // ...but nothing is lost, because the app never needed that key.
        assert_eq!(open_with_journal_key(&sealed, &keys.journal_secret).len(), 1);
    }

    #[test]
    fn corrupting_only_the_index_wrap_leaves_the_app_path_intact() {
        let keys = generate_keys().unwrap();
        let mut sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key).unwrap();

        // Locate the index wrap exactly, rather than guessing an offset: the
        // body is sealed under the shared record key, so corrupting it would
        // break both paths and prove nothing.
        let (eph_len, wrap_app_len) = {
            let parsed = split_payload(&sealed[4..]).unwrap();
            (parsed.eph_public.len(), parsed.wrap_to_app.len())
        };
        let target = 4 + 1 + 1 + eph_len + 2 + wrap_app_len + 2;
        sealed[target] ^= 0xff;

        assert!(open_with_index_key(&sealed, &keys.index_key).is_empty());
        assert_eq!(open_with_journal_key(&sealed, &keys.journal_secret).len(), 1);
    }

    #[test]
    fn the_public_key_alone_cannot_open_a_record() {
        let keys = generate_keys().unwrap();
        let sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key).unwrap();

        // Treating the public key bytes as if they were a secret scalar must
        // not yield anything.
        let mut fake_secret = [0u8; 32];
        fake_secret.copy_from_slice(&keys.journal_public[1..33]);
        assert!(open_with_journal_key(&sealed, &fake_secret).is_empty());
    }

    #[test]
    fn keys_from_another_enable_cycle_open_nothing() {
        let keys = generate_keys().unwrap();
        let other = generate_keys().unwrap();
        let sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key).unwrap();

        assert!(open_with_journal_key(&sealed, &other.journal_secret).is_empty());
        assert!(open_with_index_key(&sealed, &other.index_key).is_empty());
    }

    #[test]
    fn records_are_independent_under_truncation_at_every_offset() {
        let keys = generate_keys().unwrap();
        let mut journal = Vec::new();
        let first = seal_record(&record("r1"), &keys.journal_public, &keys.index_key).unwrap();
        let second = seal_record(&record("r2"), &keys.journal_public, &keys.index_key).unwrap();
        journal.extend_from_slice(&first);
        journal.extend_from_slice(&second);

        // Cut anywhere inside the second record: the first must always survive.
        for cut in first.len()..journal.len() {
            let opened = open_with_journal_key(&journal[..cut], &keys.journal_secret);
            assert_eq!(opened.len(), 1, "truncated at {cut}");
            assert_eq!(opened[0].record_id, "r1");
        }
        // Intact, both are readable.
        assert_eq!(open_with_journal_key(&journal, &keys.journal_secret).len(), 2);
    }

    #[test]
    fn an_unreadable_record_does_not_hide_the_ones_after_it() {
        let keys = generate_keys().unwrap();
        let other = generate_keys().unwrap();
        let mut journal = Vec::new();
        // Sealed to a different app key: well-framed, but not ours to open.
        journal.extend_from_slice(
            &seal_record(&record("foreign"), &other.journal_public, &keys.index_key).unwrap(),
        );
        journal.extend_from_slice(
            &seal_record(&record("ours"), &keys.journal_public, &keys.index_key).unwrap(),
        );

        let opened = open_with_journal_key(&journal, &keys.journal_secret);
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].record_id, "ours");
    }

    #[test]
    fn garbage_never_panics_and_yields_nothing() {
        let keys = generate_keys().unwrap();
        for junk in [
            b"".to_vec(),
            b"\x00".to_vec(),
            b"\xff\xff\xff\xff".to_vec(),
            vec![0u8; 128],
            b"not a journal at all".to_vec(),
        ] {
            assert!(open_with_journal_key(&junk, &keys.journal_secret).is_empty());
            assert!(open_with_index_key(&junk, &keys.index_key).is_empty());
        }
    }

    #[test]
    fn an_unknown_format_version_is_refused() {
        let keys = generate_keys().unwrap();
        let mut sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key).unwrap();
        sealed[4] = 99; // version byte, straight after the u32 frame length
        assert!(open_with_journal_key(&sealed, &keys.journal_secret).is_empty());
    }

    #[test]
    fn staged_records_are_never_filtered_by_age() {
        let keys = generate_keys().unwrap();
        let mut ancient = record("old");
        ancient.created_at = 0; // 1970
        let sealed = seal_record(&ancient, &keys.journal_public, &keys.index_key).unwrap();

        assert_eq!(open_with_journal_key(&sealed, &keys.journal_secret).len(), 1);
        assert_eq!(open_with_index_key(&sealed, &keys.index_key).len(), 1);
    }

    #[test]
    fn dedupe_keeps_the_first_of_each_id_in_order() {
        let records = vec![record("a"), record("b"), record("a"), record("c")];
        let ids: Vec<String> = dedupe(records).into_iter().map(|r| r.record_id).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn caps_are_enforced_at_the_documented_thresholds() {
        assert!(can_accept(0, 0));
        assert!(can_accept(1024, MAX_RECORDS - 1));
        assert!(!can_accept(1024, MAX_RECORDS));
        assert!(!can_accept(MAX_BYTES, 0));

        assert!(!should_warn(WARN_AT_RECORDS - 1));
        assert!(should_warn(WARN_AT_RECORDS));
        assert!(should_warn(MAX_RECORDS));
    }

    #[test]
    fn identity_hint_is_honoured_only_when_it_names_an_identity_type() {
        let mut r = record("r1");
        r.identity_value = "bkv".into();

        r.identity_hint = Some("MAIL".into());
        assert_eq!(r.identity_kind(), IdentityKind::Mail, "a valid hint wins");

        r.identity_hint = Some("PASS".into());
        assert_eq!(
            r.identity_kind(),
            IdentityKind::User,
            "a hint naming a non-identity type must be ignored"
        );

        r.identity_hint = Some("nonsense".into());
        assert_eq!(r.identity_kind(), IdentityKind::User);

        r.identity_hint = None;
        assert_eq!(r.identity_kind(), IdentityKind::User);

        r.identity_value = "a@bkv.me".into();
        assert_eq!(r.identity_kind(), IdentityKind::Mail, "classifier decides");
    }
}
