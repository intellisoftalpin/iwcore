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
//! # Integrity
//!
//! The app wrap provides confidentiality; it does not identify the writer,
//! because the key it is sealed to is public. Every format-2 record therefore
//! also carries an HMAC-SHA256 tag under the journal auth key (see
//! [`super::keys`]), a symmetric key held only by the app and its provider, so
//! the drain applies exactly the records the provider wrote. The tag covers every payload byte before it, version
//! included, so no part of a record can be altered or exchanged. The tag does
//! not say when a record was written, so the vault also remembers which
//! records it has applied and never applies one twice (see
//! [`crate::Wallet::drain_autofill_journal`]).
//!
//! The drain ([`open_for_drain`]) verifies the tag before it unwraps anything
//! and refuses a record whose tag does not verify. Such records are counted in
//! [`DrainRead::unauthenticated`] and never applied.
//!
//! Format-1 records, written before records carried a tag, are refused by the
//! drain as well, unless the caller passes the key they were wrapped under in
//! [`DrainKeys::legacy_wrap_keys`]: a format-1 record whose provider wrap opens
//! under one of those symmetric keys was written by a holder of that key, which
//! is the same guarantee the tag gives. Passing none refuses them all.
//!
//! The provider's read-back path ([`open_with_index_key`]) needs no tag: the
//! provider wrap is an AEAD under a symmetric key, so a record that opens there
//! was written by a holder of that key. It reads both formats.
//!
//! # Framing
//!
//! ```text
//! record := u32 LE payload_len || payload
//! payload := u8 version                        (2; 1 for legacy records)
//!         || u8  eph_len  || eph_public
//!         || u16 LE len   || wrap_to_app      (K sealed to the app's key)
//!         || u16 LE len   || wrap_to_index    (K sealed under the index key)
//!         || u32 LE len   || body             (the record JSON, sealed under K)
//!         || [32] tag                         (format 2 only; HMAC-SHA256 under
//!                                              the journal auth key over
//!                                              MAC_CONTEXT || every byte above)
//! ```
//!
//! Every length is applied with checked arithmetic and bounds-checked slices,
//! so a hostile length ends the walk on every pointer width, 32-bit included.
//!
//! Records are **independently** sealed and independently framed, and the file
//! is only ever appended to. A torn final write costs at most the last record;
//! every earlier one still opens. Both readers below stop at the first
//! malformed record and return everything they parsed before it, rather than
//! failing the whole file. Anything after that point is lost to the reader,
//! including records appended after a torn write; the drain reports how many
//! bytes it could not read in [`DrainRead::unparsed_bytes`], so the caller can
//! keep the journal instead of deleting it.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, WalletError};
use crate::passkey::PasskeyRecord;

use super::crypto::{self, KEY_LEN};

/// Current journal record format version: records carry an HMAC tag.
pub const FORMAT_VERSION: u8 = 2;
/// The format before records carried a tag. Read back by the provider; drained
/// only through [`DrainKeys::legacy_wrap_keys`].
pub const LEGACY_FORMAT_VERSION: u8 = 1;
/// Length of the HMAC-SHA256 tag closing a format-2 record.
pub const TAG_LEN: usize = 32;
/// Prefix of the message the tag is computed over, for domain separation.
pub const MAC_CONTEXT: &[u8] = b"iwcore/autofill/journal/v2/mac";

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
    /// A passkey created in the provider. The record is read with
    /// [`PendingRecord::staged_passkey`]; the password field is empty.
    CreatePasskey,
}

/// One staged login.
///
/// Note there is no expiry field, and readers never filter by age: staged
/// records fill until they are drained. That is a deliberate exemption from the
/// index's own expiry, because a record the user created moments ago has never
/// had a chance to reach the vault.
///
/// `Debug` redacts the password, the TOTP secret and the passkey.
///
/// The staged passkey (private key included) is not a public field: it is held
/// in a zeroizing buffer, written with [`PendingRecord::new_passkey`] and read back
/// only as a [`PasskeyRecord`], whose key never leaves the crate except as a
/// signature.
///
/// For the same reason the record has no public serde implementation: the
/// crate writes and reads its journal JSON itself, so the staged passkey can
/// only leave the crate sealed into a journal record. A provider that hands
/// over a login as JSON parses it into a [`PendingLogin`], which has no
/// passkey, and converts that.
///
/// ```compile_fail
/// let r = iwcore::autofill::PendingRecord::new_login("r1", "Example", "https://example.com", "bkv", "pw", 0);
/// let _ = serde_json::to_string(&r);
/// ```
///
/// ```compile_fail
/// let _: iwcore::autofill::PendingRecord = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PendingRecord {
    /// Random identifier, so a crash between "written to vault" and "journal
    /// deleted" cannot double-import on the next attempt.
    pub record_id: String,
    pub op: PendingOp,
    /// Target item for [`PendingOp::UpdatePassword`]. A record naming an item
    /// that no longer exists degrades to a create rather than being dropped.
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
    pub identity_hint: Option<String>,
    pub password: String,
    pub totp_secret: Option<String>,
    /// Unix seconds. Informational only; never used to expire a record.
    pub created_at: i64,
    /// For [`PendingOp::CreatePasskey`]: the passkey as a `PKEY` field value
    /// (see `passkey::record`), private key included. Absent otherwise, so
    /// records written before passkeys existed read unchanged.
    pub(crate) passkey: Option<Zeroizing<String>>,
}

/// A login as a provider hands it over, in the journal record's JSON shape
/// (`record_id`, `op`, `item_id`, `title`, `url`, `identity_value`,
/// `identity_hint`, `password`, `totp_secret`, `created_at`). It has no
/// passkey: a passkey is staged only through [`PendingRecord::new_passkey`].
/// Unknown members, a `passkey` member included, are ignored.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct PendingLogin {
    pub record_id: String,
    pub op: PendingOp,
    #[serde(default)]
    pub item_id: Option<String>,
    pub title: String,
    pub url: String,
    pub identity_value: String,
    #[serde(default)]
    pub identity_hint: Option<String>,
    pub password: String,
    #[serde(default)]
    pub totp_secret: Option<String>,
    pub created_at: i64,
}

impl std::fmt::Debug for PendingLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingLogin")
            .field("record_id", &self.record_id)
            .field("op", &self.op)
            .field("item_id", &self.item_id)
            .field("title", &self.title)
            .field("url", &self.url)
            .field("identity_value", &self.identity_value)
            .field("identity_hint", &self.identity_hint)
            .field("password", &crate::utils::REDACTED)
            .field("totp_secret", &self.totp_secret.as_ref().map(|_| crate::utils::REDACTED))
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl From<PendingLogin> for PendingRecord {
    fn from(login: PendingLogin) -> Self {
        Self {
            record_id: login.record_id,
            op: login.op,
            item_id: login.item_id,
            title: login.title,
            url: login.url,
            identity_value: login.identity_value,
            identity_hint: login.identity_hint,
            password: login.password,
            totp_secret: login.totp_secret,
            created_at: login.created_at,
            passkey: None,
        }
    }
}

/// A record's journal JSON, borrowed from the record for sealing. Crate-only,
/// like everything that can write the staged passkey.
#[derive(Serialize)]
pub(crate) struct WireOut<'a> {
    record_id: &'a str,
    op: PendingOp,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_id: Option<&'a str>,
    title: &'a str,
    url: &'a str,
    identity_value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_hint: Option<&'a str>,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp_secret: Option<&'a str>,
    created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    passkey: Option<&'a str>,
}

impl<'a> From<&'a PendingRecord> for WireOut<'a> {
    fn from(r: &'a PendingRecord) -> Self {
        Self {
            record_id: &r.record_id,
            op: r.op,
            item_id: r.item_id.as_deref(),
            title: &r.title,
            url: &r.url,
            identity_value: &r.identity_value,
            identity_hint: r.identity_hint.as_deref(),
            password: &r.password,
            totp_secret: r.totp_secret.as_deref(),
            created_at: r.created_at,
            passkey: r.passkey.as_deref().map(String::as_str),
        }
    }
}

/// A record's journal JSON as read back. The passkey goes straight into a
/// zeroizing buffer.
///
/// The members are spelled out rather than flattened from [`PendingLogin`]:
/// serde buffers a flattened struct's input, which would leave an unzeroized
/// copy of the passkey behind.
#[derive(Deserialize)]
pub(crate) struct WireIn {
    record_id: String,
    op: PendingOp,
    #[serde(default)]
    item_id: Option<String>,
    title: String,
    url: String,
    identity_value: String,
    #[serde(default)]
    identity_hint: Option<String>,
    password: String,
    #[serde(default)]
    totp_secret: Option<String>,
    created_at: i64,
    #[serde(default, deserialize_with = "secret_text")]
    passkey: Option<Zeroizing<String>>,
}

fn secret_text<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<Zeroizing<String>>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.map(Zeroizing::new))
}

impl From<WireIn> for PendingRecord {
    fn from(wire: WireIn) -> Self {
        Self {
            record_id: wire.record_id,
            op: wire.op,
            item_id: wire.item_id,
            title: wire.title,
            url: wire.url,
            identity_value: wire.identity_value,
            identity_hint: wire.identity_hint,
            password: wire.password,
            totp_secret: wire.totp_secret,
            created_at: wire.created_at,
            passkey: wire.passkey,
        }
    }
}

/// The journal JSON of `record`.
pub(crate) fn encode(record: &PendingRecord) -> Result<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(&WireOut::from(record))
        .map(Zeroizing::new)
        .map_err(|e| WalletError::EncryptionError(format!("journal encode failed: {e}")))
}

/// The record in `json`, or `None` when it does not read as one.
pub(crate) fn decode(json: &[u8]) -> Option<PendingRecord> {
    serde_json::from_slice::<WireIn>(json).ok().map(PendingRecord::from)
}

impl std::fmt::Debug for PendingRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRecord")
            .field("record_id", &self.record_id)
            .field("op", &self.op)
            .field("item_id", &self.item_id)
            .field("title", &self.title)
            .field("url", &self.url)
            .field("identity_value", &self.identity_value)
            .field("identity_hint", &self.identity_hint)
            .field("password", &crate::utils::REDACTED)
            .field("totp_secret", &self.totp_secret.as_ref().map(|_| crate::utils::REDACTED))
            .field("created_at", &self.created_at)
            .field("passkey", &self.passkey.as_ref().map(|_| crate::utils::REDACTED))
            .finish()
    }
}

impl PendingRecord {
    /// A login a provider handed over as JSON (see [`PendingLogin`]). Never
    /// carries a passkey.
    pub fn from_login_json(json: &str) -> Result<Self> {
        serde_json::from_str::<PendingLogin>(json)
            .map(Self::from)
            .map_err(|e| WalletError::InvalidOperation(format!("not a staged login: {e}")))
    }

    /// A staged login: [`PendingOp::Create`] with no item, hint, TOTP secret or
    /// passkey. Set the public fields afterwards for anything else.
    pub fn new_login(
        record_id: impl Into<String>,
        title: impl Into<String>,
        url: impl Into<String>,
        identity_value: impl Into<String>,
        password: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            record_id: record_id.into(),
            op: PendingOp::Create,
            item_id: None,
            title: title.into(),
            url: url.into(),
            identity_value: identity_value.into(),
            identity_hint: None,
            password: password.into(),
            totp_secret: None,
            created_at,
            passkey: None,
        }
    }

    /// A staged passkey: [`PendingOp::CreatePasskey`] carrying `passkey`, for
    /// the site at `https://<rpId>` and the passkey's user name.
    pub fn new_passkey(
        record_id: impl Into<String>,
        title: impl Into<String>,
        passkey: &PasskeyRecord,
        created_at: i64,
    ) -> Result<Self> {
        let mut record = Self::new_login(
            record_id,
            title,
            format!("https://{}", passkey.rp_id),
            passkey.user_name.clone(),
            String::new(),
            created_at,
        );
        record.op = PendingOp::CreatePasskey;
        record.passkey = Some(passkey.to_field_value()?);
        Ok(record)
    }

    /// The staged passkey, parsed and validated. `None` when the record carries
    /// none, or one that does not read as a passkey.
    pub fn staged_passkey(&self) -> Option<PasskeyRecord> {
        self.passkey
            .as_deref()
            .and_then(|stored| PasskeyRecord::from_field_value(stored).ok())
    }

    /// The field type this record's identity value belongs in: the hint when it
    /// names a real identity type, the classifier otherwise.
    pub fn identity_kind(&self) -> super::identity::IdentityKind {
        self.identity_hint
            .as_deref()
            .and_then(super::identity::IdentityKind::from_field_type)
            .unwrap_or_else(|| super::identity::classify(&self.identity_value))
    }
}

/// Seal one record into its framed on-disk form, in the current format. The
/// provider appends the returned bytes verbatim.
///
/// `index_key` fills the provider's read-back wrap (on Android, the staging
/// key); `auth_key` is the journal auth key the drain verifies the tag with.
pub fn seal_record(
    record: &PendingRecord,
    journal_public: &[u8],
    index_key: &[u8; KEY_LEN],
    auth_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>> {
    let mut payload = seal_payload(record, journal_public, index_key, FORMAT_VERSION)?;
    let tag = record_tag(auth_key, &payload);
    payload.extend_from_slice(&tag);
    frame(&payload)
}

/// The unframed payload of one record, without a tag, in format `version`.
fn seal_payload(
    record: &PendingRecord,
    journal_public: &[u8],
    index_key: &[u8; KEY_LEN],
    version: u8,
) -> Result<Vec<u8>> {
    let json = encode(record)?;

    let record_key = crypto::random_key()?;

    // The app wrap carries its own ephemeral key, so it cannot be bound to a
    // header that contains that key. It is bound to the version instead; any
    // tampering with the ephemeral key makes the derivation fail regardless.
    let (eph_public, wrap_to_app) =
        crypto::ecies_seal(journal_public, record_key.as_slice(), &[version], ECIES_INFO)?;

    // Everything else is bound to version + ephemeral key.
    let header = header_bytes(version, &eph_public);
    let wrap_to_index = crypto::seal(index_key, record_key.as_slice(), &header)?;
    let body = crypto::seal(&record_key, &json, &header)?;

    let mut payload = Vec::new();
    payload.push(version);
    payload.push(u8::try_from(eph_public.len()).map_err(|_| too_long("ephemeral key"))?);
    payload.extend_from_slice(&eph_public);
    payload.extend_from_slice(&u16::try_from(wrap_to_app.len()).map_err(|_| too_long("app wrap"))?.to_le_bytes());
    payload.extend_from_slice(&wrap_to_app);
    payload.extend_from_slice(&u16::try_from(wrap_to_index.len()).map_err(|_| too_long("index wrap"))?.to_le_bytes());
    payload.extend_from_slice(&wrap_to_index);
    payload.extend_from_slice(&u32::try_from(body.len()).map_err(|_| too_long("body"))?.to_le_bytes());
    payload.extend_from_slice(&body);
    Ok(payload)
}

/// A record in the legacy format, with no tag, for tests of the recovery path.
#[cfg(test)]
pub(crate) fn seal_legacy_record(
    record: &PendingRecord,
    journal_public: &[u8],
    index_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>> {
    frame(&seal_payload(record, journal_public, index_key, LEGACY_FORMAT_VERSION)?)
}

/// Prefix `payload` with its u32 length.
fn frame(payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len().saturating_add(4));
    out.extend_from_slice(&u32::try_from(payload.len()).map_err(|_| too_long("record"))?.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn record_mac(auth_key: &[u8; KEY_LEN], signed: &[u8]) -> Hmac<Sha256> {
    // HMAC takes keys of any length, and a 32-byte key in particular.
    let mut mac = match <Hmac<Sha256> as KeyInit>::new_from_slice(auth_key) {
        Ok(mac) => mac,
        Err(_) => unreachable!("HMAC takes any key length"),
    };
    mac.update(MAC_CONTEXT);
    mac.update(signed);
    mac
}

/// The tag over `signed`, the payload bytes before the tag.
fn record_tag(auth_key: &[u8; KEY_LEN], signed: &[u8]) -> [u8; TAG_LEN] {
    record_mac(auth_key, signed).finalize().into_bytes().into()
}

/// Constant-time check of a record's tag.
fn tag_verifies(auth_key: &[u8; KEY_LEN], signed: &[u8], tag: &[u8]) -> bool {
    record_mac(auth_key, signed).verify_slice(tag).is_ok()
}

/// Keys the app drains with. See the module documentation for what each one
/// proves.
pub struct DrainKeys<'a> {
    /// The app-private P-256 secret that opens the app wrap.
    pub journal_secret: &'a [u8; 32],
    /// The journal auth key the provider tagged each record with.
    pub auth_key: &'a [u8; KEY_LEN],
    /// Recovery only: symmetric keys a format-1 record may be wrapped under
    /// (the index key, or Android's staging key, that the provider used). A
    /// format-1 record is applied only when its provider wrap opens under one
    /// of these. Empty refuses every format-1 record.
    pub legacy_wrap_keys: &'a [[u8; KEY_LEN]],
}

/// What the drain could read from a journal.
#[derive(Debug, Default)]
pub struct DrainRead {
    /// Records that proved who wrote them and opened, in file order.
    pub records: Vec<PendingRecord>,
    /// Well-framed records that were refused because they carry no valid tag
    /// (or, for format 1, no provider wrap under a supplied legacy key).
    pub unauthenticated: usize,
    /// Bytes at the end of the journal that could not be read as records: a
    /// torn write, and everything appended after it. Zero for a journal that
    /// read cleanly to its end. Nonzero means records may have been lost to
    /// this read, so the journal should be kept rather than deleted.
    pub unparsed_bytes: usize,
}

/// Open every record the drain may apply. This is the drain path, and it works
/// regardless of the state of the index key.
///
/// A format-2 record is applied only when its tag verifies under
/// `keys.auth_key`; the tag is checked before anything is unwrapped. A format-1
/// record is applied only when its provider wrap opens under one of
/// `keys.legacy_wrap_keys`. Everything else that is well framed is counted in
/// [`DrainRead::unauthenticated`].
pub fn open_for_drain(journal: &[u8], keys: &DrainKeys<'_>) -> DrainRead {
    let mut unauthenticated = 0usize;
    let (records, unparsed_bytes) = parse(journal, |parsed| {
        let key = match parsed.tag {
            Some(tag) => {
                if !tag_verifies(keys.auth_key, parsed.signed, tag) {
                    unauthenticated = unauthenticated.saturating_add(1);
                    return Err(unauthenticated_record());
                }
                let key = crypto::ecies_open(
                    keys.journal_secret,
                    parsed.eph_public,
                    parsed.wrap_to_app,
                    &[parsed.version],
                    ECIES_INFO,
                )?;
                into_key(key)?
            }
            None => {
                let header = header_bytes(parsed.version, parsed.eph_public);
                let opened = keys
                    .legacy_wrap_keys
                    .iter()
                    .find_map(|k| crypto::open(k, parsed.wrap_to_index, &header).ok());
                let Some(key) = opened else {
                    unauthenticated = unauthenticated.saturating_add(1);
                    return Err(unauthenticated_record());
                };
                into_key(key)?
            }
        };
        Ok(key)
    });
    DrainRead { records, unauthenticated, unparsed_bytes }
}

fn unauthenticated_record() -> WalletError {
    WalletError::DecryptionError("journal record is not authenticated".into())
}

/// Open every record the provider can read, using the shared index key. This is
/// the read-back path that lets a just-created login appear in the provider's
/// list before the app has ever drained it.
pub fn open_with_index_key(journal: &[u8], index_key: &[u8; KEY_LEN]) -> Vec<PendingRecord> {
    parse(journal, |parsed| {
        let header = header_bytes(parsed.version, parsed.eph_public);
        let key = crypto::open(index_key, parsed.wrap_to_index, &header)?;
        into_key(key)
    })
    .0
}

/// Count the framed records in a journal without opening any of them.
///
/// The provider needs this at save time, where it must decide whether the cap
/// has been reached but holds no key it is willing to use: on Android
/// `onSaveRequest` runs with no authentication at all. Walking the length
/// prefixes needs no key and reveals nothing beyond how many records are there,
/// which the provider is about to be told anyway.
///
/// Stops at the first truncated frame, matching what the readers do, so a torn
/// final write is not counted.
pub fn count_records(journal: &[u8]) -> usize {
    Frames::new(journal).count()
}

/// Iterator over the framed payloads of a journal.
///
/// Every offset is computed with checked arithmetic and every slice is taken
/// with `get`, so a hostile length prefix ends the walk instead of wrapping
/// around on a 32-bit target. A zero length, a length running past the end of
/// the data, or a length that does not fit the address space all end it.
struct Frames<'a> {
    rest: &'a [u8],
    /// Bytes of the frames returned so far, length prefixes included.
    consumed: usize,
}

impl<'a> Frames<'a> {
    fn new(journal: &'a [u8]) -> Self {
        Self { rest: journal, consumed: 0 }
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        // Taken up front, so every early return leaves the walk finished.
        let rest = std::mem::take(&mut self.rest);
        let (prefix, after) = rest.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_le_bytes(*prefix)).ok()?;
        if len == 0 {
            return None;
        }
        let (payload, rest) = after.split_at_checked(len)?;
        self.rest = rest;
        self.consumed = self.consumed.saturating_add(4).saturating_add(len);
        Some(payload)
    }
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

fn header_bytes(version: u8, eph_public: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(eph_public.len().saturating_add(1));
    header.push(version);
    header.extend_from_slice(eph_public);
    header
}

fn into_key(bytes: Vec<u8>) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let bytes = Zeroizing::new(bytes);
    <[u8; KEY_LEN]>::try_from(bytes.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| WalletError::DecryptionError("journal record key has the wrong length".into()))
}

fn too_long(what: &str) -> WalletError {
    WalletError::EncryptionError(format!("journal {what} is too long to frame"))
}

struct ParsedRecord<'a> {
    version: u8,
    /// The payload bytes the tag covers: everything before it.
    signed: &'a [u8],
    /// The tag, for format 2; `None` for a format-1 record.
    tag: Option<&'a [u8]>,
    eph_public: &'a [u8],
    wrap_to_app: &'a [u8],
    wrap_to_index: &'a [u8],
    body: &'a [u8],
}

/// Walk the framed stream, unwrapping each record with `unwrap_key`.
///
/// Stops at the first structurally malformed record and returns everything
/// parsed so far, with the number of bytes from that point to the end. A record that is well-framed but fails to open (wrong key,
/// tampering) is skipped while parsing continues, so one bad record cannot hide
/// the ones after it.
fn parse<F>(journal: &[u8], mut unwrap_key: F) -> (Vec<PendingRecord>, usize)
where
    F: FnMut(&ParsedRecord<'_>) -> Result<Zeroizing<[u8; KEY_LEN]>>,
{
    let mut out = Vec::new();
    let mut frames = Frames::new(journal);
    let mut read_up_to = 0usize;

    while let Some(payload) = frames.next() {
        let Some(parsed) = split_payload(payload) else {
            break; // structurally broken, cannot trust anything past here
        };
        read_up_to = frames.consumed;
        let Ok(key) = unwrap_key(&parsed) else {
            continue; // not ours to read, or tampered; later records may be fine
        };
        let header = header_bytes(parsed.version, parsed.eph_public);
        let Ok(json) = crypto::open(&key, parsed.body, &header).map(Zeroizing::new) else {
            continue;
        };
        if let Some(record) = decode(&json) {
            out.push(record);
        }
    }

    (out, journal.len().saturating_sub(read_up_to))
}

fn split_payload(payload: &[u8]) -> Option<ParsedRecord<'_>> {
    let mut reader = Reader(payload);
    let version = reader.byte()?;
    if version != FORMAT_VERSION && version != LEGACY_FORMAT_VERSION {
        return None;
    }

    let eph_len = usize::from(reader.byte()?);
    let eph_public = reader.take(eph_len)?;

    let wrap_app_len = reader.u16()?;
    let wrap_to_app = reader.take(wrap_app_len)?;

    let wrap_idx_len = reader.u16()?;
    let wrap_to_index = reader.take(wrap_idx_len)?;

    let body_len = reader.u32()?;
    let body = reader.take(body_len)?;

    // Format 2 ends with exactly one tag; format 1 ends at the body (anything
    // after it was never read, and still is not).
    let signed_len = payload.len().checked_sub(reader.0.len())?;
    let signed = payload.get(..signed_len)?;
    let tag = if version == FORMAT_VERSION {
        let tag = reader.take(TAG_LEN)?;
        if !reader.0.is_empty() {
            return None;
        }
        Some(tag)
    } else {
        None
    };

    Some(ParsedRecord {
        version,
        signed,
        tag,
        eph_public,
        wrap_to_app,
        wrap_to_index,
        body,
    })
}

/// Forward-only reader over a record payload. Every read is bounds-checked and
/// returns `None` past the end, never panics.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(len)?;
        self.0 = tail;
        Some(head)
    }

    fn byte(&mut self) -> Option<u8> {
        let (&b, tail) = self.0.split_first()?;
        self.0 = tail;
        Some(b)
    }

    fn u16(&mut self) -> Option<usize> {
        let (bytes, tail) = self.0.split_first_chunk::<2>()?;
        self.0 = tail;
        Some(usize::from(u16::from_le_bytes(*bytes)))
    }

    fn u32(&mut self) -> Option<usize> {
        let (bytes, tail) = self.0.split_first_chunk::<4>()?;
        self.0 = tail;
        usize::try_from(u32::from_le_bytes(*bytes)).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::super::identity::IdentityKind;
    use super::super::keys::generate_keys;
    use super::*;

    /// The drain path with no legacy keys: what the app applies.
    fn open_app(journal: &[u8], secret: &[u8; 32], auth: &[u8; KEY_LEN]) -> Vec<PendingRecord> {
        open_for_drain(journal, &DrainKeys { journal_secret: secret, auth_key: auth, legacy_wrap_keys: &[] }).records
    }

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
            passkey: None,
        }
    }

    #[test]
    fn both_wraps_open_to_identical_plaintext() {
        let keys = generate_keys().unwrap();
        let original = record("r1");
        let sealed = seal_record(&original, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();

        let via_app = open_app(&sealed, &keys.journal_secret, &keys.journal_auth_key);
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
        let sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();

        // The provider has lost read-back...
        assert!(open_with_index_key(&sealed, &rotated.index_key).is_empty());
        // ...but nothing is lost, because the app never needed that key.
        assert_eq!(open_app(&sealed, &keys.journal_secret, &keys.journal_auth_key).len(), 1);
    }

    /// A damaged provider wrap costs read-back, and the drain refuses the
    /// record too: the tag covers the wrap, so the record is no longer the one
    /// the provider wrote. (A rotated index key, by contrast, costs the drain
    /// nothing; see the test above.)
    #[test]
    fn corrupting_only_the_index_wrap_is_detected_on_both_paths() {
        let keys = generate_keys().unwrap();
        let mut sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();

        // Locate the index wrap exactly, rather than guessing an offset.
        let (eph_len, wrap_app_len) = {
            let parsed = split_payload(&sealed[4..]).unwrap();
            (parsed.eph_public.len(), parsed.wrap_to_app.len())
        };
        let target = 4 + 1 + 1 + eph_len + 2 + wrap_app_len + 2;
        sealed[target] ^= 0xff;

        assert!(open_with_index_key(&sealed, &keys.index_key).is_empty());
        let read = open_for_drain(&sealed, &drain_keys(&keys, &[]));
        assert!(read.records.is_empty());
        assert_eq!(read.unauthenticated, 1);
    }

    #[test]
    fn the_public_key_alone_cannot_open_a_record() {
        let keys = generate_keys().unwrap();
        let sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();

        // Treating the public key bytes as if they were a secret scalar must
        // not yield anything.
        let mut fake_secret = [0u8; 32];
        fake_secret.copy_from_slice(&keys.journal_public[1..33]);
        assert!(open_app(&sealed, &fake_secret, &keys.journal_auth_key).is_empty());
    }

    #[test]
    fn keys_from_another_enable_cycle_open_nothing() {
        let keys = generate_keys().unwrap();
        let other = generate_keys().unwrap();
        let sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();

        assert!(open_app(&sealed, &other.journal_secret, &other.journal_auth_key).is_empty());
        assert!(open_with_index_key(&sealed, &other.index_key).is_empty());
    }

    #[test]
    fn records_are_independent_under_truncation_at_every_offset() {
        let keys = generate_keys().unwrap();
        let mut journal = Vec::new();
        let first = seal_record(&record("r1"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();
        let second = seal_record(&record("r2"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();
        journal.extend_from_slice(&first);
        journal.extend_from_slice(&second);

        // Cut anywhere inside the second record: the first must always survive.
        for cut in first.len()..journal.len() {
            let opened = open_app(&journal[..cut], &keys.journal_secret, &keys.journal_auth_key);
            assert_eq!(opened.len(), 1, "truncated at {cut}");
            assert_eq!(opened[0].record_id, "r1");
        }
        // Intact, both are readable.
        assert_eq!(open_app(&journal, &keys.journal_secret, &keys.journal_auth_key).len(), 2);
    }

    #[test]
    fn an_unreadable_record_does_not_hide_the_ones_after_it() {
        let keys = generate_keys().unwrap();
        let other = generate_keys().unwrap();
        let mut journal = Vec::new();
        // Sealed to a different app key: well-framed, but not ours to open.
        journal.extend_from_slice(
            &seal_record(&record("foreign"), &other.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap(),
        );
        journal.extend_from_slice(
            &seal_record(&record("ours"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap(),
        );

        let opened = open_app(&journal, &keys.journal_secret, &keys.journal_auth_key);
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
            assert!(open_app(&junk, &keys.journal_secret, &keys.journal_auth_key).is_empty());
            assert!(open_with_index_key(&junk, &keys.index_key).is_empty());
        }
    }

    #[test]
    fn an_unknown_format_version_is_refused() {
        let keys = generate_keys().unwrap();
        let mut sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();
        sealed[4] = 99; // version byte, straight after the u32 frame length
        assert!(open_app(&sealed, &keys.journal_secret, &keys.journal_auth_key).is_empty());
    }

    #[test]
    fn staged_records_are_never_filtered_by_age() {
        let keys = generate_keys().unwrap();
        let mut ancient = record("old");
        ancient.created_at = 0; // 1970
        let sealed = seal_record(&ancient, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();

        assert_eq!(open_app(&sealed, &keys.journal_secret, &keys.journal_auth_key).len(), 1);
        assert_eq!(open_with_index_key(&sealed, &keys.index_key).len(), 1);
    }

    // ---- integrity ----------------------------------------------------------

    fn drain_keys<'a>(keys: &'a crate::autofill::AutofillKeys, legacy: &'a [[u8; KEY_LEN]]) -> DrainKeys<'a> {
        DrainKeys { journal_secret: &keys.journal_secret, auth_key: &keys.journal_auth_key, legacy_wrap_keys: legacy }
    }

    /// A record tagged under any key but the journal auth key is not applied.
    #[test]
    fn a_record_without_the_auth_key_is_refused_and_counted() {
        let keys = generate_keys().unwrap();
        let unrelated = generate_keys().unwrap();
        let untagged = seal_record(&record("other"), &keys.journal_public, &unrelated.index_key, &unrelated.journal_auth_key)
            .unwrap();
        let genuine = seal_record(&record("genuine"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();
        let mut journal = untagged.clone();
        journal.extend_from_slice(&genuine);

        let read = open_for_drain(&journal, &drain_keys(&keys, &[]));
        assert_eq!(read.unauthenticated, 1);
        let ids: Vec<_> = read.records.iter().map(|r| r.record_id.as_str()).collect();
        assert_eq!(ids, vec!["genuine"], "the refused record does not hide the next one");
    }

    #[test]
    fn every_byte_of_a_record_is_covered_by_the_tag() {
        let keys = generate_keys().unwrap();
        let sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();
        // Skip the outer length: changing it breaks framing, not the tag.
        for byte in 5..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[byte] ^= 0x01;
            let read = open_for_drain(&tampered, &drain_keys(&keys, &[]));
            assert!(read.records.is_empty(), "byte {byte}");
            // Inner lengths may now be malformed (not counted); otherwise
            // the tag must be what refused it.
            if split_payload(&tampered[4..]).is_some() {
                assert_eq!(read.unauthenticated, 1, "byte {byte}");
            }
        }
    }

    #[test]
    fn a_tagged_record_must_end_exactly_at_its_tag() {
        let keys = generate_keys().unwrap();
        let sealed = seal_record(&record("r1"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();
        let payload = &sealed[4..];
        assert!(split_payload(payload).is_some());
        let mut longer = payload.to_vec();
        longer.push(0);
        assert!(split_payload(&longer).is_none(), "trailing byte after the tag");
        assert!(split_payload(&payload[..payload.len() - 1]).is_none(), "tag one byte short");
    }

    #[test]
    fn a_tag_does_not_open_a_record_meant_for_another_app_key() {
        let keys = generate_keys().unwrap();
        let other = generate_keys().unwrap();
        let sealed = seal_record(&record("r1"), &other.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();
        let read = open_for_drain(&sealed, &drain_keys(&keys, &[]));
        assert!(read.records.is_empty());
        assert_eq!(read.unauthenticated, 0, "authentic, just not ours to open");
    }

    #[test]
    fn legacy_records_drain_only_through_a_supplied_wrap_key() {
        let keys = generate_keys().unwrap();
        let other = generate_keys().unwrap();
        let legacy = seal_legacy_record(&record("old"), &keys.journal_public, &keys.index_key).unwrap();
        assert_eq!(legacy[4], LEGACY_FORMAT_VERSION);

        let refused = open_for_drain(&legacy, &drain_keys(&keys, &[]));
        assert!(refused.records.is_empty());
        assert_eq!(refused.unauthenticated, 1);

        let wrong = [*other.index_key];
        let refused = open_for_drain(&legacy, &drain_keys(&keys, &wrong));
        assert!(refused.records.is_empty());
        assert_eq!(refused.unauthenticated, 1);

        let right = [*other.index_key, *keys.index_key];
        let read = open_for_drain(&legacy, &drain_keys(&keys, &right));
        assert_eq!(read.records, vec![record("old")]);
        assert_eq!(read.unauthenticated, 0);
    }

    #[test]
    fn read_back_opens_both_formats() {
        let keys = generate_keys().unwrap();
        let mut journal = seal_legacy_record(&record("old"), &keys.journal_public, &keys.index_key).unwrap();
        journal.extend_from_slice(
            &seal_record(&record("new"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap(),
        );
        let ids: Vec<_> = open_with_index_key(&journal, &keys.index_key).into_iter().map(|r| r.record_id).collect();
        assert_eq!(ids, vec!["old", "new"]);
        assert_eq!(count_records(&journal), 2);
    }

    #[test]
    fn the_tag_is_hmac_sha256_over_the_context_and_the_payload() {
        // Pinned so other implementations (the Swift extension) can match it.
        let key = [0x42u8; KEY_LEN];
        let tag = record_tag(&key, b"payload");
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
        mac.update(b"iwcore/autofill/journal/v2/mac");
        mac.update(b"payload");
        assert_eq!(tag.as_slice(), mac.finalize().into_bytes().as_slice());
        assert!(tag_verifies(&key, b"payload", &tag));
        assert!(!tag_verifies(&key, b"payload", &tag[..TAG_LEN - 1]));
        assert!(!tag_verifies(&[0x43; KEY_LEN], b"payload", &tag));
    }

    #[test]
    fn a_staged_passkey_is_redacted_and_keeps_its_wire_form() {
        let passkey = crate::passkey::record::tests::sample(true);
        let key_b64 = crate::passkey::b64::encode(passkey.pkcs8());
        let r = PendingRecord::new_passkey("p1", "Example", &passkey, 5).unwrap();
        assert_eq!(r.op, PendingOp::CreatePasskey);
        assert_eq!(r.url, format!("https://{}", passkey.rp_id));
        assert_eq!(r.identity_value, passkey.user_name);
        assert!(r.password.is_empty());
        assert!(!format!("{r:?}").contains(&key_b64), "Debug must not show the key");

        // On disk the passkey is the stored PKEY value as a JSON string, as
        // the Swift extension and earlier builds write it.
        let bytes = encode(&r).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["passkey"].as_str(), Some(passkey.to_field_value().unwrap().as_str()));
        let back = decode(&bytes).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.staged_passkey().unwrap().credential_id, passkey.credential_id);

        let login = PendingRecord::new_login("l1", "Example", "https://example.com", "bkv", "pw", 5);
        assert_eq!(login.op, PendingOp::Create);
        assert!(login.staged_passkey().is_none());
        let json: serde_json::Value = serde_json::from_slice(&encode(&login).unwrap()).unwrap();
        assert!(json.get("passkey").is_none());
    }

    #[test]
    fn a_login_from_json_never_carries_a_passkey() {
        let passkey = crate::passkey::record::tests::sample(true);
        let staged = PendingRecord::new_passkey("p1", "Example", &passkey, 5).unwrap();
        // Even the full journal JSON of a staged passkey loses its passkey.
        let json = String::from_utf8(encode(&staged).unwrap().to_vec()).unwrap();
        let login = PendingRecord::from_login_json(&json).unwrap();
        assert!(login.passkey.is_none() && login.staged_passkey().is_none());
        assert_eq!((login.record_id.as_str(), login.op, login.created_at), ("p1", PendingOp::CreatePasskey, 5));

        let full = r#"{"record_id":"r1","op":"UpdatePassword","item_id":"it","title":"T","url":"https://e.com",
            "identity_value":"bkv","identity_hint":"MAIL","password":"pw","totp_secret":"JBSW","created_at":7}"#;
        let r = PendingRecord::from_login_json(full).unwrap();
        assert_eq!(r.op, PendingOp::UpdatePassword);
        assert_eq!(r.item_id.as_deref(), Some("it"));
        assert_eq!(r.identity_hint.as_deref(), Some("MAIL"));
        assert_eq!(r.totp_secret.as_deref(), Some("JBSW"));
        // It round-trips through the journal unchanged.
        assert_eq!(decode(&encode(&r).unwrap()).unwrap(), r);

        let minimal = r#"{"record_id":"r2","op":"Create","title":"T","url":"u","identity_value":"v","password":"p-secret-9","created_at":1}"#;
        let m = PendingRecord::from_login_json(minimal).unwrap();
        assert_eq!(m, PendingRecord::new_login("r2", "T", "u", "v", "p-secret-9", 1));
        assert!(PendingRecord::from_login_json("{}").is_err());
        assert!(PendingRecord::from_login_json("not json").is_err());

        let parsed: PendingLogin = serde_json::from_str(minimal).unwrap();
        let shown = format!("{parsed:?}");
        assert!(!shown.contains("p-secret-9"), "Debug redacts the password");
        assert!(shown.starts_with("PendingLogin"), "{shown}");
        assert!(shown.contains("\"r2\"") && shown.contains("created_at: 1"), "{shown}");
    }

    #[test]
    fn the_drain_reports_what_it_could_not_read() {
        let keys = generate_keys().unwrap();
        let dk = DrainKeys { journal_secret: &keys.journal_secret, auth_key: &keys.journal_auth_key, legacy_wrap_keys: &[] };
        let seal = |id: &str| seal_record(&record(id), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();

        let clean = [seal("a"), seal("b")].concat();
        let read = open_for_drain(&clean, &dk);
        assert_eq!((read.records.len(), read.unparsed_bytes), (2, 0));
        assert_eq!(open_for_drain(&[], &dk).unparsed_bytes, 0);

        // A torn write, then a later append: the later record is lost to the
        // reader, and the drain says how much it could not read.
        let first = seal("a");
        let torn = seal("torn");
        let torn = &torn[..torn.len() / 2];
        let later = seal("c");
        let journal = [first.clone(), torn.to_vec(), later.clone()].concat();
        let read = open_for_drain(&journal, &dk);
        assert_eq!(read.records.iter().map(|r| r.record_id.as_str()).collect::<Vec<_>>(), vec!["a"]);
        // The torn frame's length runs into the later record, which then no
        // longer frames: some of the journal is left unread, and reported.
        assert!(read.unparsed_bytes > 0 && read.unparsed_bytes < torn.len() + later.len(), "{}", read.unparsed_bytes);
        assert_eq!(read.unauthenticated, 1, "the misaligned frame does not verify");

        // A torn final write only.
        let journal = [first.clone(), torn.to_vec()].concat();
        assert_eq!(open_for_drain(&journal, &dk).unparsed_bytes, torn.len());

        // A well-framed record that does not open is read, not unparsed.
        let other = generate_keys().unwrap();
        let foreign = seal_record(&record("x"), &other.journal_public, &other.index_key, &other.journal_auth_key).unwrap();
        let read = open_for_drain(&[foreign, first].concat(), &dk);
        assert_eq!((read.records.len(), read.unauthenticated, read.unparsed_bytes), (1, 1, 0));
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

    #[test]
    fn reader_reads_each_width_at_the_offset_and_stops_one_byte_short() {
        for at in 0..6 {
            let mut buf = vec![0xaa; at];
            buf.extend_from_slice(&0x1234u16.to_le_bytes());
            let mut r = Reader(&buf);
            assert!(r.take(at).is_some());
            assert_eq!(r.u16(), Some(0x1234), "offset {at}");
            assert_eq!(r.byte(), None, "nothing left");

            let short = &buf[..buf.len() - 1];
            let mut r = Reader(short);
            r.take(at).unwrap();
            assert_eq!(r.u16(), None, "offset {at}, one byte short");
        }
        let mut r = Reader(&[1, 0, 0]);
        assert_eq!(r.u32(), None, "three bytes are not a u32");
        let mut r = Reader(&[1, 0, 0, 0]);
        assert_eq!(r.u32(), Some(1));
        assert_eq!(Reader(&[1, 2]).take(3), None);
    }

    /// Length prefixes that would wrap a 32-bit `usize` when added to the
    /// cursor. The readers must stop, never loop and never panic, whatever the
    /// pointer width.
    #[test]
    fn hostile_frame_lengths_end_the_walk() {
        let keys = generate_keys().unwrap();
        let valid = seal_record(&record("r1"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();

        let mut cases: Vec<Vec<u8>> = vec![
            vec![0xfc, 0xff, 0xff, 0xff],
            vec![0xff, 0xff, 0xff, 0xff],
            vec![0xfc, 0xff, 0xff, 0xff, 0, 0, 0, 0],
            vec![0x00, 0x00, 0x00, 0x00, 0x01],
            vec![0x05, 0x00, 0x00, 0x00, 0x01, 0x02],
            vec![0x01, 0x00, 0x00],
        ];
        // A valid record followed by each hostile tail: the record survives,
        // the tail is ignored.
        for tail in cases.clone() {
            let mut j = valid.clone();
            j.extend_from_slice(&tail);
            cases.push(j);
        }

        for journal in &cases {
            let starts_valid = journal.starts_with(&valid);
            let expected = usize::from(starts_valid);
            assert_eq!(count_records(journal), expected, "{journal:02x?}");
            assert_eq!(open_app(journal, &keys.journal_secret, &keys.journal_auth_key).len(), expected);
            assert_eq!(open_with_index_key(journal, &keys.index_key).len(), expected);
        }
    }

    /// Inner lengths that point past the payload, up to the maximum each
    /// width can hold, are refused as malformed.
    #[test]
    fn hostile_inner_lengths_are_refused() {
        let payloads: Vec<Vec<u8>> = vec![
            // eph_len past the end
            vec![FORMAT_VERSION, 0xff],
            // wrap_to_app length past the end
            vec![FORMAT_VERSION, 0, 0xff, 0xff],
            // wrap_to_index length past the end
            vec![FORMAT_VERSION, 0, 0, 0, 0xff, 0xff],
            // body length at the u32 maximum
            vec![FORMAT_VERSION, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
            // body length field cut short
            vec![FORMAT_VERSION, 0, 0, 0, 0, 0, 0xff],
            // version only
            vec![FORMAT_VERSION],
        ];

        for payload in payloads {
            assert!(split_payload(&payload).is_none(), "{payload:02x?}");
            let mut framed = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
            framed.extend_from_slice(&payload);
            assert_eq!(count_records(&framed), 1, "framing itself is fine");
            let keys = generate_keys().unwrap();
            assert!(open_app(&framed, &keys.journal_secret, &keys.journal_auth_key).is_empty());
        }
        // The smallest structurally complete payloads: every length zero, and
        // for the current format a tag.
        let mut tagged = vec![FORMAT_VERSION, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        tagged.extend_from_slice(&[0u8; TAG_LEN]);
        assert!(split_payload(&tagged).is_some());
        assert!(split_payload(&[LEGACY_FORMAT_VERSION, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_some());
        assert!(split_payload(&tagged[..10]).is_none(), "format 2 without its tag");
    }

    #[test]
    fn a_record_key_of_the_wrong_length_is_refused() {
        assert!(into_key(vec![0u8; KEY_LEN - 1]).is_err());
        assert!(into_key(vec![0u8; KEY_LEN + 1]).is_err());
        assert_eq!(*into_key(vec![7u8; KEY_LEN]).unwrap(), [7u8; KEY_LEN]);
    }

    #[test]
    fn records_are_counted_without_a_key() {
        let keys = generate_keys().unwrap();
        let mut journal = Vec::new();
        assert_eq!(count_records(&journal), 0);

        for i in 0..3 {
            let sealed = seal_record(
                &record(&format!("r{i}")),
                &keys.journal_public,
                &keys.index_key, &keys.journal_auth_key)
            .unwrap();
            journal.extend_from_slice(&sealed);
            assert_eq!(count_records(&journal), i + 1);
        }

        // A torn final write is not counted, matching what the readers do.
        let whole = count_records(&journal);
        journal.truncate(journal.len() - 8);
        assert_eq!(count_records(&journal), whole - 1);

        assert_eq!(count_records(b"not a journal at all"), 0);
    }
}
