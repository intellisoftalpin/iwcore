//! CXF → IntelliWallet.
//!
//! Two steps, so the user sees exactly what will happen before anything is
//! written:
//!
//! 1. [`Wallet::preview_cxf`] parses and maps the payload and compares it with
//!    the vault: counts per kind, duplicates, new custom field labels, and every
//!    skipped credential with its reason. It writes nothing.
//! 2. [`Wallet::import_cxf`] takes an automatic backup, then writes the same
//!    plan in **one transaction**. Existing items are never modified: imports
//!    land in a new folder per account, named after the exporter.
//!
//! Passkeys are never replaced by an import: a passkey whose credential id or
//! whose account (rpId + user handle) the vault already holds is skipped, and
//! so is a second copy of the same credential id inside the payload. Each is
//! listed with its reason.
//!
//! Mapping rule: a value goes into an IntelliWallet system field only when the
//! meaning is exact; anything else becomes a clearly named custom field, so
//! nothing is dropped silently. Credentials that cannot be stored at all
//! (attachments, references, unknown types, unusable passkeys) are listed as
//! skipped with the reason.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use super::de::{Cred, Ef};
use super::text::{self, Totp};
use super::{parse, Header, Item, FIELDS_MAX, NEW_LABELS_MAX, SKIPPED_LISTED_MAX};
use crate::autofill::identity;
use crate::business::Wallet;
use crate::error::{Result, WalletError};
use crate::passkey::{PasskeyRecord, FIELD_PASSKEY};

/// Where the automatic pre-import backup goes.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    pub backup_folder: PathBuf,
}

/// Credentials per kind, as the preview shows them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KindCounts {
    pub logins: usize,
    pub passkeys: usize,
    pub totp: usize,
    pub notes: usize,
    pub cards: usize,
    pub wifi: usize,
    /// Addresses, names, ID documents, API and SSH keys, custom fields.
    pub other: usize,
}

/// One credential that will not be imported, and why. Never carries a value.
///
/// A preview lists at most [`SKIPPED_LISTED_MAX`] of them; when there are more,
/// one last entry with an empty title and type gives the number not listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub item_title: String,
    pub credential_type: String,
    pub reason: String,
}

/// What an import will do (from [`Wallet::preview_cxf`]) or did (inside an
/// [`ImportReport`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportPreview {
    /// Who exported it, as the payload says.
    pub exporter: String,
    /// Names of the folders the import creates at the top level.
    pub destination_folders: Vec<String>,
    /// Items that will be added.
    pub items: usize,
    /// Items left out because the vault already holds the same content.
    pub duplicates: usize,
    pub counts: KindCounts,
    /// Custom field labels that will be created.
    pub new_labels: Vec<String>,
    pub skipped: Vec<Skipped>,
}

/// The outcome of [`Wallet::import_cxf`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReport {
    pub preview: ImportPreview,
    /// Top-level folders created, one per account.
    pub folder_ids: Vec<String>,
    /// Items created.
    pub item_ids: Vec<String>,
    /// The backup taken before anything was written.
    pub backup_path: PathBuf,
}

// --- the plan ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Kind {
    System(&'static str),
    Custom { name: String, value_type: &'static str },
}

struct PlannedField {
    kind: Kind,
    value: Zeroizing<String>,
    /// Who the passkey is for, for a passkey.
    passkey: Option<PasskeyKey>,
}

/// What identifies a passkey: its credential id, and the account it signs in
/// to (rpId + user handle).
struct PasskeyKey {
    id: Vec<u8>,
    rp_id: String,
    user_handle: Vec<u8>,
}

struct PlannedItem {
    title: String,
    folder: usize,
    fields: Vec<PlannedField>,
}

struct PlannedFolder {
    name: String,
    parent: Option<usize>,
}

/// Skipped credentials: the first [`SKIPPED_LISTED_MAX`] one by one, the rest
/// only counted.
#[derive(Clone, Default)]
struct SkipList {
    listed: Vec<Skipped>,
    more: usize,
}

impl SkipList {
    fn push(&mut self, item_title: &str, credential_type: &str, reason: &str) {
        if self.listed.len() < SKIPPED_LISTED_MAX {
            self.listed.push(Skipped {
                item_title: item_title.to_string(),
                credential_type: credential_type.to_string(),
                reason: reason.to_string(),
            });
        } else {
            self.more = self.more.saturating_add(1);
        }
    }

    fn into_vec(self) -> Vec<Skipped> {
        let mut out = self.listed;
        if self.more > 0 {
            out.push(Skipped {
                item_title: String::new(),
                credential_type: String::new(),
                reason: format!("{} more not listed", self.more),
            });
        }
        out
    }
}

struct Plan {
    exporter: String,
    folders: Vec<PlannedFolder>,
    items: Vec<PlannedItem>,
    counts: KindCounts,
    skipped: SkipList,
}

fn plan(header: &Header<'_>) -> Result<Plan> {
    let date = chrono::DateTime::from_timestamp(header.timestamp as i64, 0)
        .filter(|_| header.timestamp > 0)
        .unwrap_or_else(chrono::Utc::now)
        .format("%Y-%m-%d")
        .to_string();
    let mut p = Plan {
        exporter: header.exporter_display_name.clone(),
        folders: Vec::new(),
        items: Vec::new(),
        counts: KindCounts::default(),
        skipped: SkipList::default(),
    };
    let mut fields_total = 0usize;
    let several = header.accounts.len() > 1;
    for (n, account) in header.accounts.iter().enumerate() {
        let mut name = format!("Imported from {} {}", header.exporter_display_name, date);
        if several {
            let who = [&account.username, &account.email].into_iter().find(|s| !s.is_empty());
            name.push_str(&format!(" ({})", who.cloned().unwrap_or_else(|| format!("account {}", n.saturating_add(1)))));
        }
        let top = p.folders.len();
        p.folders.push(PlannedFolder { name, parent: None });

        // An item linked from several collections lands in the first.
        let mut placement: HashMap<&str, usize> = HashMap::new();
        fn walk<'a>(c: &'a super::Collection<'_>, parent: usize, p: &mut Plan, placement: &mut HashMap<&'a str, usize>) {
            let idx = p.folders.len();
            p.folders.push(PlannedFolder { name: c.title.clone(), parent: Some(parent) });
            for id in &c.items {
                placement.entry(id.as_ref()).or_insert(idx);
            }
            for s in &c.sub {
                walk(s, idx, p, placement);
            }
        }
        for c in &account.collections {
            walk(c, top, &mut p, &mut placement);
        }

        for item in &account.items {
            let folder = placement.get(item.id.as_ref()).copied().unwrap_or(top);
            let fields = map_item(item, &mut p.counts, &mut p.skipped);
            fields_total = fields_total.saturating_add(fields.len());
            if fields_total > FIELDS_MAX {
                return Err(WalletError::InvalidInput("import would create more than 500 000 fields".into()));
            }
            p.items.push(PlannedItem {
                title: if item.title.is_empty() { "Untitled".into() } else { item.title.clone() },
                folder,
                fields,
            });
        }
    }
    Ok(p)
}

/// The text of an editable field (`{"fieldType": ..., "value": ...}`).
fn ef(cred: &Cred, key: &str) -> Option<String> {
    ef_text(cred.ef(key)?)
}

fn ef_text(e: &Ef) -> Option<String> {
    // Values may span lines (an address, a recovery sheet); names never do.
    let v = text::clean(e.value.as_deref()?, text::VALUE_MAX, true);
    (!v.trim().is_empty()).then_some(v)
}

fn system(code: &'static str, value: String) -> PlannedField {
    PlannedField { kind: Kind::System(code), value: Zeroizing::new(value), passkey: None }
}

fn custom(name: &str, value_type: &'static str, value: String) -> PlannedField {
    PlannedField {
        kind: Kind::Custom { name: text::name(name), value_type },
        value: Zeroizing::new(value),
        passkey: None,
    }
}

/// Count one more credential of a kind.
fn bump(count: &mut usize) {
    *count = count.saturating_add(1);
}

/// Sort weight of the field at `index` within its item: 0, 100, 200, …,
/// held at `i32::MAX` past the range.
fn field_weight(index: usize) -> i32 {
    i32::try_from(index).unwrap_or(i32::MAX).saturating_mul(100)
}

fn skip(item: &Item<'_>, ty: &str, reason: &str, out: &mut SkipList) {
    out.push(&item.title, ty, reason);
}

/// Human label for a CXF member name: `issuingAuthority` → `Issuing authority`.
fn humanise(member: &str) -> String {
    let mut out = String::new();
    for (i, c) in member.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push(' ');
            out.push(c.to_ascii_lowercase());
        } else if i == 0 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn map_item(item: &Item<'_>, counts: &mut KindCounts, skipped: &mut SkipList) -> Vec<PlannedField> {
    let mut f: Vec<PlannedField> = Vec::new();
    for url in &item.urls {
        let url = text::clean(url, text::VALUE_MAX, false);
        if !url.trim().is_empty() {
            f.push(system("LINK", url));
        }
    }

    for raw in &item.credentials {
        // One credential at a time: only what this mapping reads is kept.
        let cred = &Cred::read(raw);
        let ty = cred.str("type").unwrap_or("");
        match ty {
            "basic-auth" => {
                bump(&mut counts.logins);
                if let Some(user) = ef(cred, "username") {
                    f.push(system(identity::classify(&user).field_type(), user));
                }
                if let Some(pass) = ef(cred, "password") {
                    f.push(system("PASS", pass));
                }
            }
            "passkey" => match passkey_field(cred, item) {
                Ok(pf) => {
                    bump(&mut counts.passkeys);
                    f.push(pf);
                }
                Err(reason) => skip(item, ty, &reason, skipped),
            },
            "totp" => {
                let algorithm = cred.str("algorithm").unwrap_or("sha1").to_ascii_uppercase();
                let secret = cred.str("secret").and_then(text::base32_secret);
                match (secret, ["SHA1", "SHA256", "SHA512"].contains(&algorithm.as_str())) {
                    (Some(secret), true) => {
                        bump(&mut counts.totp);
                        let t = Totp {
                            secret,
                            algorithm,
                            digits: cred.u64("digits").filter(|d| (4..=10).contains(d)).unwrap_or(6) as u32,
                            period: cred.u64("period").filter(|p| (1..=86_400).contains(p)).unwrap_or(30) as u32,
                            issuer: cred.str("issuer").map(text::name).filter(|s| !s.is_empty()),
                            account: cred.str("username").map(text::name).filter(|s| !s.is_empty()),
                        };
                        f.push(system("2FAC", text::totp_value(&t)));
                    }
                    (None, _) => skip(item, ty, "the secret is not Base32", skipped),
                    (_, false) => skip(item, ty, "unknown hash algorithm", skipped),
                }
            }
            "note" => {
                if let Some(content) = cred.ef("content").and_then(|c| c.value.as_deref()) {
                    bump(&mut counts.notes);
                    f.push(system("NOTE", text::clean(content, text::NOTE_MAX, true)));
                }
            }
            "credit-card" => {
                bump(&mut counts.cards);
                for (member, code) in [("number", "CARD"), ("fullName", "NAME"), ("verificationNumber", "CVVC"), ("pin", "PINC")] {
                    if let Some(v) = ef(cred, member) {
                        f.push(system(code, v));
                    }
                }
                if let Some(exp) = ef(cred, "expiryDate") {
                    match text::year_month_to_last_day(&exp) {
                        Some(d) => f.push(system("EXPD", d)),
                        None => f.push(custom("Expiry date", "text", exp)),
                    }
                }
                for (member, label) in [("cardType", "Card type"), ("validFrom", "Valid from")] {
                    if let Some(v) = ef(cred, member) {
                        f.push(custom(label, "text", v));
                    }
                }
            }
            "wifi" => {
                bump(&mut counts.wifi);
                let sec = match ef(cred, "networkSecurityType").as_deref() {
                    Some("unsecured") => "nopass",
                    Some("wep") => "WEP",
                    _ => "WPA",
                };
                let hidden = ef(cred, "hidden").is_some_and(|h| h == "true");
                f.push(system(
                    "WIFI",
                    text::wifi_value(&ef(cred, "ssid").unwrap_or_default(), sec, &ef(cred, "passphrase").unwrap_or_default(), hidden),
                ));
            }
            "address" => {
                bump(&mut counts.other);
                let city_line = [ef(cred, "postalCode"), ef(cred, "city")].into_iter().flatten().collect::<Vec<_>>().join(" ");
                let lines: Vec<String> = [ef(cred, "streetAddress"), Some(city_line), ef(cred, "territory"), ef(cred, "country")]
                    .into_iter()
                    .flatten()
                    .filter(|l| !l.trim().is_empty())
                    .collect();
                if !lines.is_empty() {
                    f.push(system("ADDR", lines.join("\n")));
                }
                if let Some(tel) = ef(cred, "tel") {
                    f.push(system("PHON", tel));
                }
            }
            "person-name" => {
                bump(&mut counts.other);
                let parts: Vec<String> = ["title", "given", "given2", "surnamePrefix", "surname", "surname2", "generation", "credentials"]
                    .iter()
                    .filter_map(|m| ef(cred, m))
                    .collect();
                if !parts.is_empty() {
                    f.push(system("NAME", parts.join(" ")));
                }
                if let Some(informal) = ef(cred, "givenInformal") {
                    f.push(custom("Informal name", "text", informal));
                }
            }
            "api-key" => {
                bump(&mut counts.other);
                if let Some(k) = ef(cred, "key") {
                    f.push(custom("API key", "pass", k));
                }
                if let Some(u) = ef(cred, "username") {
                    f.push(system("USER", u));
                }
                if let Some(u) = ef(cred, "url") {
                    f.push(system("LINK", u));
                }
                if let Some(t) = ef(cred, "keyType") {
                    f.push(custom("Key type", "text", t));
                }
                if let Some(d) = ef(cred, "validFrom") {
                    f.push(custom("Valid from", "date", text::iso_date_to_vault(&d)));
                }
                if let Some(d) = ef(cred, "expiryDate") {
                    f.push(system("EXPD", text::iso_date_to_vault(&d)));
                }
            }
            "ssh-key" => {
                let key = cred.str("privateKey").and_then(|k| crate::passkey::b64::decode(k, "privateKey").ok().map(Zeroizing::new));
                match key {
                    Some(der) => {
                        bump(&mut counts.other);
                        f.push(custom("SSH private key", "pass", text::pem_private_key(&der)));
                        if let Some(t) = cred.str("keyType") {
                            f.push(custom("Key type", "text", text::name(t)));
                        }
                        if let Some(c) = cred.str("keyComment") {
                            f.push(custom("Key comment", "text", text::name(c)));
                        }
                        if let Some(d) = ef(cred, "creationDate") {
                            f.push(custom("Created", "date", text::iso_date_to_vault(&d)));
                        }
                        if let Some(d) = ef(cred, "expiryDate") {
                            f.push(system("EXPD", text::iso_date_to_vault(&d)));
                        }
                        if let Some(s) = ef(cred, "keyGenerationSource") {
                            f.push(custom("Key source", "text", s));
                        }
                    }
                    None => skip(item, ty, "the private key is missing or not base64url", skipped),
                }
            }
            "drivers-license" | "passport" | "identity-document" => {
                if cred.over {
                    skip(item, ty, "more than 256 fields", skipped);
                    continue;
                }
                bump(&mut counts.other);
                let number = match ty {
                    "drivers-license" => "licenseNumber",
                    "passport" => "passportNumber",
                    _ => "documentNumber",
                };
                for (member, e) in cred.efs() {
                    let Some(v) = ef_text(e) else { continue };
                    match member {
                        "fullName" => f.push(system("NAME", v)),
                        m if m == number => f.push(system("SNUM", v)),
                        "expiryDate" => f.push(system("EXPD", text::iso_date_to_vault(&v))),
                        "birthDate" => f.push(custom("Birth date", "date", text::iso_date_to_vault(&v))),
                        "issueDate" => f.push(custom("Issue date", "date", text::iso_date_to_vault(&v))),
                        m => f.push(custom(&humanise(m), "text", v)),
                    }
                }
            }
            "custom-fields" => {
                let fields = cred.fields().map(|f| (f.list.as_slice(), f.over)).unwrap_or_default();
                if fields.1 {
                    skip(item, ty, "more than 256 custom fields", skipped);
                    continue;
                }
                bump(&mut counts.other);
                let group = cred.str("label").map(text::name).filter(|s| !s.is_empty());
                for field in fields.0 {
                    let Some(v) = field.value.as_deref() else { continue };
                    let v = text::clean(v, text::VALUE_MAX, true);
                    let label = field
                        .label
                        .as_deref()
                        .map(text::name)
                        .filter(|s| !s.is_empty())
                        .or_else(|| group.clone())
                        .unwrap_or_else(|| "Custom field".into());
                    // Unknown field types are read as text, so the data is kept.
                    let (value_type, v) = match field.field_type.as_deref() {
                        Some("concealed-string") => ("pass", v),
                        Some("date") => ("date", text::iso_date_to_vault(&v)),
                        _ => ("text", v),
                    };
                    f.push(custom(&label, value_type, v));
                }
            }
            "generated-password" => match cred.str("password") {
                Some(p) if !p.is_empty() => {
                    bump(&mut counts.logins);
                    f.push(custom("Generated password", "pass", text::clean(p, text::VALUE_MAX, false)));
                }
                _ => skip(item, ty, "no password", skipped),
            },
            "file" => skip(item, ty, "attachments are not supported", skipped),
            "item-reference" => skip(item, ty, "references to other items are not supported", skipped),
            other => skip(item, if other.is_empty() { "unknown" } else { other }, "unknown credential type", skipped),
        }
    }

    let mut details = Vec::new();
    if let Some(s) = &item.subtitle {
        details.push(format!("Subtitle: {s}"));
    }
    if !item.tags.is_empty() {
        details.push(format!("Tags: {}", item.tags.iter().map(|t| text::name(t)).collect::<Vec<_>>().join(", ")));
    }
    if !item.android_apps.is_empty() {
        details.push(format!("Android apps: {}", item.android_apps.iter().map(|a| text::name(a)).collect::<Vec<_>>().join(", ")));
    }
    if !details.is_empty() {
        f.push(custom("Imported details", "text", details.join("\n")));
    }
    f
}

/// A CXF passkey as a stored record, before validation. Borrows every value.
#[derive(Serialize)]
struct CxfPasskey<'a> {
    v: u64,
    #[serde(rename = "credentialId")]
    credential_id: &'a str,
    #[serde(rename = "rpId")]
    rp_id: &'a str,
    #[serde(rename = "userName")]
    user_name: &'a str,
    #[serde(rename = "userDisplayName")]
    user_display_name: &'a str,
    #[serde(rename = "userHandle")]
    user_handle: &'a str,
    key: &'a str,
    alg: i64,
    #[serde(rename = "createdAt")]
    created_at: i64,
    #[serde(rename = "fido2Extensions", skip_serializing_if = "Option::is_none")]
    fido2_extensions: Option<&'a RawValue>,
}

/// A CXF passkey as a `PKEY` field. Errors are reasons for the preview, never
/// values.
fn passkey_field(cred: &Cred, item: &Item<'_>) -> std::result::Result<PlannedField, String> {
    let s = |k: &str| cred.str(k).unwrap_or_default();
    let rp_id = s("rpId").to_ascii_lowercase();
    let stored = CxfPasskey {
        v: 1,
        credential_id: s("credentialId"),
        rp_id: &rp_id,
        user_name: s("username"),
        user_display_name: s("userDisplayName"),
        user_handle: s("userHandle"),
        key: s("key"),
        alg: crate::passkey::ALG_ES256,
        created_at: item.creation_at.unwrap_or(0),
        fido2_extensions: cred.raw("fido2Extensions"),
    };
    let text = super::to_json(&stored).map_err(|_| "passkey could not be stored".to_string())?;
    match PasskeyRecord::from_field_value(&text) {
        Ok(r) => Ok(PlannedField {
            kind: Kind::System(FIELD_PASSKEY),
            value: r.to_field_value().map_err(|_| "passkey could not be stored".to_string())?,
            passkey: Some(PasskeyKey { id: r.credential_id.clone(), rp_id: r.rp_id.clone(), user_handle: r.user_handle.clone() }),
        }),
        Err(WalletError::InvalidInput(m)) if m.contains("P-256") => Err("only P-256 (ES256) passkeys are supported".into()),
        Err(WalletError::InvalidInput(m)) => Err(format!("passkey is not usable: {m}")),
        Err(_) => Err("passkey is not usable".into()),
    }
}

// --- against the vault --------------------------------------------------------

/// Content fingerprint: a digest of the title plus the set of (field kind,
/// value) pairs, passkeys by credential id. Two items with the same
/// fingerprint hold the same data, however they were exported. Only digests
/// are kept, so comparing never copies a value.
type Fingerprint = [u8; 32];

/// The preview, the plan items to keep, and the `(item, field)` plan indexes
/// of fields to leave out.
type Assessment = (ImportPreview, HashSet<usize>, HashSet<(usize, usize)>);

/// Digest of one (field kind, value) pair.
fn pair_digest(kind: &str, value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((kind.len() as u64).to_le_bytes());
    h.update(kind.as_bytes());
    h.update(value);
    h.finalize().into()
}

/// Fingerprint of a title and its pair digests; a set, so order and
/// repetition do not matter.
fn fingerprint(title: &str, pairs: &BTreeSet<[u8; 32]>) -> Fingerprint {
    let mut h = Sha256::new();
    h.update((title.len() as u64).to_le_bytes());
    h.update(title.as_bytes());
    for p in pairs {
        h.update(p);
    }
    h.finalize().into()
}

impl Wallet {
    /// Parse and map a CXF payload and compare it with the vault. Writes nothing.
    pub fn preview_cxf(&mut self, json: &str) -> Result<ImportPreview> {
        let header = parse(json)?;
        let plan = plan(&header)?;
        Ok(self.assess(&plan)?.0)
    }

    /// Import a CXF payload: automatic backup first, then everything in one
    /// transaction. Existing items are never modified.
    pub fn import_cxf(&mut self, json: &str, options: &ImportOptions) -> Result<ImportReport> {
        let header = parse(json)?;
        let mut plan = plan(&header)?;
        let (preview, keep, dropped) = self.assess(&plan)?;

        let backup_path = crate::backup::BackupManager::new(&options.backup_folder)
            .create_backup(self.database()?, true)?;

        for (i, item) in plan.items.iter_mut().enumerate() {
            let mut fi = 0usize;
            item.fields.retain(|_| {
                let keep_field = !dropped.contains(&(i, fi));
                fi = fi.saturating_add(1);
                keep_field
            });
        }

        let (folder_ids, item_ids) = self.in_transaction(|w| w.apply(&plan, &keep))?;
        Ok(ImportReport { preview, folder_ids, item_ids, backup_path })
    }

    /// The preview, which items to keep, and which fields of them to leave out
    /// (`(item, field)` indexes into the plan).
    ///
    /// A passkey is left out, with a reason, when the vault already holds its
    /// credential id or a passkey for the same account (rpId + user handle),
    /// or when an earlier item of the import carries the same credential id.
    /// An import never replaces a passkey. An item left with no field at all
    /// counts as a duplicate.
    fn assess(&mut self, plan: &Plan) -> Result<Assessment> {
        let labels = self.get_labels()?;
        let system: HashSet<String> = labels.iter().filter(|l| l.system).map(|l| l.field_type.clone()).collect();
        let existing_custom: HashSet<(String, String)> = labels
            .iter()
            .filter(|l| !l.system)
            .map(|l| (l.name.to_lowercase(), l.value_type.clone()))
            .collect();

        let vault_prints = self.vault_fingerprints(&system)?;
        let mut held_ids: HashSet<Vec<u8>> = HashSet::new();
        let mut held_accounts: HashSet<(String, Vec<u8>)> = HashSet::new();
        for (_, _, r) in self.live_passkeys()? {
            held_accounts.insert((r.rp_id.clone(), r.user_handle.clone()));
            held_ids.insert(r.credential_id.clone());
        }

        let mut preview = ImportPreview {
            exporter: plan.exporter.clone(),
            destination_folders: plan.folders.iter().filter(|f| f.parent.is_none()).map(|f| f.name.clone()).collect(),
            counts: plan.counts.clone(),
            ..Default::default()
        };
        let mut skipped = plan.skipped.clone();
        let mut keep = HashSet::new();
        let mut dropped: HashSet<(usize, usize)> = HashSet::new();
        let mut seen_in_payload: HashSet<Fingerprint> = HashSet::new();
        let mut seen_ids: HashSet<&[u8]> = HashSet::new();
        let mut new_labels: BTreeSet<(String, &'static str)> = BTreeSet::new();
        for (i, item) in plan.items.iter().enumerate() {
            let fp = planned_fingerprint(item);
            if vault_prints.contains(&fp) || !seen_in_payload.insert(fp) {
                preview.duplicates = preview.duplicates.saturating_add(1);
                continue;
            }
            let mut dropped_here = Vec::new();
            let mut ids_here: Vec<&[u8]> = Vec::new();
            for (fi, f) in item.fields.iter().enumerate() {
                let Some(pk) = &f.passkey else { continue };
                let reason = if held_ids.contains(&pk.id) {
                    Some("this passkey is already in the vault")
                } else if held_accounts.contains(&(pk.rp_id.clone(), pk.user_handle.clone())) {
                    Some("the vault already has a passkey for this account on this site")
                } else if seen_ids.contains(pk.id.as_slice()) || ids_here.contains(&pk.id.as_slice()) {
                    Some("this passkey appears more than once in the import")
                } else {
                    None
                };
                match reason {
                    Some(reason) => {
                        skipped.push(&item.title, "passkey", reason);
                        dropped_here.push(fi);
                    }
                    None => ids_here.push(&pk.id),
                }
            }
            if !dropped_here.is_empty() && dropped_here.len() == item.fields.len() {
                preview.duplicates = preview.duplicates.saturating_add(1);
                continue;
            }
            seen_ids.extend(ids_here);
            dropped.extend(dropped_here.iter().map(|&fi| (i, fi)));
            keep.insert(i);
            for f in &item.fields {
                if let Kind::Custom { name, value_type } = &f.kind
                    && !existing_custom.contains(&(name.to_lowercase(), value_type.to_string()))
                {
                    new_labels.insert((name.to_lowercase(), value_type));
                }
            }
        }
        if new_labels.len() > NEW_LABELS_MAX {
            return Err(WalletError::InvalidInput("import would create more than 200 custom field labels".into()));
        }
        preview.items = keep.len();
        preview.skipped = skipped.into_vec();
        preview.new_labels = plan
            .items
            .iter()
            .flat_map(|i| &i.fields)
            .filter_map(|f| match &f.kind {
                Kind::Custom { name, value_type } if new_labels.contains(&(name.to_lowercase(), value_type)) => Some(name.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok((preview, keep, dropped))
    }

    fn vault_fingerprints(&mut self, system: &HashSet<String>) -> Result<HashSet<Fingerprint>> {
        let items: Vec<(String, String)> =
            self.get_items()?.iter().filter(|i| !i.deleted && !i.folder).map(|i| (i.item_id.clone(), i.name.clone())).collect();
        // Passkeys by credential id, read before the fields are borrowed.
        let pkeys: Vec<(String, String)> = self
            .get_fields()?
            .iter()
            .filter(|f| !f.deleted && f.field_type == FIELD_PASSKEY)
            .map(|f| (f.item_id.clone(), f.field_id.clone()))
            .collect();
        let mut by_item: HashMap<String, BTreeSet<[u8; 32]>> = HashMap::new();
        let passkey_kind = format!("sys:{FIELD_PASSKEY}");
        for (item_id, field_id) in pkeys {
            let id = self.passkey_record(&item_id, &field_id)?.map(|r| crate::passkey::b64::encode(&r.credential_id)).unwrap_or_default();
            by_item.entry(item_id).or_default().insert(pair_digest(&passkey_kind, id.as_bytes()));
        }
        for f in self.get_fields()?.iter().filter(|f| !f.deleted && f.field_type != FIELD_PASSKEY) {
            let kind = if system.contains(&f.field_type) {
                format!("sys:{}", f.field_type)
            } else {
                format!("custom:{}:{}", f.label.to_lowercase(), f.value_type)
            };
            by_item.entry(f.item_id.clone()).or_default().insert(pair_digest(&kind, f.value.as_bytes()));
        }
        Ok(items.iter().map(|(id, name)| fingerprint(name, &by_item.remove(id).unwrap_or_default())).collect())
    }

    /// Write the plan. Runs inside the import transaction.
    fn apply(&mut self, plan: &Plan, keep: &HashSet<usize>) -> Result<(Vec<String>, Vec<String>)> {
        // Only folders that end up holding something are created.
        let mut used = vec![false; plan.folders.len()];
        for (i, item) in plan.items.iter().enumerate() {
            if keep.contains(&i) {
                // Parents always come before their children in the plan, so
                // this walk ends; it is bounded by the folder count regardless.
                let mut f = Some(item.folder);
                for _ in 0..=plan.folders.len() {
                    let Some(idx) = f else { break };
                    if let Some(slot) = used.get_mut(idx) {
                        *slot = true;
                    }
                    f = plan.folders.get(idx).and_then(|x| x.parent);
                }
            }
        }
        let mut folder_ids: Vec<Option<String>> = vec![None; plan.folders.len()];
        let mut top = Vec::new();
        for (idx, folder) in plan.folders.iter().enumerate() {
            if !used.get(idx).copied().unwrap_or(false) {
                continue;
            }
            let parent = folder.parent.and_then(|p| folder_ids.get(p).cloned().flatten());
            let id = self.add_item(&folder.name, "folder", true, parent.as_deref())?;
            if folder.parent.is_none() {
                top.push(id.clone());
            }
            if let Some(slot) = folder_ids.get_mut(idx) {
                *slot = Some(id);
            }
        }

        let mut label_ids: HashMap<(String, &'static str), String> = HashMap::new();
        for l in self.get_labels()?.into_iter().filter(|l| !l.system) {
            let vt: &'static str = match l.value_type.as_str() {
                "pass" => "pass",
                "date" => "date",
                _ => "text",
            };
            label_ids.entry((l.name.to_lowercase(), vt)).or_insert(l.field_type);
        }

        let mut item_ids = Vec::new();
        for (i, item) in plan.items.iter().enumerate() {
            if !keep.contains(&i) {
                continue;
            }
            let parent = folder_ids.get(item.folder).cloned().flatten();
            let item_id = self.add_item(&item.title, "document", false, parent.as_deref())?;
            for (weight, f) in item.fields.iter().enumerate() {
                let field_type = match &f.kind {
                    Kind::System(code) => code.to_string(),
                    Kind::Custom { name, value_type } => {
                        let key = (name.to_lowercase(), *value_type);
                        match label_ids.get(&key) {
                            Some(id) => id.clone(),
                            None => {
                                let id = self.add_label(name, "label", value_type)?;
                                label_ids.insert(key, id.clone());
                                id
                            }
                        }
                    }
                };
                self.add_field_unchecked(&item_id, &field_type, &f.value, Some(field_weight(weight)))?;
            }
            item_ids.push(item_id);
        }
        Ok((top, item_ids))
    }
}

fn planned_fingerprint(item: &PlannedItem) -> Fingerprint {
    let pairs = item
        .fields
        .iter()
        .map(|f| match (&f.kind, &f.passkey) {
            (_, Some(pk)) => pair_digest(&format!("sys:{FIELD_PASSKEY}"), crate::passkey::b64::encode(&pk.id).as_bytes()),
            (Kind::System(code), None) => pair_digest(&format!("sys:{code}"), f.value.as_bytes()),
            (Kind::Custom { name, value_type }, None) => pair_digest(&format!("custom:{}:{}", name.to_lowercase(), value_type), f.value.as_bytes()),
        })
        .collect();
    fingerprint(&item.title, &pairs)
}

/// Convenience for callers holding a path to the backup folder.
pub fn options(backup_folder: &Path) -> ImportOptions {
    ImportOptions { backup_folder: backup_folder.to_path_buf() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(items: &str) -> String {
        format!(r#"{{"version": {{"major": 1}}, "exporterDisplayName": "X", "accounts": [{{"id": "a", "items": [{items}]}}]}}"#)
    }

    #[test]
    fn skipped_credentials_are_listed_up_to_the_limit_then_counted() {
        let mut list = SkipList::default();
        for _ in 0..SKIPPED_LISTED_MAX {
            list.push("t", "file", "r");
        }
        assert_eq!(list.clone().into_vec().len(), SKIPPED_LISTED_MAX, "no summary at the limit");
        list.push("t", "file", "r");
        list.push("t", "file", "r");
        let v = list.into_vec();
        assert_eq!(v.len(), SKIPPED_LISTED_MAX + 1);
        let last = v.last().unwrap();
        assert_eq!((last.item_title.as_str(), last.credential_type.as_str(), last.reason.as_str()), ("", "", "2 more not listed"));
    }

    #[test]
    fn the_plan_refuses_more_than_the_field_limit() {
        let item = |urls: usize| format!(r#"{{"title": "t", "scope": {{"urls": [{}]}}}}"#, vec![r#""u""#; urls].join(","));
        let per_item = 250;
        let n = FIELDS_MAX / per_item;
        let mut items = vec![item(per_item); n];
        let at = doc(&items.join(","));
        let p = plan(&parse(&at).unwrap()).unwrap();
        assert_eq!(p.items.iter().map(|i| i.fields.len()).sum::<usize>(), FIELDS_MAX);
        items.push(item(1));
        let over = doc(&items.join(","));
        assert!(matches!(plan(&parse(&over).unwrap()), Err(WalletError::InvalidInput(m)) if m.contains("500 000 fields")));
    }

    #[test]
    fn an_identity_document_with_too_many_fields_is_skipped() {
        let fields = |n: usize| (0..n).map(|i| format!(r#""m{i}": {{"value": "v"}}"#)).collect::<Vec<_>>().join(",");
        let at = doc(&format!(r#"{{"title": "P", "credentials": [{{"type": "passport", {}}}]}}"#, fields(CUSTOM_FIELDS_MAX_FOR_TEST)));
        let p = plan(&parse(&at).unwrap()).unwrap();
        assert_eq!(p.items[0].fields.len(), CUSTOM_FIELDS_MAX_FOR_TEST);
        assert_eq!(p.counts.other, 1);
        let over = doc(&format!(r#"{{"title": "P", "credentials": [{{"type": "passport", {}}}]}}"#, fields(CUSTOM_FIELDS_MAX_FOR_TEST + 1)));
        let p = plan(&parse(&over).unwrap()).unwrap();
        assert!(p.items[0].fields.is_empty());
        assert_eq!(p.counts.other, 0);
        let skipped = p.skipped.into_vec();
        assert_eq!((skipped[0].credential_type.as_str(), skipped[0].reason.as_str()), ("passport", "more than 256 fields"));
    }

    const CUSTOM_FIELDS_MAX_FOR_TEST: usize = super::super::CUSTOM_FIELDS_MAX;

    #[test]
    fn a_passkey_record_is_built_without_a_json_tree() {
        // Extensions are carried over verbatim, and only when they are an object.
        let c = r#"{"type": "passkey", "credentialId": "AAAAAAAAAAAAAAAAAAAAAA", "rpId": "Example.COM", "userHandle": "aA", "key": "x",
                    "fido2Extensions": {"a": [1, 2]}}"#;
        let raw: &RawValue = serde_json::from_str(c).unwrap();
        let cred = Cred::read(raw);
        let stored = CxfPasskey {
            v: 1, credential_id: cred.str("credentialId").unwrap(), rp_id: "example.com", user_name: "", user_display_name: "",
            user_handle: cred.str("userHandle").unwrap(), key: cred.str("key").unwrap(), alg: -7, created_at: 0,
            fido2_extensions: cred.raw("fido2Extensions"),
        };
        let text = super::super::to_json(&stored).unwrap();
        assert!(text.ends_with(r#""createdAt":0,"fido2Extensions":{"a": [1, 2]}}"#), "{}", &*text);
        let item = Item::default();
        // The key is not a P-256 key: refused with a reason that carries no value.
        let reason = passkey_field(&cred, &item).err().unwrap();
        assert!(reason.starts_with("passkey is not usable"), "{reason}");
        assert!(!reason.contains("AAAAAAAA"));
    }

    #[test]
    fn counters_and_weights_saturate() {
        let mut n = usize::MAX - 1;
        bump(&mut n);
        assert_eq!(n, usize::MAX);
        bump(&mut n);
        assert_eq!(n, usize::MAX);
        assert_eq!(field_weight(0), 0);
        assert_eq!(field_weight(3), 300);
        assert_eq!(field_weight(21_474_836), 2_147_483_600);
        assert_eq!(field_weight(21_474_837), i32::MAX);
        assert_eq!(field_weight(usize::MAX), i32::MAX);
    }

    /// A card expiry no calendar can hold is kept as text, never an overflow.
    #[test]
    fn extreme_card_expiry_dates_are_kept_as_text() {
        for exp in ["2147483647-12", "2024-4294967295", "-2147483648-01"] {
            let d = doc(&format!(r#"{{"title": "Card", "credentials": [{{"type": "credit-card", "number": {{"value": "4111"}}, "expiryDate": {{"value": "{exp}"}}}}]}}"#));
            let p = plan(&parse(&d).unwrap()).unwrap();
            let f = &p.items[0].fields;
            assert!(f.iter().any(|f| matches!(&f.kind, Kind::Custom { name, .. } if name == "Expiry date") && *f.value == exp), "{exp}");
            assert!(!f.iter().any(|f| f.kind == Kind::System("EXPD")), "{exp}");
        }
    }

    // --- passkeys met twice ---------------------------------------------------

    use crate::business::wallet::tests::create_test_wallet;
    use crate::passkey::sign::{self, RegisterInput};

    /// A CXF passkey credential for `rp` and `handle`, freshly registered.
    fn cxf_passkey(rp: &str, handle: &[u8]) -> String {
        let reg = sign::register(&RegisterInput {
            rp_id: rp, user_name: "bkv", user_display_name: "B", user_handle: handle,
            exclude_credentials: &[], held_credential_ids: &[], user_verified: true, now: 0,
        })
        .unwrap();
        let stored: serde_json::Value = serde_json::from_str(&reg.record.to_field_value().unwrap()).unwrap();
        serde_json::json!({"type": "passkey", "credentialId": stored["credentialId"], "rpId": rp, "username": "bkv",
            "userDisplayName": "B", "userHandle": stored["userHandle"], "key": stored["key"]})
        .to_string()
    }

    fn import(w: &mut Wallet, t: &tempfile::TempDir, items: &str) -> ImportReport {
        w.import_cxf(&doc(items), &options(&t.path().join("backups"))).unwrap()
    }

    fn reasons(r: &ImportReport) -> Vec<&str> {
        r.preview.skipped.iter().map(|s| s.reason.as_str()).collect()
    }

    #[test]
    fn a_passkey_carried_by_two_items_is_imported_once() {
        let (mut w, t) = create_test_wallet();
        let pk = cxf_passkey("example.com", b"h1");
        let note = r#"{"type": "note", "content": {"fieldType": "string", "value": "n"}}"#;
        let items = format!(
            r#"{{"title": "A", "credentials": [{pk}]}}, {{"title": "B", "credentials": [{pk}]}}, {{"title": "C", "credentials": [{pk}, {note}]}}"#
        );
        assert_eq!(w.preview_cxf(&doc(&items)).unwrap().items, 2);
        let r = import(&mut w, &t, &items);
        assert_eq!(r.item_ids.len(), 2, "B holds nothing else and is left out; C keeps its note");
        assert_eq!(r.preview.duplicates, 1);
        assert_eq!(reasons(&r), ["this passkey appears more than once in the import"; 2]);
        assert_eq!(r.preview.skipped[0].item_title, "B");
        assert_eq!(w.list_passkeys().unwrap().len(), 1);
        let c = w.get_fields_by_item(&r.item_ids[1]).unwrap();
        assert!(c.iter().all(|f| f.field_type != FIELD_PASSKEY) && c.iter().any(|f| f.field_type == "NOTE"));
        // The same credential twice inside one item.
        let (mut w, t) = create_test_wallet();
        let r = import(&mut w, &t, &format!(r#"{{"title": "A", "credentials": [{pk}, {pk}, {note}]}}"#));
        assert_eq!(reasons(&r), ["this passkey appears more than once in the import"]);
        assert_eq!(w.list_passkeys().unwrap().len(), 1);
    }

    #[test]
    fn an_account_with_a_passkey_in_the_vault_is_not_replaced_by_an_import() {
        let (mut w, t) = create_test_wallet();
        import(&mut w, &t, &format!(r#"{{"title": "A", "credentials": [{}]}}"#, cxf_passkey("example.com", b"h1")));
        let before = w.list_passkeys().unwrap();

        // Same site and user handle, another credential id.
        let r = import(&mut w, &t, &format!(r#"{{"title": "A2", "credentials": [{}]}}"#, cxf_passkey("example.com", b"h1")));
        assert!(r.item_ids.is_empty());
        assert_eq!(reasons(&r), ["the vault already has a passkey for this account on this site"]);
        let after = w.list_passkeys().unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].credential_id, before[0].credential_id);

        // Another user on the same site, or the same user handle on another site, is new.
        let r = import(
            &mut w,
            &t,
            &format!(
                r#"{{"title": "U2", "credentials": [{}]}}, {{"title": "S2", "credentials": [{}]}}"#,
                cxf_passkey("example.com", b"h2"),
                cxf_passkey("other.example", b"h1")
            ),
        );
        assert_eq!(r.item_ids.len(), 2);
        assert!(r.preview.skipped.is_empty());
        assert_eq!(w.list_passkeys().unwrap().len(), 3);
    }
}
