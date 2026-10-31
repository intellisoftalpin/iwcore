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
//! Mapping rule: a value goes into an IntelliWallet system field only when the
//! meaning is exact; anything else becomes a clearly named custom field, so
//! nothing is dropped silently. Credentials that cannot be stored at all
//! (attachments, references, unknown types, unusable passkeys) are listed as
//! skipped with the reason.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::text::{self, Totp};
use super::{parse, Header, Item, NEW_LABELS_MAX};
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
    /// Credential id, for a passkey.
    passkey_id: Option<Vec<u8>>,
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

struct Plan {
    exporter: String,
    folders: Vec<PlannedFolder>,
    items: Vec<PlannedItem>,
    counts: KindCounts,
    skipped: Vec<Skipped>,
}

fn plan(header: &Header) -> Plan {
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
        skipped: Vec::new(),
    };
    let several = header.accounts.len() > 1;
    for (n, account) in header.accounts.iter().enumerate() {
        let mut name = format!("Imported from {} {}", header.exporter_display_name, date);
        if several {
            let who = [&account.username, &account.email].into_iter().find(|s| !s.is_empty());
            name.push_str(&format!(" ({})", who.cloned().unwrap_or_else(|| format!("account {}", n + 1))));
        }
        let top = p.folders.len();
        p.folders.push(PlannedFolder { name, parent: None });

        // An item linked from several collections lands in the first.
        let mut placement: HashMap<&str, usize> = HashMap::new();
        fn walk<'a>(c: &'a super::Collection, parent: usize, p: &mut Plan, placement: &mut HashMap<&'a str, usize>) {
            let idx = p.folders.len();
            p.folders.push(PlannedFolder { name: c.title.clone(), parent: Some(parent) });
            for id in &c.items {
                placement.entry(id.as_str()).or_insert(idx);
            }
            for s in &c.sub {
                walk(s, idx, p, placement);
            }
        }
        for c in &account.collections {
            walk(c, top, &mut p, &mut placement);
        }

        for item in &account.items {
            let folder = placement.get(item.id.as_str()).copied().unwrap_or(top);
            let fields = map_item(item, &mut p.counts, &mut p.skipped);
            p.items.push(PlannedItem {
                title: if item.title.is_empty() { "Untitled".into() } else { item.title.clone() },
                folder,
                fields,
            });
        }
    }
    p
}

/// The text of an editable field (`{"fieldType": ..., "value": ...}`).
fn ef(cred: &Value, key: &str) -> Option<String> {
    let v = cred.get(key)?.get("value")?.as_str()?;
    // Values may span lines (an address, a recovery sheet); names never do.
    let v = text::clean(v, text::VALUE_MAX, true);
    (!v.trim().is_empty()).then_some(v)
}

fn system(code: &'static str, value: String) -> PlannedField {
    PlannedField { kind: Kind::System(code), value: Zeroizing::new(value), passkey_id: None }
}

fn custom(name: &str, value_type: &'static str, value: String) -> PlannedField {
    PlannedField {
        kind: Kind::Custom { name: text::name(name), value_type },
        value: Zeroizing::new(value),
        passkey_id: None,
    }
}

fn skip(item: &Item, ty: &str, reason: &str, out: &mut Vec<Skipped>) {
    out.push(Skipped { item_title: item.title.clone(), credential_type: ty.to_string(), reason: reason.to_string() });
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

fn map_item(item: &Item, counts: &mut KindCounts, skipped: &mut Vec<Skipped>) -> Vec<PlannedField> {
    let mut f: Vec<PlannedField> = Vec::new();
    for url in &item.urls {
        if !url.trim().is_empty() {
            f.push(system("LINK", url.clone()));
        }
    }

    for cred in &item.credentials {
        let ty = cred.get("type").and_then(Value::as_str).unwrap_or("");
        match ty {
            "basic-auth" => {
                counts.logins += 1;
                if let Some(user) = ef(cred, "username") {
                    f.push(system(identity::classify(&user).field_type(), user));
                }
                if let Some(pass) = ef(cred, "password") {
                    f.push(system("PASS", pass));
                }
            }
            "passkey" => match passkey_field(cred, item) {
                Ok(pf) => {
                    counts.passkeys += 1;
                    f.push(pf);
                }
                Err(reason) => skip(item, ty, &reason, skipped),
            },
            "totp" => {
                let algorithm = cred.get("algorithm").and_then(Value::as_str).unwrap_or("sha1").to_ascii_uppercase();
                let secret = cred.get("secret").and_then(Value::as_str).and_then(text::base32_secret);
                match (secret, ["SHA1", "SHA256", "SHA512"].contains(&algorithm.as_str())) {
                    (Some(secret), true) => {
                        counts.totp += 1;
                        let t = Totp {
                            secret,
                            algorithm,
                            digits: cred.get("digits").and_then(Value::as_u64).filter(|d| (4..=10).contains(d)).unwrap_or(6) as u32,
                            period: cred.get("period").and_then(Value::as_u64).filter(|p| (1..=86_400).contains(p)).unwrap_or(30) as u32,
                            issuer: cred.get("issuer").and_then(Value::as_str).map(text::name).filter(|s| !s.is_empty()),
                            account: cred.get("username").and_then(Value::as_str).map(text::name).filter(|s| !s.is_empty()),
                        };
                        f.push(system("2FAC", text::totp_value(&t)));
                    }
                    (None, _) => skip(item, ty, "the secret is not Base32", skipped),
                    (_, false) => skip(item, ty, "unknown hash algorithm", skipped),
                }
            }
            "note" => {
                if let Some(content) = cred.get("content").and_then(|c| c.get("value")).and_then(Value::as_str) {
                    counts.notes += 1;
                    f.push(system("NOTE", text::clean(content, text::NOTE_MAX, true)));
                }
            }
            "credit-card" => {
                counts.cards += 1;
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
                counts.wifi += 1;
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
                counts.other += 1;
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
                counts.other += 1;
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
                counts.other += 1;
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
                let key = cred.get("privateKey").and_then(Value::as_str).and_then(|k| crate::passkey::b64::decode(k, "privateKey").ok());
                match key {
                    Some(der) => {
                        counts.other += 1;
                        f.push(custom("SSH private key", "pass", text::pem_private_key(&der)));
                        if let Some(t) = cred.get("keyType").and_then(Value::as_str) {
                            f.push(custom("Key type", "text", text::name(t)));
                        }
                        if let Some(c) = cred.get("keyComment").and_then(Value::as_str) {
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
                counts.other += 1;
                let number = match ty {
                    "drivers-license" => "licenseNumber",
                    "passport" => "passportNumber",
                    _ => "documentNumber",
                };
                let obj = cred.as_object().cloned().unwrap_or_default();
                for (member, _) in obj.iter() {
                    let Some(v) = ef(cred, member) else { continue };
                    match member.as_str() {
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
                let fields = cred.get("fields").and_then(Value::as_array).cloned().unwrap_or_default();
                if fields.len() > super::CUSTOM_FIELDS_MAX {
                    skip(item, ty, "more than 256 custom fields", skipped);
                    continue;
                }
                counts.other += 1;
                let group = cred.get("label").and_then(Value::as_str).map(text::name).filter(|s| !s.is_empty());
                for field in fields {
                    let Some(v) = field.get("value").and_then(Value::as_str) else { continue };
                    let v = text::clean(v, text::VALUE_MAX, true);
                    let label = field
                        .get("label")
                        .and_then(Value::as_str)
                        .map(text::name)
                        .filter(|s| !s.is_empty())
                        .or_else(|| group.clone())
                        .unwrap_or_else(|| "Custom field".into());
                    // Unknown field types are read as text, so the data is kept.
                    let (value_type, v) = match field.get("fieldType").and_then(Value::as_str) {
                        Some("concealed-string") => ("pass", v),
                        Some("date") => ("date", text::iso_date_to_vault(&v)),
                        _ => ("text", v),
                    };
                    f.push(custom(&label, value_type, v));
                }
            }
            "generated-password" => match cred.get("password").and_then(Value::as_str) {
                Some(p) if !p.is_empty() => {
                    counts.logins += 1;
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
        details.push(format!("Tags: {}", item.tags.join(", ")));
    }
    if !item.android_apps.is_empty() {
        details.push(format!("Android apps: {}", item.android_apps.join(", ")));
    }
    if !details.is_empty() {
        f.push(custom("Imported details", "text", details.join("\n")));
    }
    f
}

/// A CXF passkey as a `PKEY` field. Errors are reasons for the preview, never
/// values.
fn passkey_field(cred: &Value, item: &Item) -> std::result::Result<PlannedField, String> {
    let s = |k: &str| cred.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let mut stored = Map::new();
    stored.insert("v".into(), 1.into());
    stored.insert("credentialId".into(), s("credentialId").into());
    stored.insert("rpId".into(), s("rpId").to_ascii_lowercase().into());
    stored.insert("userName".into(), s("username").into());
    stored.insert("userDisplayName".into(), s("userDisplayName").into());
    stored.insert("userHandle".into(), s("userHandle").into());
    stored.insert("key".into(), Zeroizing::new(s("key")).as_str().into());
    stored.insert("alg".into(), crate::passkey::ALG_ES256.into());
    stored.insert("createdAt".into(), item.creation_at.unwrap_or(0).into());
    if let Some(ext) = cred.get("fido2Extensions").filter(|e| e.is_object()) {
        stored.insert("fido2Extensions".into(), ext.clone());
    }
    let text = Zeroizing::new(Value::Object(stored).to_string());
    match PasskeyRecord::from_field_value(&text) {
        Ok(r) => Ok(PlannedField {
            kind: Kind::System(FIELD_PASSKEY),
            value: r.to_field_value().map_err(|_| "passkey could not be stored".to_string())?,
            passkey_id: Some(r.credential_id.clone()),
        }),
        Err(WalletError::InvalidInput(m)) if m.contains("P-256") => Err("only P-256 (ES256) passkeys are supported".into()),
        Err(WalletError::InvalidInput(m)) => Err(format!("passkey is not usable: {m}")),
        Err(_) => Err("passkey is not usable".into()),
    }
}

// --- against the vault --------------------------------------------------------

/// Content fingerprint: the title plus every (field kind, value) pair, and
/// passkeys by credential id. Two items with the same fingerprint hold the same
/// data, however they were exported.
type Fingerprint = (String, BTreeSet<(String, String)>);

impl Wallet {
    /// Parse and map a CXF payload and compare it with the vault. Writes nothing.
    pub fn preview_cxf(&mut self, json: &str) -> Result<ImportPreview> {
        let header = parse(json)?;
        let plan = plan(&header);
        Ok(self.assess(&plan)?.0)
    }

    /// Import a CXF payload: automatic backup first, then everything in one
    /// transaction. Existing items are never modified.
    pub fn import_cxf(&mut self, json: &str, options: &ImportOptions) -> Result<ImportReport> {
        let header = parse(json)?;
        let mut plan = plan(&header);
        let (preview, keep, drop_passkeys) = self.assess(&plan)?;

        let backup_path = crate::backup::BackupManager::new(&options.backup_folder)
            .create_backup(self.database()?, true)?;

        for (i, item) in plan.items.iter_mut().enumerate() {
            if keep.contains(&i) {
                item.fields.retain(|f| f.passkey_id.as_ref().is_none_or(|id| !drop_passkeys.contains(id)));
            }
        }

        let (folder_ids, item_ids) = self.in_transaction(|w| w.apply(&plan, &keep))?;
        Ok(ImportReport { preview, folder_ids, item_ids, backup_path })
    }

    /// The preview, which items to keep, and passkeys already in the vault.
    fn assess(&mut self, plan: &Plan) -> Result<(ImportPreview, HashSet<usize>, HashSet<Vec<u8>>)> {
        let labels = self.get_labels()?;
        let system: HashSet<String> = labels.iter().filter(|l| l.system).map(|l| l.field_type.clone()).collect();
        let existing_custom: HashSet<(String, String)> = labels
            .iter()
            .filter(|l| !l.system)
            .map(|l| (l.name.to_lowercase(), l.value_type.clone()))
            .collect();

        let vault_prints = self.vault_fingerprints(&system)?;
        let held: HashSet<Vec<u8>> = self.live_passkeys()?.into_iter().map(|(_, _, r)| r.credential_id).collect();

        let mut preview = ImportPreview {
            exporter: plan.exporter.clone(),
            destination_folders: plan.folders.iter().filter(|f| f.parent.is_none()).map(|f| f.name.clone()).collect(),
            counts: plan.counts.clone(),
            skipped: plan.skipped.clone(),
            ..Default::default()
        };
        let mut keep = HashSet::new();
        let mut seen_in_payload: HashSet<Fingerprint> = HashSet::new();
        let mut new_labels: BTreeSet<(String, &'static str)> = BTreeSet::new();
        for (i, item) in plan.items.iter().enumerate() {
            let fp = planned_fingerprint(item);
            if vault_prints.contains(&fp) || !seen_in_payload.insert(fp) {
                preview.duplicates += 1;
                continue;
            }
            keep.insert(i);
            for f in &item.fields {
                if let Some(id) = &f.passkey_id
                    && held.contains(id)
                {
                    preview.skipped.push(Skipped {
                        item_title: item.title.clone(),
                        credential_type: "passkey".into(),
                        reason: "this passkey is already in the vault".into(),
                    });
                }
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
        Ok((preview, keep, held))
    }

    fn vault_fingerprints(&mut self, system: &HashSet<String>) -> Result<HashSet<Fingerprint>> {
        let items: Vec<_> = self.get_items()?.iter().filter(|i| !i.deleted && !i.folder).cloned().collect();
        let fields = self.get_fields()?.to_vec();
        let mut by_item: HashMap<&str, BTreeSet<(String, String)>> = HashMap::new();
        for f in fields.iter().filter(|f| !f.deleted) {
            let key = if f.field_type == FIELD_PASSKEY {
                let id = self
                    .passkey_record(&f.item_id, &f.field_id)?
                    .map(|r| crate::passkey::b64::encode(&r.credential_id))
                    .unwrap_or_default();
                (format!("sys:{FIELD_PASSKEY}"), id)
            } else if system.contains(&f.field_type) {
                (format!("sys:{}", f.field_type), f.value.clone())
            } else {
                (format!("custom:{}:{}", f.label.to_lowercase(), f.value_type), f.value.clone())
            };
            by_item.entry(f.item_id.as_str()).or_default().insert(key);
        }
        Ok(items
            .iter()
            .map(|i| (i.name.clone(), by_item.remove(i.item_id.as_str()).unwrap_or_default()))
            .collect())
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
                self.add_field_unchecked(&item_id, &field_type, &f.value, Some(weight as i32 * 100))?;
            }
            item_ids.push(item_id);
        }
        Ok((top, item_ids))
    }
}

fn planned_fingerprint(item: &PlannedItem) -> Fingerprint {
    let set = item
        .fields
        .iter()
        .map(|f| match (&f.kind, &f.passkey_id) {
            (_, Some(id)) => (format!("sys:{FIELD_PASSKEY}"), crate::passkey::b64::encode(id)),
            (Kind::System(code), None) => (format!("sys:{code}"), f.value.to_string()),
            (Kind::Custom { name, value_type }, None) => (format!("custom:{}:{}", name.to_lowercase(), value_type), f.value.to_string()),
        })
        .collect();
    (item.title.clone(), set)
}

/// Convenience for callers holding a path to the backup folder.
pub fn options(backup_folder: &Path) -> ImportOptions {
    ImportOptions { backup_folder: backup_folder.to_path_buf() }
}
