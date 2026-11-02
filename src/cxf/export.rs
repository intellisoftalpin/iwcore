//! IntelliWallet → CXF.
//!
//! The whole vault, or chosen folders, as a CXF document. Lossless: a value
//! goes into a typed CXF credential when its meaning is exact, and everything
//! else (old passwords, secret questions, seed phrases, custom labels, extra
//! values of a type that appears twice) into one `custom-fields` credential per
//! item, concealed when the vault masks it.
//!
//! The result holds every secret of the exported items in plain text. It is
//! returned in a zeroizing buffer and meant to be handed straight to the
//! operating system's transfer flow, never written to disk by the app.
//!
//! The document is written straight from typed views that borrow the vault's
//! values; every string built on the way (encoded keys, parsed TOTP and Wi-Fi
//! secrets) is held zeroizing, the copied fields are wiped once written, and
//! the output buffer is sized exactly before the single write, so it never
//! grows and leaves a copy behind.

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use super::text;
use super::{CXF_MAJOR, CXF_MINOR, EXPORTER_NAME, EXPORTER_RP_ID};
use crate::business::Wallet;
use crate::error::{Result, WalletError};
use crate::passkey::{b64, PasskeyRecord, FIELD_PASSKEY};
use crate::{IWField, IWItem, ROOT_ID};

/// What to export.
#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// Only these folders and everything below them; `None` for the whole vault.
    pub folder_ids: Option<Vec<String>>,
}

impl Wallet {
    /// Export as CXF JSON. See the module documentation.
    pub fn export_cxf(&mut self, options: &ExportOptions) -> Result<Zeroizing<String>> {
        let database_id = self.get_properties()?.database_id;
        let items: Vec<IWItem> = self.get_items()?.iter().filter(|i| !i.deleted).cloned().collect();
        let fields = WipedFields(self.get_fields()?.iter().filter(|f| !f.deleted).cloned().collect());

        let in_scope = scope(&items, options)?;
        let mut by_item: HashMap<&str, Vec<&IWField>> = HashMap::new();
        for f in &fields.0 {
            by_item.entry(f.item_id.as_str()).or_default().push(f);
        }
        for v in by_item.values_mut() {
            v.sort_by_key(|f| f.sort_weight);
        }
        // Passkey records are read up front so the document can borrow them.
        let mut records: HashMap<(&str, &str), PasskeyRecord> = HashMap::new();
        for f in fields.0.iter().filter(|f| f.field_type == FIELD_PASSKEY && in_scope.contains(f.item_id.as_str())) {
            if let Some(r) = self.passkey_record(&f.item_id, &f.field_id)? {
                records.insert((f.item_id.as_str(), f.field_id.as_str()), r);
            }
        }

        let mut cxf_items = Vec::new();
        for item in items.iter().filter(|i| !i.folder && !i.is_root() && in_scope.contains(i.item_id.as_str())) {
            let own = by_item.get(item.item_id.as_str()).map(Vec::as_slice).unwrap_or_default();
            cxf_items.push(item_view(item, own, &records));
        }

        // Folders become collections, nested as in the vault.
        let mut children: HashMap<&str, Vec<&IWItem>> = HashMap::new();
        for i in items.iter().filter(|i| !i.is_root() && in_scope.contains(i.item_id.as_str())) {
            children.entry(i.parent_id.as_deref().unwrap_or(ROOT_ID)).or_default().push(i);
        }
        let roots: Vec<&IWItem> = match &options.folder_ids {
            None => children.get(ROOT_ID).cloned().unwrap_or_default().into_iter().filter(|i| i.folder).collect(),
            Some(ids) => items.iter().filter(|i| i.folder && ids.contains(&i.item_id)).collect(),
        };
        let mut guard = HashSet::new();
        let collections: Vec<CollectionView<'_>> = roots.iter().map(|f| collection_view(f, &children, &mut guard, 1)).collect();

        let doc = DocView {
            accounts: [AccountView {
                collections,
                email: "",
                id: b64::encode(database_id.as_bytes()),
                items: cxf_items,
                username: "",
            }],
            exporter_display_name: EXPORTER_NAME,
            exporter_rp_id: EXPORTER_RP_ID,
            timestamp: chrono::Utc::now().timestamp().max(0),
            version: VersionView { major: CXF_MAJOR, minor: CXF_MINOR },
        };
        to_zeroizing_json(&doc)
    }
}

/// Serialize into a buffer sized exactly beforehand, so it is never
/// reallocated and no partial copy is left behind.
fn to_zeroizing_json<T: Serialize>(value: &T) -> Result<Zeroizing<String>> {
    let encode = |e: serde_json::Error| WalletError::ExportError(format!("CXF encode failed: {e}"));
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(encode)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(counter.0));
    serde_json::to_writer(Fixed(&mut buf), value).map_err(encode)?;
    into_string(buf)
}

/// The buffer as text without copying it; wiped when it is not UTF-8.
fn into_string(mut buf: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>> {
    match String::from_utf8(std::mem::take(&mut *buf)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            e.into_bytes().zeroize();
            Err(WalletError::ExportError("CXF encode failed: not UTF-8".into()))
        }
    }
}

/// Counts the bytes written.
struct Counter(usize);

impl Write for Counter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(data.len());
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Appends within the buffer's capacity only; refuses to grow it.
struct Fixed<'a>(&'a mut Vec<u8>);

impl Write for Fixed<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.0.capacity().saturating_sub(self.0.len()) {
            return Err(io::Error::other("output larger than measured"));
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Copies of the vault's fields, values wiped on drop.
struct WipedFields(Vec<IWField>);

impl Drop for WipedFields {
    fn drop(&mut self) {
        wipe_values(&mut self.0);
    }
}

fn wipe_values(fields: &mut [IWField]) {
    for f in fields {
        f.value.zeroize();
    }
}

/// Text borrowed from the vault, or built for the export and wiped on drop.
enum Text<'a> {
    Borrowed(&'a str),
    Owned(Zeroizing<String>),
}

impl Serialize for Text<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            Text::Borrowed(v) => v,
            Text::Owned(v) => v.as_str(),
        })
    }
}

impl<'a> From<&'a str> for Text<'a> {
    fn from(v: &'a str) -> Self {
        Text::Borrowed(v)
    }
}

impl From<String> for Text<'_> {
    fn from(v: String) -> Self {
        Text::Owned(Zeroizing::new(v))
    }
}

// Members are declared in alphabetical order: the order the document has
// always been written in.

#[derive(Serialize)]
struct DocView<'a> {
    accounts: [AccountView<'a>; 1],
    #[serde(rename = "exporterDisplayName")]
    exporter_display_name: &'static str,
    #[serde(rename = "exporterRpId")]
    exporter_rp_id: &'static str,
    timestamp: i64,
    version: VersionView,
}

#[derive(Serialize)]
struct VersionView {
    major: u64,
    minor: u64,
}

#[derive(Serialize)]
struct AccountView<'a> {
    collections: Vec<CollectionView<'a>>,
    email: &'static str,
    id: String,
    items: Vec<ItemView<'a>>,
    username: &'static str,
}

#[derive(Serialize)]
struct CollectionView<'a> {
    id: String,
    items: Vec<LinkedItemView>,
    #[serde(rename = "subCollections", skip_serializing_if = "Option::is_none")]
    sub_collections: Option<Vec<CollectionView<'a>>>,
    title: &'a str,
}

#[derive(Serialize)]
struct LinkedItemView {
    item: String,
}

#[derive(Serialize)]
struct ItemView<'a> {
    #[serde(rename = "creationAt")]
    creation_at: i64,
    credentials: Vec<CredentialView<'a>>,
    id: String,
    #[serde(rename = "modifiedAt")]
    modified_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<ScopeView<'a>>,
    title: &'a str,
}

#[derive(Serialize)]
struct ScopeView<'a> {
    #[serde(rename = "androidApps")]
    android_apps: [(); 0],
    urls: Vec<&'a str>,
}

/// An editable field.
#[derive(Serialize)]
struct Ef<'a> {
    #[serde(rename = "fieldType")]
    field_type: &'static str,
    value: Text<'a>,
}

fn ef<'a>(field_type: &'static str, value: impl Into<Text<'a>>) -> Ef<'a> {
    Ef { field_type, value: value.into() }
}

#[derive(Serialize)]
struct CustomFieldView<'a> {
    #[serde(rename = "fieldType")]
    field_type: &'static str,
    label: &'a str,
    value: Text<'a>,
}

fn custom_field<'a>(label: &'a str, field_type: &'static str, value: impl Into<Text<'a>>) -> CustomFieldView<'a> {
    CustomFieldView { field_type, label, value: value.into() }
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum CredentialView<'a> {
    #[serde(rename = "basic-auth")]
    BasicAuth {
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<Ef<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<Ef<'a>>,
    },
    #[serde(rename = "credit-card")]
    CreditCard {
        #[serde(rename = "expiryDate", skip_serializing_if = "Option::is_none")]
        expiry_date: Option<Ef<'a>>,
        #[serde(rename = "fullName", skip_serializing_if = "Option::is_none")]
        full_name: Option<Ef<'a>>,
        number: Ef<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pin: Option<Ef<'a>>,
        #[serde(rename = "verificationNumber", skip_serializing_if = "Option::is_none")]
        verification_number: Option<Ef<'a>>,
    },
    #[serde(rename = "passkey")]
    Passkey {
        #[serde(rename = "credentialId")]
        credential_id: String,
        #[serde(rename = "fido2Extensions", skip_serializing_if = "Option::is_none")]
        fido2_extensions: Option<&'a Map<String, Value>>,
        key: Text<'a>,
        #[serde(rename = "rpId")]
        rp_id: &'a str,
        #[serde(rename = "userDisplayName")]
        user_display_name: &'a str,
        #[serde(rename = "userHandle")]
        user_handle: String,
        username: &'a str,
    },
    #[serde(rename = "totp")]
    Totp {
        algorithm: String,
        digits: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        issuer: Option<String>,
        period: u32,
        secret: Text<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
    #[serde(rename = "note")]
    Note { content: Ef<'a> },
    #[serde(rename = "wifi")]
    Wifi {
        hidden: Ef<'a>,
        #[serde(rename = "networkSecurityType")]
        network_security_type: Ef<'a>,
        passphrase: Ef<'a>,
        ssid: Ef<'a>,
    },
    #[serde(rename = "address")]
    Address {
        #[serde(rename = "streetAddress")]
        street_address: Ef<'a>,
    },
    #[serde(rename = "custom-fields")]
    CustomFields { fields: Vec<CustomFieldView<'a>>, id: String },
}

fn item_view<'a>(item: &'a IWItem, fields: &[&'a IWField], records: &'a HashMap<(&str, &str), PasskeyRecord>) -> ItemView<'a> {
    let mut credentials: Vec<CredentialView<'a>> = Vec::new();
    let mut custom: Vec<CustomFieldView<'a>> = Vec::new();
    let mut urls: Vec<&'a str> = Vec::new();
    let mut used: HashSet<usize> = HashSet::new();
    let find = |code: &str, used: &HashSet<usize>| {
        fields.iter().enumerate().find(|(i, f)| f.field_type == code && !used.contains(i)).map(|(i, _)| i)
    };
    let value = |i: usize| -> &'a str { fields.get(i).map(|f| f.value.as_str()).unwrap_or_default() };

    // One login: the first identity and the first password.
    let identity = ["USER", "MAIL", "ACNT"].iter().find_map(|c| find(c, &used));
    let password = find("PASS", &used);
    if identity.is_some() || password.is_some() {
        let username = identity.map(|i| {
            used.insert(i);
            ef("string", value(i))
        });
        let password = password.map(|i| {
            used.insert(i);
            ef("concealed-string", value(i))
        });
        credentials.push(CredentialView::BasicAuth { password, username });
    }

    // A card, when there is a card number.
    if let Some(card) = find("CARD", &used) {
        used.insert(card);
        let take = |code: &str, kind: &'static str, used: &mut HashSet<usize>| {
            find(code, used).map(|i| {
                used.insert(i);
                ef(kind, value(i))
            })
        };
        let full_name = take("NAME", "string", &mut used);
        let verification_number = take("CVVC", "concealed-string", &mut used);
        let pin = take("PINC", "concealed-string", &mut used);
        let mut expiry_date = None;
        if let Some(i) = find("EXPD", &used)
            && let Some(mut iso) = text::vault_date_to_iso(value(i))
        {
            iso.truncate(7);
            expiry_date = Some(ef("year-month", iso));
            used.insert(i);
        }
        credentials.push(CredentialView::CreditCard {
            expiry_date,
            full_name,
            number: ef("concealed-string", value(card)),
            pin,
            verification_number,
        });
    }

    for (i, f) in fields.iter().enumerate() {
        if used.contains(&i) {
            continue;
        }
        match f.field_type.as_str() {
            "LINK" => urls.push(&f.value),
            FIELD_PASSKEY => match records.get(&(f.item_id.as_str(), f.field_id.as_str())) {
                Some(r) => credentials.push(CredentialView::Passkey {
                    credential_id: b64::encode(&r.credential_id),
                    fido2_extensions: r.fido2_extensions(),
                    key: b64::encode(r.pkcs8()).into(),
                    rp_id: &r.rp_id,
                    user_display_name: &r.user_display_name,
                    user_handle: b64::encode(&r.user_handle),
                    username: &r.user_name,
                }),
                // An unreadable record is kept as text rather than lost.
                None => custom.push(custom_field("Passkey (unreadable)", "concealed-string", f.value.as_str())),
            },
            "2FAC" => match text::parse_totp(&f.value) {
                Some(t) => credentials.push(CredentialView::Totp {
                    algorithm: t.algorithm.to_ascii_lowercase(),
                    digits: t.digits,
                    issuer: t.issuer,
                    period: t.period,
                    secret: t.secret.into(),
                    username: t.account,
                }),
                None => custom.push(custom_field(&f.label, "concealed-string", f.value.as_str())),
            },
            "NOTE" => credentials.push(CredentialView::Note { content: ef("string", f.value.as_str()) }),
            "WIFI" => {
                let (ssid, sec, pass, hidden) = text::parse_wifi(&f.value);
                let security = match sec.as_str() {
                    "nopass" => "unsecured",
                    "WEP" => "wep",
                    _ => "wpa2-personal",
                };
                credentials.push(CredentialView::Wifi {
                    hidden: ef("boolean", if hidden { "true" } else { "false" }),
                    network_security_type: ef("wifi-network-security-type", security),
                    passphrase: ef("concealed-string", pass),
                    ssid: ef("string", ssid),
                });
            }
            "ADDR" => credentials.push(CredentialView::Address { street_address: ef("string", f.value.as_str()) }),
            _ => custom.push(match f.value_type.as_str() {
                "pass" => custom_field(&f.label, "concealed-string", f.value.as_str()),
                "date" => match text::vault_date_to_iso(&f.value) {
                    Some(iso) => custom_field(&f.label, "date", iso),
                    None => custom_field(&f.label, "string", f.value.as_str()),
                },
                _ => custom_field(&f.label, "string", f.value.as_str()),
            }),
        }
    }
    if !custom.is_empty() {
        credentials.push(CredentialView::CustomFields {
            fields: custom,
            id: b64::encode(format!("{}-custom", item.item_id).as_bytes()),
        });
    }

    ItemView {
        creation_at: item.create_timestamp.timestamp().max(0),
        credentials,
        id: b64::encode(item.item_id.as_bytes()),
        modified_at: item.change_timestamp.timestamp().max(0),
        scope: (!urls.is_empty()).then_some(ScopeView { android_apps: [], urls }),
        title: &item.name,
    }
}

/// Item ids in scope: everything, or the chosen folders and all below them.
fn scope<'a>(items: &'a [IWItem], options: &'a ExportOptions) -> Result<HashSet<&'a str>> {
    let Some(ids) = &options.folder_ids else {
        return Ok(items.iter().map(|i| i.item_id.as_str()).collect());
    };
    for id in ids {
        if !items.iter().any(|i| i.folder && &i.item_id == id) {
            return Err(WalletError::ItemNotFound(id.clone()));
        }
    }
    let mut out: HashSet<&str> = ids.iter().map(String::as_str).collect();
    // Grow downwards until stable; a parent cycle cannot loop because the set
    // only ever grows and is bounded by the item count.
    loop {
        let before = out.len();
        for i in items {
            if i.parent_id.as_deref().is_some_and(|p| out.contains(p)) {
                out.insert(i.item_id.as_str());
            }
        }
        if out.len() == before {
            return Ok(out);
        }
    }
}

fn collection_view<'a>(
    folder: &'a IWItem,
    children: &HashMap<&str, Vec<&'a IWItem>>,
    guard: &mut HashSet<&'a str>,
    depth: usize,
) -> CollectionView<'a> {
    let kids = children.get(folder.item_id.as_str()).cloned().unwrap_or_default();
    let items = kids.iter().filter(|i| !i.folder).map(|i| LinkedItemView { item: b64::encode(i.item_id.as_bytes()) }).collect();
    let mut sub_collections = None;
    if guard.insert(folder.item_id.as_str()) && depth < super::COLLECTION_DEPTH_MAX {
        let mut subs = Vec::new();
        for f in kids.iter().filter(|i| i.folder) {
            if !guard.contains(f.item_id.as_str()) {
                subs.push(collection_view(f, children, guard, depth.saturating_add(1)));
            }
        }
        if !subs.is_empty() {
            sub_collections = Some(subs);
        }
    }
    CollectionView { id: b64::encode(folder.item_id.as_bytes()), items, sub_collections, title: &folder.name }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::business::wallet::tests::create_test_wallet;
    use std::cell::Cell;

    /// Writes one byte more on every call.
    struct Growing(Cell<usize>);

    impl Serialize for Growing {
        fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
            let n = self.0.get();
            self.0.set(n + 1);
            s.serialize_str(&"x".repeat(n))
        }
    }

    #[test]
    fn the_output_buffer_is_sized_exactly_and_never_grows() {
        let out = to_zeroizing_json(&Text::from(String::from("secret \"quoted\" é"))).unwrap();
        assert_eq!(out.as_str(), r#""secret \"quoted\" é""#);
        assert_eq!(out.capacity(), out.len());
        assert_eq!(to_zeroizing_json(&Text::Borrowed("b")).unwrap().as_str(), r#""b""#);
        // Output longer than measured is refused rather than reallocated.
        let err = to_zeroizing_json(&Growing(Cell::new(4))).unwrap_err();
        assert!(err.to_string().contains("larger than measured"), "{err}");
    }

    #[test]
    fn writers_count_and_refuse_to_grow() {
        let mut c = Counter(usize::MAX - 1);
        assert_eq!(c.write(b"abc").unwrap(), 3);
        assert_eq!(c.0, usize::MAX);
        c.flush().unwrap();
        let mut v = Vec::with_capacity(4);
        let mut f = Fixed(&mut v);
        assert_eq!(f.write(b"abcd").unwrap(), 4);
        assert!(f.write(b"e").is_err());
        f.flush().unwrap();
        assert_eq!(v, b"abcd");
        assert_eq!(v.capacity(), 4);
    }

    #[test]
    fn non_utf8_output_is_refused() {
        assert!(into_string(Zeroizing::new(vec![0xff, 0xfe])).is_err());
        assert_eq!(into_string(Zeroizing::new(b"ok".to_vec())).unwrap().as_str(), "ok");
    }

    #[test]
    fn copied_field_values_are_wiped() {
        let (mut w, _t) = create_test_wallet();
        let item = w.add_item("I", "document", false, None).unwrap();
        w.add_field(&item, "PASS", "hunter2", None).unwrap();
        let mut copies: Vec<IWField> = w.get_fields().unwrap().to_vec();
        wipe_values(&mut copies);
        assert!(copies.iter().all(|f| f.value.is_empty()));
        drop(WipedFields(w.get_fields().unwrap().to_vec()));
    }

    /// Every credential kind, read back: members, the `type` tag and
    /// optional members left out when empty.
    #[test]
    fn export_document_shape() {
        let (mut w, _t) = create_test_wallet();
        let a = w.add_item("A", "folder", true, None).unwrap();
        let item = w.add_item("Card", "document", false, Some(&a)).unwrap();
        for (ty, v) in [("CARD", "4111"), ("EXPD", "20301231"), ("2FAC", "JBSWY3DPEHPK3PXP"), ("PASS", "pw")] {
            w.add_field(&item, ty, v, None).unwrap();
        }
        let doc = w.export_cxf(&ExportOptions::default()).unwrap();
        assert_eq!(doc.capacity(), doc.len());
        let v: Value = serde_json::from_str(&doc).unwrap();
        let acc = &v["accounts"][0];
        assert_eq!(acc["collections"][0]["title"], "A");
        assert!(acc["collections"][0].get("subCollections").is_none());
        let it = &acc["items"][0];
        assert!(it.get("scope").is_none());
        let creds = it["credentials"].as_array().unwrap();
        assert_eq!(creds[0], serde_json::json!({"type": "basic-auth", "password": {"fieldType": "concealed-string", "value": "pw"}}));
        assert_eq!(creds[1], serde_json::json!({"type": "credit-card", "number": {"fieldType": "concealed-string", "value": "4111"},
            "expiryDate": {"fieldType": "year-month", "value": "2030-12"}}));
        assert_eq!(creds[2], serde_json::json!({"type": "totp", "secret": "JBSWY3DPEHPK3PXP", "algorithm": "sha1", "digits": 6, "period": 30}));
    }

    /// The root row is never a collection, even when an old or hand-edited file
    /// gives it no parent, or itself as the parent.
    #[test]
    fn the_root_is_not_a_collection_whatever_its_parent() {
        for parent in [None, Some(ROOT_ID)] {
            let (mut w, _t) = create_test_wallet();
            w.add_item("Top", "folder", true, None).unwrap();
            w.db.as_ref().unwrap().connection().unwrap()
                .execute("UPDATE nswallet_items SET parent_id = ? WHERE item_id = ?", rusqlite::params![parent, ROOT_ID])
                .unwrap();
            w.items_cache = None;
            assert_eq!(w.get_item(ROOT_ID).unwrap().unwrap().parent_id.as_deref(), parent);

            let doc = w.export_cxf(&ExportOptions::default()).unwrap();
            let v: Value = serde_json::from_str(&doc).unwrap();
            let titles: Vec<&str> = v["accounts"][0]["collections"].as_array().unwrap()
                .iter().map(|c| c["title"].as_str().unwrap()).collect();
            assert_eq!(titles, ["Top"], "parent {parent:?}");
        }
    }
}
