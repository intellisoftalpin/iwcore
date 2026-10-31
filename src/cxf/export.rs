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

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use super::text;
use super::{CXF_MAJOR, CXF_MINOR, EXPORTER_NAME, EXPORTER_RP_ID};
use crate::business::Wallet;
use crate::error::{Result, WalletError};
use crate::passkey::{b64, FIELD_PASSKEY};
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
        let fields: Vec<IWField> = self.get_fields()?.iter().filter(|f| !f.deleted).cloned().collect();

        let in_scope = scope(&items, options)?;
        let mut by_item: HashMap<&str, Vec<&IWField>> = HashMap::new();
        for f in &fields {
            by_item.entry(f.item_id.as_str()).or_default().push(f);
        }
        for v in by_item.values_mut() {
            v.sort_by_key(|f| f.sort_weight);
        }

        let mut cxf_items = Vec::new();
        for item in items.iter().filter(|i| !i.folder && !i.is_root() && in_scope.contains(i.item_id.as_str())) {
            let own = by_item.get(item.item_id.as_str()).cloned().unwrap_or_default();
            cxf_items.push(self.item_json(item, &own)?);
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
        let collections: Vec<Value> = roots.iter().map(|f| collection_json(f, &children, &mut guard, 1)).collect();

        let doc = json!({
            "version": { "major": CXF_MAJOR, "minor": CXF_MINOR },
            "exporterRpId": EXPORTER_RP_ID,
            "exporterDisplayName": EXPORTER_NAME,
            "timestamp": chrono::Utc::now().timestamp().max(0),
            "accounts": [{
                "id": b64::encode(database_id.as_bytes()),
                "username": "",
                "email": "",
                "collections": collections,
                "items": cxf_items,
            }],
        });
        serde_json::to_string(&doc)
            .map(Zeroizing::new)
            .map_err(|e| WalletError::ExportError(format!("CXF encode failed: {e}")))
    }

    fn item_json(&mut self, item: &IWItem, fields: &[&IWField]) -> Result<Value> {
        let mut credentials: Vec<Value> = Vec::new();
        let mut custom: Vec<Value> = Vec::new();
        let mut urls: Vec<String> = Vec::new();
        let mut used: HashSet<usize> = HashSet::new();
        let find = |code: &str, used: &HashSet<usize>| fields.iter().position(|f| f.field_type == code).filter(|i| !used.contains(i));

        // One login: the first identity and the first password.
        let identity = ["USER", "MAIL", "ACNT"].iter().find_map(|c| find(c, &used));
        let password = find("PASS", &used);
        if identity.is_some() || password.is_some() {
            let mut cred = Map::new();
            cred.insert("type".into(), "basic-auth".into());
            if let Some(i) = identity {
                cred.insert("username".into(), ef("string", &fields[i].value));
                used.insert(i);
            }
            if let Some(i) = password {
                cred.insert("password".into(), ef("concealed-string", &fields[i].value));
                used.insert(i);
            }
            credentials.push(Value::Object(cred));
        }

        // A card, when there is a card number.
        if let Some(card) = find("CARD", &used) {
            let mut cred = Map::new();
            cred.insert("type".into(), "credit-card".into());
            cred.insert("number".into(), ef("concealed-string", &fields[card].value));
            used.insert(card);
            for (code, member, kind) in [("NAME", "fullName", "string"), ("CVVC", "verificationNumber", "concealed-string"), ("PINC", "pin", "concealed-string")] {
                if let Some(i) = find(code, &used) {
                    cred.insert(member.into(), ef(kind, &fields[i].value));
                    used.insert(i);
                }
            }
            if let Some(i) = find("EXPD", &used)
                && let Some(iso) = text::vault_date_to_iso(&fields[i].value)
            {
                cred.insert("expiryDate".into(), ef("year-month", &iso[..7]));
                used.insert(i);
            }
            credentials.push(Value::Object(cred));
        }

        for (i, f) in fields.iter().enumerate() {
            if used.contains(&i) {
                continue;
            }
            match f.field_type.as_str() {
                "LINK" => urls.push(f.value.clone()),
                FIELD_PASSKEY => match self.passkey_record(&f.item_id, &f.field_id)? {
                    Some(r) => {
                        let mut cred = Map::new();
                        cred.insert("type".into(), "passkey".into());
                        cred.insert("credentialId".into(), b64::encode(&r.credential_id).into());
                        cred.insert("rpId".into(), r.rp_id.clone().into());
                        cred.insert("username".into(), r.user_name.clone().into());
                        cred.insert("userDisplayName".into(), r.user_display_name.clone().into());
                        cred.insert("userHandle".into(), b64::encode(&r.user_handle).into());
                        cred.insert("key".into(), b64::encode(r.pkcs8()).into());
                        if let Some(ext) = r.fido2_extensions() {
                            cred.insert("fido2Extensions".into(), Value::Object(ext.clone()));
                        }
                        credentials.push(Value::Object(cred));
                    }
                    // An unreadable record is kept as text rather than lost.
                    None => custom.push(custom_field("Passkey (unreadable)", "concealed-string", &f.value)),
                },
                "2FAC" => match text::parse_totp(&f.value) {
                    Some(t) => {
                        let mut cred = json!({
                            "type": "totp", "secret": t.secret, "period": t.period, "digits": t.digits,
                            "algorithm": t.algorithm.to_ascii_lowercase(),
                        });
                        if let Some(i) = t.issuer {
                            cred["issuer"] = i.into();
                        }
                        if let Some(a) = t.account {
                            cred["username"] = a.into();
                        }
                        credentials.push(cred);
                    }
                    None => custom.push(custom_field(&f.label, "concealed-string", &f.value)),
                },
                "NOTE" => credentials.push(json!({ "type": "note", "content": ef("string", &f.value) })),
                "WIFI" => {
                    let (ssid, sec, pass, hidden) = text::parse_wifi(&f.value);
                    let security = match sec.as_str() {
                        "nopass" => "unsecured",
                        "WEP" => "wep",
                        _ => "wpa2-personal",
                    };
                    credentials.push(json!({
                        "type": "wifi",
                        "ssid": ef("string", &ssid),
                        "networkSecurityType": ef("wifi-network-security-type", security),
                        "passphrase": ef("concealed-string", &pass),
                        "hidden": ef("boolean", if hidden { "true" } else { "false" }),
                    }));
                }
                "ADDR" => credentials.push(json!({ "type": "address", "streetAddress": ef("string", &f.value) })),
                _ => {
                    let kind = match f.value_type.as_str() {
                        "pass" => "concealed-string",
                        "date" => "date",
                        _ => "string",
                    };
                    let value = if kind == "date" { text::vault_date_to_iso(&f.value).unwrap_or_else(|| f.value.clone()) } else { f.value.clone() };
                    let kind = if kind == "date" && text::vault_date_to_iso(&f.value).is_none() { "string" } else { kind };
                    custom.push(custom_field(&f.label, kind, &value));
                }
            }
        }
        if !custom.is_empty() {
            credentials.push(json!({
                "type": "custom-fields",
                "id": b64::encode(format!("{}-custom", item.item_id).as_bytes()),
                "fields": custom,
            }));
        }

        let mut obj = Map::new();
        obj.insert("id".into(), b64::encode(item.item_id.as_bytes()).into());
        obj.insert("creationAt".into(), item.create_timestamp.timestamp().max(0).into());
        obj.insert("modifiedAt".into(), item.change_timestamp.timestamp().max(0).into());
        obj.insert("title".into(), item.name.clone().into());
        if !urls.is_empty() {
            obj.insert("scope".into(), json!({ "urls": urls, "androidApps": [] }));
        }
        obj.insert("credentials".into(), Value::Array(credentials));
        Ok(Value::Object(obj))
    }
}

/// An editable field.
fn ef(field_type: &str, value: &str) -> Value {
    json!({ "fieldType": field_type, "value": value })
}

fn custom_field(label: &str, field_type: &str, value: &str) -> Value {
    json!({ "fieldType": field_type, "value": value, "label": label })
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

fn collection_json<'a>(
    folder: &'a IWItem,
    children: &HashMap<&str, Vec<&'a IWItem>>,
    guard: &mut HashSet<&'a str>,
    depth: usize,
) -> Value {
    let kids = children.get(folder.item_id.as_str()).cloned().unwrap_or_default();
    let linked: Vec<Value> = kids
        .iter()
        .filter(|i| !i.folder)
        .map(|i| json!({ "item": b64::encode(i.item_id.as_bytes()) }))
        .collect();
    let mut obj = Map::new();
    obj.insert("id".into(), b64::encode(folder.item_id.as_bytes()).into());
    obj.insert("title".into(), folder.name.clone().into());
    obj.insert("items".into(), Value::Array(linked));
    if guard.insert(folder.item_id.as_str()) && depth < super::COLLECTION_DEPTH_MAX {
        let mut subs: Vec<Value> = Vec::new();
        for f in kids.iter().filter(|i| i.folder) {
            if !guard.contains(f.item_id.as_str()) {
                subs.push(collection_json(f, children, guard, depth + 1));
            }
        }
        if !subs.is_empty() {
            obj.insert("subCollections".into(), Value::Array(subs));
        }
    }
    Value::Object(obj)
}
