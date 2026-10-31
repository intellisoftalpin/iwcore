//! FIDO Credential Exchange Format (CXF) v1.0: import and export of the whole
//! vault, so users can move in from 1Password, Bitwarden or Apple Passwords and
//! out again.
//!
//! The operating system's app-to-app transfer flow carries the data (iOS 26
//! `ASCredentialImportManager` / `ExportManager`, Android Credential Manager
//! transfer); this module only converts between CXF JSON and the vault.
//!
//! Reading follows the specification's own tolerance rules: unknown members and
//! enum values are ignored, a credential whose required value is unusable is
//! dropped (and reported), and an editable field of an unknown `fieldType` is
//! read as text so the user's data is kept. Every value is bounded by the
//! limits below before it reaches the vault.
//!
//! - [`import`]: preview (writes nothing) and import (one transaction, after an
//!   automatic backup, never touching existing items);
//! - [`export`]: the whole vault, losslessly.

pub mod export;
pub mod import;
pub(crate) mod text;

use serde_json::{Map, Value};

use crate::error::{Result, WalletError};

/// CXF major version read and written.
pub const CXF_MAJOR: u64 = 1;
/// CXF minor version written.
pub const CXF_MINOR: u64 = 0;
/// `exporterRpId` written on export.
pub const EXPORTER_RP_ID: &str = "intelliwallet.io";
/// `exporterDisplayName` written on export.
pub const EXPORTER_NAME: &str = "IntelliWallet";

/// Largest CXF payload accepted, in bytes.
pub const PAYLOAD_MAX: usize = 64 * 1024 * 1024;
/// Most items read from one payload.
pub const ITEMS_MAX: usize = 100_000;
/// Most credentials read from one item.
pub const CREDENTIALS_PER_ITEM_MAX: usize = 64;
/// Most fields read from one `custom-fields` credential.
pub const CUSTOM_FIELDS_MAX: usize = 256;
/// Deepest collection nesting read.
pub const COLLECTION_DEPTH_MAX: usize = 32;
/// Most new custom labels one import may create.
pub const NEW_LABELS_MAX: usize = 200;

/// A CXF document, as read.
#[derive(Debug, Clone, Default)]
pub(crate) struct Header {
    pub exporter_display_name: String,
    pub timestamp: u64,
    pub accounts: Vec<Account>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Account {
    pub username: String,
    pub email: String,
    pub collections: Vec<Collection>,
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Collection {
    pub title: String,
    /// Item ids linked from this collection that belong to the same account.
    pub items: Vec<String>,
    pub sub: Vec<Collection>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Item {
    pub id: String,
    pub creation_at: Option<i64>,
    pub title: String,
    pub subtitle: Option<String>,
    pub urls: Vec<String>,
    pub android_apps: Vec<String>,
    pub tags: Vec<String>,
    /// Raw credential objects; mapping reads them field by field.
    pub credentials: Vec<Value>,
}

/// Parse a CXF document, enforcing the limits. The checks that cannot wait for
/// the full parse (size, nesting) run first.
pub(crate) fn parse(json: &str) -> Result<Header> {
    if json.len() > PAYLOAD_MAX {
        return Err(invalid("CXF payload is larger than 64 MiB"));
    }
    let root: Value = serde_json::from_str(json).map_err(|_| invalid("CXF payload is not valid JSON"))?;
    let root = root.as_object().ok_or_else(|| invalid("CXF payload is not a JSON object"))?;

    let version = root.get("version").and_then(Value::as_object).ok_or_else(|| invalid("CXF version is missing"))?;
    match version.get("major").and_then(Value::as_u64) {
        Some(CXF_MAJOR) => {}
        Some(_) => return Err(WalletError::NotSupported("CXF major version other than 1".into())),
        None => return Err(invalid("CXF version.major is missing")),
    }

    let accounts_json = root.get("accounts").and_then(Value::as_array).ok_or_else(|| invalid("CXF accounts are missing"))?;
    let mut item_count = 0usize;
    let mut accounts = Vec::with_capacity(accounts_json.len());
    for a in accounts_json {
        let Some(a) = a.as_object() else { continue };
        let account = parse_account(a, &mut item_count)?;
        accounts.push(account);
    }

    Ok(Header {
        exporter_display_name: text::name(str_of(root, "exporterDisplayName").unwrap_or("another app")),
        timestamp: root.get("timestamp").and_then(Value::as_u64).unwrap_or(0),
        accounts,
    })
}

fn parse_account(a: &Map<String, Value>, item_count: &mut usize) -> Result<Account> {
    let id = str_of(a, "id").unwrap_or_default().to_string();
    let mut items = Vec::new();
    for item in a.get("items").and_then(Value::as_array).into_iter().flatten() {
        let Some(item) = item.as_object() else { continue };
        *item_count += 1;
        if *item_count > ITEMS_MAX {
            return Err(invalid("CXF payload has more than 100 000 items"));
        }
        items.push(parse_item(item)?);
    }
    let mut collections = Vec::new();
    for c in a.get("collections").and_then(Value::as_array).into_iter().flatten() {
        if let Some(c) = c.as_object() {
            collections.push(parse_collection(c, &id, 1)?);
        }
    }
    Ok(Account {
        username: text::name(str_of(a, "username").unwrap_or_default()),
        email: text::name(str_of(a, "email").unwrap_or_default()),
        collections,
        items,
    })
}

fn parse_collection(c: &Map<String, Value>, account_id: &str, depth: usize) -> Result<Collection> {
    if depth > COLLECTION_DEPTH_MAX {
        return Err(invalid("CXF collections are nested deeper than 32 levels"));
    }
    let items = c
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter(|l| l.get("account").and_then(Value::as_str).is_none_or(|acc| acc == account_id))
        .filter_map(|l| str_of(l, "item").map(str::to_string))
        .collect();
    let mut sub = Vec::new();
    for s in c.get("subCollections").and_then(Value::as_array).into_iter().flatten() {
        if let Some(s) = s.as_object() {
            sub.push(parse_collection(s, account_id, depth + 1)?);
        }
    }
    Ok(Collection { title: text::name(str_of(c, "title").unwrap_or("Collection")), items, sub })
}

fn parse_item(i: &Map<String, Value>) -> Result<Item> {
    let credentials: Vec<Value> = i.get("credentials").and_then(Value::as_array).cloned().unwrap_or_default();
    if credentials.len() > CREDENTIALS_PER_ITEM_MAX {
        return Err(invalid("a CXF item has more than 64 credentials"));
    }
    let scope = i.get("scope");
    let urls = scope
        .and_then(|s| s.get("urls"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|u| text::clean(u, text::VALUE_MAX, false))
        .collect();
    let android_apps = scope
        .and_then(|s| s.get("androidApps"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| a.get("bundleId").and_then(Value::as_str))
        .map(text::name)
        .collect();
    let tags = i
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(text::name)
        .collect();
    Ok(Item {
        id: str_of(i, "id").unwrap_or_default().to_string(),
        creation_at: i.get("creationAt").and_then(Value::as_i64),
        title: text::name(str_of(i, "title").unwrap_or_default()),
        subtitle: str_of(i, "subtitle").map(text::name).filter(|s| !s.is_empty()),
        urls,
        android_apps,
        tags,
        credentials,
    })
}

fn str_of<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(Value::as_str)
}

fn invalid(msg: &str) -> WalletError {
    WalletError::InvalidInput(msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(accounts: Value) -> String {
        json!({"version": {"major": 1, "minor": 0}, "exporterRpId": "x.example", "exporterDisplayName": "X",
               "timestamp": 1_790_000_000u64, "accounts": accounts}).to_string()
    }

    #[test]
    fn version_and_shape_rules() {
        assert!(parse(&doc(json!([]))).is_ok());
        let v2 = json!({"version": {"major": 2, "minor": 0}, "accounts": []}).to_string();
        assert!(matches!(parse(&v2), Err(WalletError::NotSupported(_))));
        let minor = json!({"version": {"major": 1, "minor": 7}, "accounts": [], "futureMember": 1}).to_string();
        assert!(parse(&minor).is_ok(), "newer minor and unknown members are fine");
        for bad in ["", "[]", "{}", "{\"version\":{}}", "{\"version\":{\"major\":1}}", "not json"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert!(parse(&" ".repeat(PAYLOAD_MAX + 1)).is_err());
    }

    #[test]
    fn limits_on_items_credentials_and_depth() {
        let item = |n_creds: usize| json!({"id": "i", "title": "t", "credentials": vec![json!({"type": "note", "content": {"fieldType": "string", "value": "x"}}); n_creds]});
        assert!(parse(&doc(json!([{"id": "a", "username": "", "email": "", "items": [item(CREDENTIALS_PER_ITEM_MAX)], "collections": []}]))).is_ok());
        assert!(parse(&doc(json!([{"id": "a", "username": "", "email": "", "items": [item(CREDENTIALS_PER_ITEM_MAX + 1)], "collections": []}]))).is_err());

        let mut c = json!({"id": "c", "title": "deep", "items": []});
        for _ in 0..COLLECTION_DEPTH_MAX {
            c = json!({"id": "c", "title": "deep", "items": [], "subCollections": [c]});
        }
        assert!(parse(&doc(json!([{"id": "a", "username": "", "email": "", "items": [], "collections": [c]}]))).is_err());
    }

    #[test]
    fn links_to_other_accounts_are_ignored() {
        let h = parse(&doc(json!([{"id": "a", "username": "u", "email": "", "items": [],
            "collections": [{"id": "c", "title": "C", "items": [{"item": "i1"}, {"item": "i2", "account": "a"}, {"item": "i3", "account": "other"}]}]}]))).unwrap();
        assert_eq!(h.accounts[0].collections[0].items, vec!["i1".to_string(), "i2".to_string()]);
    }

    #[test]
    fn names_are_cleaned() {
        let h = parse(&doc(json!([{"id": "a", "username": "u\u{0}", "email": "", "collections": [],
            "items": [{"id": "i", "title": "Bank\u{1b}[0m", "credentials": [], "tags": ["t\u{7}"]}]}]))).unwrap();
        assert_eq!(h.accounts[0].items[0].title, "Bank[0m");
        assert_eq!(h.accounts[0].items[0].tags, vec!["t".to_string()]);
        assert_eq!(h.accounts[0].username, "u");
    }
}
