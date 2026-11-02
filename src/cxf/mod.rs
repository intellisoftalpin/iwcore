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
//!
//! Limits on a payload: at most [`PAYLOAD_MAX`] (16 MiB), [`ITEMS_MAX`] items,
//! [`COLLECTIONS_MAX`] collections nested at most [`COLLECTION_DEPTH_MAX`]
//! deep, [`CREDENTIALS_PER_ITEM_MAX`] credentials per item and
//! [`CUSTOM_FIELDS_MAX`] fields per `custom-fields` credential or identity
//! document, and [`ENTRIES_MAX`] list entries of every kind together; values
//! are cut to 64 KiB (notes to 1 MiB). The payload is read without building a
//! JSON tree, so members the import does not use cost no memory. One import
//! creates at most [`FIELDS_MAX`] fields and [`NEW_LABELS_MAX`] custom labels,
//! and a preview lists at most [`SKIPPED_LISTED_MAX`] skipped credentials one
//! by one.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)
)]

pub(crate) mod de;
pub mod export;
pub mod import;
pub(crate) mod text;

use std::borrow::Cow;

use serde_json::value::RawValue;
use zeroize::Zeroizing;

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
pub const PAYLOAD_MAX: usize = 16 * 1024 * 1024;
/// Most items read from one payload.
pub const ITEMS_MAX: usize = 100_000;
/// Most collections read from one payload, at every nesting level.
pub const COLLECTIONS_MAX: usize = 100_000;
/// Most list entries read from one payload: items, collections, collection
/// links, credentials, URLs, Android apps and tags together.
pub const ENTRIES_MAX: usize = 1_000_000;
/// Most fields one import may create.
pub const FIELDS_MAX: usize = 500_000;
/// Most skipped credentials listed one by one in a preview; the rest are
/// summed up in one last entry.
pub const SKIPPED_LISTED_MAX: usize = 1_000;
/// Most credentials read from one item.
pub const CREDENTIALS_PER_ITEM_MAX: usize = 64;
/// Most fields read from one `custom-fields` credential, and most editable
/// fields read from one identity document.
pub const CUSTOM_FIELDS_MAX: usize = 256;
/// Deepest collection nesting read.
pub const COLLECTION_DEPTH_MAX: usize = 32;
/// Most new custom labels one import may create.
pub const NEW_LABELS_MAX: usize = 200;

/// A CXF document, as read. Strings borrow from the payload where they can.
#[derive(Debug, Default)]
pub(crate) struct Header<'a> {
    pub exporter_display_name: String,
    pub timestamp: u64,
    pub accounts: Vec<Account<'a>>,
}

#[derive(Debug, Default)]
pub(crate) struct Account<'a> {
    pub username: String,
    pub email: String,
    pub collections: Vec<Collection<'a>>,
    pub items: Vec<Item<'a>>,
}

#[derive(Debug, Default)]
pub(crate) struct Collection<'a> {
    pub title: String,
    /// Item ids linked from this collection that belong to the same account.
    pub items: Vec<Cow<'a, str>>,
    pub sub: Vec<Collection<'a>>,
}

#[derive(Debug, Default)]
pub(crate) struct Item<'a> {
    pub id: Cow<'a, str>,
    pub creation_at: Option<i64>,
    pub title: String,
    pub subtitle: Option<String>,
    /// As in the payload; cleaned when mapped.
    pub urls: Vec<Cow<'a, str>>,
    pub android_apps: Vec<Cow<'a, str>>,
    pub tags: Vec<Cow<'a, str>>,
    /// The credentials as slices of the payload, read one at a time when
    /// mapped.
    pub credentials: Vec<&'a RawValue>,
}

/// Parse a CXF document, enforcing the limits while reading.
pub(crate) fn parse(json: &str) -> Result<Header<'_>> {
    if json.len() > PAYLOAD_MAX {
        return Err(invalid("CXF payload is larger than 16 MiB"));
    }
    let mut ctx = de::Ctx::default();
    let root = match de::header(json, &mut ctx) {
        Ok(Some(root)) => root,
        Ok(None) => return Err(invalid("CXF payload is not a JSON object")),
        Err(_) => return Err(invalid(ctx.limit.unwrap_or("CXF payload is not valid JSON"))),
    };

    let version = root.version.ok_or_else(|| invalid("CXF version is missing"))?;
    match version.major {
        Some(CXF_MAJOR) => {}
        Some(_) => return Err(WalletError::NotSupported("CXF major version other than 1".into())),
        None => return Err(invalid("CXF version.major is missing")),
    }
    let accounts = root.accounts.ok_or_else(|| invalid("CXF accounts are missing"))?;

    Ok(Header {
        exporter_display_name: text::name(root.exporter_display_name.as_deref().unwrap_or("another app")),
        timestamp: root.timestamp.unwrap_or(0),
        accounts: accounts.into_iter().map(account).collect(),
    })
}

fn account(a: de::RawAccount<'_>) -> Account<'_> {
    let id = a.id.unwrap_or_default();
    Account {
        username: text::name(a.username.as_deref().unwrap_or_default()),
        email: text::name(a.email.as_deref().unwrap_or_default()),
        collections: a.collections.into_iter().map(|c| collection(c, &id)).collect(),
        items: a.items.into_iter().map(item).collect(),
    }
}

fn collection<'a>(c: de::RawCollection<'a>, account_id: &str) -> Collection<'a> {
    let items = c
        .links
        .into_iter()
        .filter(|l| l.account.as_deref().is_none_or(|acc| acc == account_id))
        .filter_map(|l| l.item)
        .collect();
    Collection {
        title: text::name(c.title.as_deref().unwrap_or("Collection")),
        items,
        sub: c.sub.into_iter().map(|s| collection(s, account_id)).collect(),
    }
}

fn item(i: de::RawItem<'_>) -> Item<'_> {
    let scope = i.scope.unwrap_or_default();
    Item {
        id: i.id.unwrap_or_default(),
        creation_at: i.creation_at,
        title: text::name(i.title.as_deref().unwrap_or_default()),
        subtitle: i.subtitle.as_deref().map(text::name).filter(|s| !s.is_empty()),
        urls: scope.urls,
        android_apps: scope.android_apps,
        tags: i.tags,
        credentials: i.credentials,
    }
}

fn invalid(msg: &str) -> WalletError {
    WalletError::InvalidInput(msg.to_string())
}

/// Serialise to JSON in a zeroizing buffer of exactly the right size.
///
/// The length is measured first, so the buffer is allocated once and never
/// grows: a growing buffer would leave copies of the secrets it holds in the
/// memory it gives back.
pub(crate) fn to_json<T: serde::Serialize + ?Sized>(value: &T) -> serde_json::Result<Zeroizing<String>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(count.0));
    serde_json::to_writer(&mut *buf, value)?;
    // serde_json writes UTF-8 only, so this cannot fail; if it did, the bytes
    // are wiped all the same.
    match String::from_utf8(std::mem::take(&mut *buf)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            Err(serde::ser::Error::custom("JSON output is not UTF-8"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

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

    /// A payload of exactly 16 MiB is read; one byte more is refused.
    #[test]
    fn payload_size_limit_is_inclusive() {
        let mut at_limit = doc(json!([]));
        at_limit.push_str(&" ".repeat(PAYLOAD_MAX - at_limit.len()));
        assert!(parse(&at_limit).is_ok());
        at_limit.push(' ');
        assert!(parse(&at_limit).is_err());
    }

    /// Items are counted across accounts; exactly the limit is read.
    #[test]
    fn item_limit_is_inclusive_and_spans_accounts() {
        let accounts = |n: usize| {
            let first = vec![json!({}); n / 2];
            let second = vec![json!({}); n - n / 2];
            json!([{"id": "a", "items": first}, {"id": "b", "items": second}])
        };
        let d = doc(accounts(ITEMS_MAX));
        let h = parse(&d).unwrap();
        assert_eq!(h.accounts.iter().map(|a| a.items.len()).sum::<usize>(), ITEMS_MAX);
        assert!(parse(&doc(accounts(ITEMS_MAX + 1))).is_err());
    }

    /// Collections nested exactly to the limit are read.
    #[test]
    fn collection_depth_limit_is_inclusive() {
        let mut c = json!({"title": "deep"});
        for _ in 1..COLLECTION_DEPTH_MAX {
            c = json!({"title": "deep", "subCollections": [c]});
        }
        let d = doc(json!([{"id": "a", "collections": [c.clone()]}]));
        let h = parse(&d).unwrap();
        let mut depth = 0;
        let mut level = h.accounts[0].collections.first();
        while let Some(col) = level {
            depth += 1;
            level = col.sub.first();
        }
        assert_eq!(depth, COLLECTION_DEPTH_MAX);
        let deeper = json!({"title": "deep", "subCollections": [c]});
        assert!(parse(&doc(json!([{"id": "a", "collections": [deeper]}]))).is_err());
    }

    #[test]
    fn links_to_other_accounts_are_ignored() {
        let d = doc(json!([{"id": "a", "username": "u", "email": "", "items": [],
            "collections": [{"id": "c", "title": "C", "items": [{"item": "i1"}, {"item": "i2", "account": "a"}, {"item": "i3", "account": "other"}]}]}]));
        let h = parse(&d).unwrap();
        assert_eq!(h.accounts[0].collections[0].items, ["i1", "i2"]);
    }

    #[test]
    fn names_are_cleaned() {
        let d = doc(json!([{"id": "a", "username": "u\u{0}", "email": "", "collections": [],
            "items": [{"id": "i", "title": "Bank\u{1b}[0m", "credentials": [], "tags": ["t\u{7}"]}]}]));
        let h = parse(&d).unwrap();
        assert_eq!(h.accounts[0].items[0].title, "Bank[0m");
        assert_eq!(h.accounts[0].items[0].tags, ["t\u{7}"], "tags are cleaned when mapped");
        assert_eq!(h.accounts[0].username, "u");
    }

    /// A string made of `n` copies of `unit`, comma separated.
    fn list(unit: &str, n: usize) -> String {
        vec![unit; n].join(",")
    }

    fn raw_doc(accounts: &str) -> String {
        format!(r#"{{"version": {{"major": 1}}, "accounts": [{accounts}]}}"#)
    }

    /// Every kept list entry counts, whatever its kind; exactly the limit is read.
    #[test]
    fn entries_limit_spans_kinds_and_is_inclusive() {
        // One item (1 entry), one collection (1) with one link (1), one tag (1), one app (1), one credential (1), the rest URLs.
        let fixed = 6;
        let make = |urls: usize| {
            raw_doc(&format!(
                r#"{{"id": "a", "collections": [{{"items": [{{"item": "i"}}]}}], "items": [{{"id": "i", "tags": ["t"], "credentials": [{{}}],
                    "scope": {{"androidApps": [{{"bundleId": "b"}}], "urls": [{}]}}}}]}}"#,
                list(r#""u""#, urls)
            ))
        };
        let at = make(ENTRIES_MAX - fixed);
        let h = parse(&at).unwrap();
        assert_eq!(h.accounts[0].items[0].urls.len(), ENTRIES_MAX - fixed);
        let over = make(ENTRIES_MAX - fixed + 1);
        assert!(matches!(parse(&over), Err(WalletError::InvalidInput(m)) if m.contains("1 000 000 list entries")));
        // Elements of the wrong shape are not kept, so they do not count.
        let wrong = raw_doc(&format!(r#"{{"id": "a", "items": [{{"tags": [{}]}}]}}"#, list("1", ENTRIES_MAX)));
        assert!(parse(&wrong).is_ok());
    }

    /// Collections are counted at every level; exactly the limit is read.
    #[test]
    fn collection_limit_is_inclusive() {
        let make = |n: usize| raw_doc(&format!(r#"{{"id": "a", "collections": [{{"subCollections": [{}]}}]}}"#, list("{}", n - 1)));
        let at = make(COLLECTIONS_MAX);
        assert_eq!(parse(&at).unwrap().accounts[0].collections[0].sub.len(), COLLECTIONS_MAX - 1);
        let over = make(COLLECTIONS_MAX + 1);
        assert!(matches!(parse(&over), Err(WalletError::InvalidInput(m)) if m.contains("100 000 collections")));
    }

    /// Members of the wrong JSON type read as absent; nothing is refused for it.
    #[test]
    fn members_of_the_wrong_type_read_as_absent() {
        let d = raw_doc(r#"{"id": 5, "username": [], "email": {}, "collections": "x", "items": [
            {"id": 1, "title": 2, "subtitle": null, "creationAt": 1.5, "scope": [], "tags": "t", "credentials": {}},
            {"scope": {"urls": "u", "androidApps": {"bundleId": "b"}}},
            {"scope": {"urls": [1, "u", null], "androidApps": [{"bundleId": 1}, "x", {"bundleId": "b"}]}},
            7, "s", null, true, []
        ]}, 3, "x", [], null"#);
        let h = parse(&d).unwrap();
        assert_eq!(h.accounts.len(), 1);
        let items = &h.accounts[0].items;
        assert_eq!(items.len(), 3, "only objects are items");
        assert!(items[0].id.is_empty() && items[0].title.is_empty() && items[0].subtitle.is_none() && items[0].creation_at.is_none());
        assert!(items[0].tags.is_empty() && items[0].credentials.is_empty() && items[0].urls.is_empty());
        assert!(items[1].urls.is_empty() && items[1].android_apps.is_empty());
        assert_eq!(items[2].urls, ["u"]);
        assert_eq!(items[2].android_apps, ["b"]);
        let d = raw_doc(r#"{"collections": [{"title": 1, "items": {"item": "i"}, "subCollections": {}}, 5, {"items": [{"item": 1}, "x", {"item": "i", "account": 2}]}]}"#);
        let h = parse(&d).unwrap();
        let cols = &h.accounts[0].collections;
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].title, "Collection");
        assert!(cols[0].items.is_empty() && cols[0].sub.is_empty());
        assert_eq!(cols[1].items, ["i"], "an account that is not a string does not filter");
        for root in [r#"{"version": 1, "accounts": []}"#, r#"{"version": {"major": "1"}, "accounts": []}"#, r#"{"version": {"major": 1}, "accounts": {}}"#] {
            assert!(matches!(parse(root), Err(WalletError::InvalidInput(_))), "{root}");
        }
        let h = parse(r#"{"version": {"major": 1, "minor": "x"}, "accounts": [], "exporterDisplayName": 5, "timestamp": -1}"#).unwrap();
        assert_eq!((h.exporter_display_name.as_str(), h.timestamp), ("another app", 0));
    }

    /// The last member of a name wins, as in a JSON object map.
    #[test]
    fn the_last_member_wins() {
        let h = parse(r#"{"version": {"major": 2}, "version": {"major": 1}, "accounts": 1, "accounts": [{"items": [{"title": "a", "title": "b"}]}]}"#).unwrap();
        assert_eq!(h.accounts[0].items[0].title, "b");
    }

    /// Trailing content after the document is refused.
    #[test]
    fn trailing_content_is_refused() {
        assert!(parse(r#"{"version": {"major": 1}, "accounts": []} x"#).is_err());
        assert!(parse(r#"{"version": {"major": 1}, "accounts": []}  "#).is_ok());
    }

    #[test]
    fn to_json_matches_serde_json() {
        let v = json!({"a": "é\u{0}\"", "b": [1, 2.5, null], "c": {"d": true}});
        assert_eq!(*to_json(&v).unwrap(), serde_json::to_string(&v).unwrap());
        let s = to_json(&json!("x".repeat(10_000))).unwrap();
        assert_eq!(s.len(), 10_002);
    }
}
