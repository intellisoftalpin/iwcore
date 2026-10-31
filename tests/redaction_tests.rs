//! `Debug` output of every public type that carries a decrypted secret must not
//! contain the secret, in either `{:?}` or `{:#?}` form. Apps log `{:?}` freely;
//! a password must never end up in a log because of it.

use iwcore::autofill::{journal, IndexOptions, PendingOp, PendingRecord, generate_keys, index};
use iwcore::Wallet;
use tempfile::TempDir;

const PASSWORD: &str = "SecretPass-6c1f9e";
const TOTP: &str = "JBSWY3DPEHPK3PXQ";

fn assert_hidden(what: &str, debug: String) {
    for secret in [PASSWORD, TOTP] {
        assert!(!debug.contains(secret), "{what} leaks a secret in Debug: {debug}");
    }
    assert!(debug.contains("[redacted]"), "{what} should mark redaction: {debug}");
}

fn wallet() -> (TempDir, Wallet, String) {
    let temp = TempDir::new().unwrap();
    let mut w = Wallet::create(temp.path(), "wallet-pass-1", "en").unwrap();
    if !w.is_unlocked() {
        w.unlock("wallet-pass-1").unwrap();
    }
    let item = w.add_item("Example", "web", false, None).unwrap();
    w.add_field(&item, "USER", "someone", Some(0)).unwrap();
    w.add_field(&item, "PASS", PASSWORD, Some(1)).unwrap();
    w.add_field(&item, "LINK", "https://example.com", Some(2)).unwrap();
    w.add_field(&item, "2FAC", TOTP, Some(3)).unwrap();
    (temp, w, item)
}

#[test]
fn iwfield_debug_is_redacted() {
    let (_t, mut w, item) = wallet();
    for f in w.get_fields_by_item(&item).unwrap() {
        if f.field_type == "PASS" || f.field_type == "2FAC" {
            assert_hidden("IWField", format!("{f:?}"));
            assert_hidden("IWField pretty", format!("{f:#?}"));
        }
    }
}

#[test]
fn search_results_are_redacted() {
    let (_t, mut w, _) = wallet();
    let results = w.search("SecretPass").unwrap();
    assert!(!results.is_empty(), "the password field should match");
    assert_hidden("SearchResult", format!("{results:?}"));
}

#[test]
fn field_value_usage_is_redacted() {
    let (_t, mut w, _) = wallet();
    let top = w.get_top_field_values_by_type("PASS", 5).unwrap();
    assert!(!top.is_empty());
    assert_hidden("FieldValueUsage", format!("{top:?}"));
}

#[test]
fn index_entries_are_redacted() {
    let (_t, mut w, _) = wallet();
    let keys = generate_keys().unwrap();
    let options = IndexOptions { include_totp: true };
    let sealed = w.build_autofill_index(&keys.index_key, 1, 0, options).unwrap();
    let (_, entries) = index::open(&sealed, &keys.index_key).unwrap();
    assert!(!entries.is_empty());
    assert!(entries.iter().any(|e| e.totp_secret.is_some()));
    assert_hidden("IndexEntry", format!("{entries:?}"));
    assert_hidden("IndexEntry pretty", format!("{entries:#?}"));
}

#[test]
fn pending_records_are_redacted() {
    let record = PendingRecord {
        record_id: "r1".into(),
        op: PendingOp::Create,
        item_id: None,
        title: "Example".into(),
        url: "https://example.com".into(),
        identity_value: "someone".into(),
        identity_hint: None,
        password: PASSWORD.into(),
        totp_secret: Some(TOTP.into()),
        created_at: 0,
    };
    assert_hidden("PendingRecord", format!("{record:?}"));

    let keys = generate_keys().unwrap();
    let sealed = journal::seal_record(&record, &keys.journal_public, &keys.index_key).unwrap();
    let opened = journal::open_with_journal_key(&sealed, &keys.journal_secret);
    assert_eq!(opened.len(), 1);
    assert_hidden("PendingRecord opened", format!("{opened:#?}"));
}
