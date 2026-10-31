//! Old-format backups written by published iwcore versions must restore with
//! the current code, with every label, item and field intact.
//!
//! Fixtures and how they were made: `testdata/backups/README.md`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use iwcore::autofill::{index, IndexOptions};
use iwcore::backup::{get_backup_db_version, BackupManager};
use iwcore::{IWField, IWItem, IWLabel, Wallet};
use serde_json::Value;
use tempfile::TempDir;

const VERSIONS: &[&str] = &["0.1.3", "0.1.27", "0.2.0", "0.2.9", "0.3.0", "0.4.0"];

fn fixture_dir(version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("backups")
        .join(format!("v{version}"))
}

fn manifest(version: &str) -> Value {
    let text = fs::read_to_string(fixture_dir(version).join("manifest.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn backup_zip(version: &str, m: &Value) -> PathBuf {
    fixture_dir(version).join(m["backup_file"].as_str().unwrap())
}

/// Restore a fixture's backup into a fresh folder and unlock it.
fn restore(version: &str) -> (TempDir, Wallet, Value) {
    let m = manifest(version);
    let temp = TempDir::new().unwrap();
    let mgr = BackupManager::new(&temp.path().join("backups"));
    let target = temp.path().join("wallet");
    mgr.extract_backup(&backup_zip(version, &m), &target).unwrap();

    let mut wallet = Wallet::open(&target).unwrap();
    let password = m["password"].as_str().unwrap();
    assert!(wallet.unlock(password).unwrap(), "{version}: unlock failed");
    (temp, wallet, m)
}

fn from_manifest<T: serde::de::DeserializeOwned>(m: &Value, key: &str) -> Vec<T> {
    serde_json::from_value(m[key].clone()).unwrap()
}

fn hex32(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

#[test]
fn every_fixture_backup_is_recognised() {
    for v in VERSIONS {
        let m = manifest(v);
        let zip = backup_zip(v, &m);
        let mgr = BackupManager::new(Path::new(env!("CARGO_MANIFEST_DIR")));
        assert!(mgr.verify_backup(&zip).unwrap(), "{v}: verify_backup");
        get_backup_db_version(&zip).unwrap_or_else(|e| panic!("{v}: db version: {e}"));
    }
}

#[test]
fn every_item_survives_restore() {
    for v in VERSIONS {
        let (_t, mut wallet, m) = restore(v);
        let expected: Vec<IWItem> = from_manifest(&m, "items");
        let actual: HashMap<String, IWItem> = wallet
            .get_items()
            .unwrap()
            .iter()
            .map(|i| (i.item_id.clone(), i.clone()))
            .collect();

        for e in &expected {
            let a = actual
                .get(&e.item_id)
                .unwrap_or_else(|| panic!("{v}: item {} ({}) missing", e.item_id, e.name));
            assert_eq!(a.name, e.name, "{v}: name of {}", e.item_id);
            assert_eq!(a.icon, e.icon, "{v}: icon of {}", e.item_id);
            assert_eq!(a.folder, e.folder, "{v}: folder flag of {}", e.item_id);
            assert_eq!(a.parent_id, e.parent_id, "{v}: parent of {}", e.item_id);
            assert!(!a.deleted, "{v}: {} came back deleted", e.item_id);
        }
        assert_eq!(actual.len(), expected.len(), "{v}: item count");
    }
}

#[test]
fn every_field_value_survives_restore() {
    for v in VERSIONS {
        let (_t, mut wallet, m) = restore(v);
        let expected: Vec<IWField> = from_manifest(&m, "fields");
        let actual: HashMap<(String, String), IWField> = wallet
            .get_fields()
            .unwrap()
            .iter()
            .map(|f| ((f.item_id.clone(), f.field_id.clone()), f.clone()))
            .collect();

        for e in &expected {
            let key = (e.item_id.clone(), e.field_id.clone());
            let a = actual
                .get(&key)
                .unwrap_or_else(|| panic!("{v}: field {:?} ({}) missing", key, e.field_type));
            assert_eq!(a.field_type, e.field_type, "{v}: type of {:?}", key);
            assert_eq!(a.value, e.value, "{v}: value of {:?} ({})", key, e.field_type);
            assert_eq!(a.sort_weight, e.sort_weight, "{v}: sort weight of {:?}", key);
            assert!(!a.deleted, "{v}: {:?} came back deleted", key);
        }
        assert_eq!(actual.len(), expected.len(), "{v}: field count");
    }
}

#[test]
fn every_label_survives_restore() {
    for v in VERSIONS {
        let (_t, mut wallet, m) = restore(v);
        let expected: Vec<IWLabel> = from_manifest(&m, "labels");
        let actual: HashMap<String, IWLabel> = wallet
            .get_labels()
            .unwrap()
            .into_iter()
            .map(|l| (l.field_type.clone(), l))
            .collect();

        for e in &expected {
            let a = actual
                .get(&e.field_type)
                .unwrap_or_else(|| panic!("{v}: label {} missing", e.field_type));
            assert_eq!(a.value_type, e.value_type, "{v}: value type of {}", e.field_type);
            assert_eq!(a.system, e.system, "{v}: system flag of {}", e.field_type);
            if !e.system {
                assert_eq!(a.name, e.name, "{v}: custom label name");
            }
        }
    }
}

#[test]
fn trashed_item_stays_in_the_trash() {
    for v in VERSIONS {
        let (_t, mut wallet, m) = restore(v);
        let trashed = m["trashed_item_id"].as_str().unwrap();
        assert!(
            wallet.get_deleted_items().unwrap().iter().any(|i| i.item_id == trashed),
            "{v}: trashed item not in the trash"
        );
        assert!(
            !wallet.get_items().unwrap().iter().any(|i| i.item_id == trashed),
            "{v}: trashed item visible"
        );
    }
}

#[test]
fn restored_vault_accepts_new_data_and_backs_up_again() {
    for v in VERSIONS {
        let (temp, mut wallet, m) = restore(v);
        let item = wallet.add_item("Added after restore", "document", false, None).unwrap();
        wallet.add_field(&item, "PASS", "new-secret", None).unwrap();

        let mgr = BackupManager::new(&temp.path().join("again"));
        let zip = mgr.create_backup(wallet.database().unwrap(), true).unwrap();
        wallet.close();

        let target = temp.path().join("second");
        mgr.extract_backup(&zip, &target).unwrap();
        let mut second = Wallet::open(&target).unwrap();
        assert!(second.unlock(m["password"].as_str().unwrap()).unwrap(), "{v}");
        let fields = second.get_fields_by_item(&item).unwrap();
        assert!(fields.iter().any(|f| f.value == "new-secret"), "{v}: new data lost");
    }
}

#[test]
fn v1_autofill_index_from_0_4_0_still_opens() {
    let dir = fixture_dir("0.4.0");
    let m = manifest("0.4.0");
    let key = hex32(m["autofill"]["index_key"].as_str().unwrap());
    let bytes = fs::read(dir.join("autofill-index-v1.bin")).unwrap();

    let (header, entries) = index::open(&bytes, &key).unwrap();
    assert_eq!(header.format_version, 1);
    assert!(
        entries.iter().any(|e| e.title == "Example Login" && e.username == "fixture_user"),
        "the fixture's login must be in the index"
    );

    // And the restored vault rebuilds an index that opens the same way.
    let (_t, mut wallet, _) = restore("0.4.0");
    let rebuilt = wallet
        .build_autofill_index(&key, 2, 1_790_000_500, IndexOptions::default())
        .unwrap();
    let (_, rebuilt_entries) = index::open(&rebuilt, &key).unwrap();
    assert_eq!(rebuilt_entries.len(), entries.len());
}

#[test]
fn v1_journal_from_0_4_0_drains_into_the_restored_vault() {
    let dir = fixture_dir("0.4.0");
    let (_t, mut wallet, m) = restore("0.4.0");
    let secret = hex32(m["autofill"]["journal_secret"].as_str().unwrap());
    let journal = fs::read(dir.join("autofill-journal-v1.bin")).unwrap();

    let summary = wallet.drain_autofill_journal(&journal, &secret, None).unwrap();
    assert_eq!(summary.created.len(), 1, "the staged login must be imported");
    let fields = wallet.get_fields_by_item(&summary.created[0]).unwrap();
    assert!(fields.iter().any(|f| f.field_type == "PASS" && f.value == "staged-pass-1"));

    // Draining the same journal again changes nothing.
    let again = wallet.drain_autofill_journal(&journal, &secret, Some(&summary.folder_id)).unwrap();
    assert!(again.created.is_empty(), "second drain must not duplicate");
}

/// Replace the one volatile value in each export, the export time.
fn normalise_export(kind: &str, bytes: &[u8]) -> String {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    match kind {
        "json" => {
            let mut v: Value = serde_json::from_str(&text).unwrap();
            v["exported_at"] = Value::String("<exported_at>".into());
            // Computed from today's date, not stored: they would make the
            // golden file fail on the day a fixture date starts "expiring".
            for f in v["fields"].as_array_mut().unwrap() {
                let f = f.as_object_mut().unwrap();
                f.remove("expired");
                f.remove("expiring");
            }
            serde_json::to_string_pretty(&v).unwrap()
        }
        "xml" => {
            let start = text.find("exported_at=\"").unwrap() + "exported_at=\"".len();
            let end = start + text[start..].find('"').unwrap();
            format!("{}<exported_at>{}", &text[..start], &text[end..])
        }
        _ => text,
    }
}

/// CSV, JSON and XML exports of the 0.4.0 fixture must stay byte-identical to
/// what iwcore 0.4.0 produced. Run once with `IWCORE_WRITE_GOLDEN=1` to (re)write
/// the golden files, which is only ever done on purpose.
#[test]
fn exports_match_the_0_4_0_golden_files() {
    let (_t, mut wallet, _) = restore("0.4.0");
    let golden = fixture_dir("0.4.0").join("golden");
    let write = std::env::var("IWCORE_WRITE_GOLDEN").is_ok();
    if write {
        fs::create_dir_all(&golden).unwrap();
    }

    let exports = [
        ("csv", wallet.export_csv().unwrap()),
        ("json", wallet.export_json().unwrap()),
        ("xml", wallet.export_xml().unwrap()),
    ];
    for (kind, bytes) in exports {
        let actual = normalise_export(kind, &bytes);
        let path = golden.join(format!("export.{kind}"));
        if write {
            fs::write(&path, &actual).unwrap();
        } else {
            let expected = fs::read_to_string(&path).unwrap();
            assert_eq!(actual, expected, "{kind} export changed");
        }
    }
}
