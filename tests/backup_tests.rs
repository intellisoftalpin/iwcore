//! Backup/restore round-trip and password-verification tests against real
//! (v6) wallets, covering the public backup surface end to end.

use std::path::PathBuf;

use iwcore::backup::{
    check_backup_password_in, get_backup_db_version, is_backup_compatible, BackupManager,
};
use iwcore::Wallet;
use tempfile::TempDir;

const PASSWORD: &str = "correct-horse-9";

/// Create a v6 wallet with some data; return (temp, folder).
fn wallet_with_data() -> (TempDir, PathBuf) {
    let temp = TempDir::new().unwrap();
    let folder = temp.path().to_path_buf();
    let mut w = Wallet::create(&folder, PASSWORD, "en").unwrap();
    let item = w.add_item("Account", "document", false, None).unwrap();
    w.add_field(&item, "MAIL", "a@b.com", None).unwrap();
    w.add_field(&item, "PASS", "secret-value", None).unwrap();
    drop(w);
    (temp, folder)
}

#[test]
fn backup_from_database_handle_verify_and_restore() {
    let (_t, folder) = wallet_with_data();
    let backups = TempDir::new().unwrap();
    let mgr = BackupManager::new(backups.path());

    // create_backup takes a live &Database handle (the WAL-checkpointing path).
    let zip = {
        let w = Wallet::open(&folder).unwrap();
        mgr.create_backup(w.database().unwrap(), true).unwrap()
    };
    assert!(zip.exists());
    assert!(zip.file_name().unwrap().to_str().unwrap().contains("manual"));

    // Verify + version + compatibility.
    assert!(mgr.verify_backup(&zip).unwrap());
    assert_eq!(get_backup_db_version(&zip).unwrap(), "6");
    assert!(is_backup_compatible(&zip, "6").unwrap());

    // Restore into a fresh folder and unlock.
    let restore = TempDir::new().unwrap();
    let db = mgr.extract_backup(&zip, restore.path()).unwrap();
    assert!(db.exists());
    let mut restored = Wallet::open(restore.path()).unwrap();
    assert!(restored.unlock(PASSWORD).unwrap());
    let item = restored.get_items().unwrap().iter().find(|i| i.name == "Account").cloned();
    assert!(item.is_some(), "restored vault must contain the original entry");
}

#[test]
fn check_backup_password_accepts_correct_rejects_wrong() {
    let (_t, folder) = wallet_with_data();
    let backups = TempDir::new().unwrap();
    let mgr = BackupManager::new(backups.path());
    let zip = mgr
        .create_backup_from_path(&folder.join("nswallet.dat"), false)
        .unwrap();
    assert!(zip.file_name().unwrap().to_str().unwrap().contains("auto"));

    let tmp_base = TempDir::new().unwrap();
    assert!(
        check_backup_password_in(&zip, PASSWORD, tmp_base.path()).unwrap(),
        "correct password must verify against the backup"
    );
    assert!(
        !check_backup_password_in(&zip, "wrong-password", tmp_base.path()).unwrap(),
        "wrong password must be rejected"
    );
}

#[test]
fn verify_backup_rejects_non_zip() {
    let dir = TempDir::new().unwrap();
    let mgr = BackupManager::new(dir.path());
    let bad = dir.path().join("garbage.zip");
    std::fs::write(&bad, b"this is not a zip file").unwrap();
    // Either a hard error or a false result is acceptable; both mean "not valid".
    let ok = mgr.verify_backup(&bad).unwrap_or(false);
    assert!(!ok, "a non-zip file must not verify as a valid backup");
}
