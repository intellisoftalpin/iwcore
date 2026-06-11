//! v5 -> v6 crypto migration tests, exercised against the REAL test vault
//! (`testdata/nswallet.dat`) plus fabricated edge cases.
//!
//! These simulate the production upgrade end to end before any deployment:
//! - golden snapshot equivalence (the user must see no difference);
//! - migration markers (version 6, crypto record, AEAD blobs, kept pre-v6 backup);
//! - idempotency, wrong-password-no-mutation, crash/rollback;
//! - undecryptable soft-deleted records are purged (active corruption aborts);
//! - change_password is a cheap DEK re-wrap (data blobs unchanged);
//! - backups restore and migrate in both directions;
//! - stored KDF params are honoured (future-hardening path).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use iwcore::backup::{is_backup_compatible, BackupManager};
use iwcore::crypto::{aead, dek, kdf, legacy};
use iwcore::Wallet;
use rusqlite::Connection;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "KuiperBelt30au";
const PRE_V6_BACKUP: &str = "nswallet.pre-v6.bak";

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

/// Copy the real test vault into a fresh temp folder; return (temp, folder).
fn fresh_real_vault() -> (TempDir, PathBuf) {
    let temp = TempDir::new().unwrap();
    let folder = temp.path().to_path_buf();
    fs::copy(testdata("nswallet.dat"), folder.join("nswallet.dat")).unwrap();
    (temp, folder)
}

// ── snapshots ───────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    active_items: BTreeMap<String, String>,
    active_fields: BTreeMap<(String, String), String>,
    deleted_items: BTreeMap<String, String>,
    deleted_fields: BTreeMap<(String, String), String>,
}

/// Build a snapshot of READABLE plaintext from a legacy (v5) database file by
/// reading raw rows and decrypting with the legacy scheme. Undecryptable
/// soft-deleted rows are excluded (the app never showed them).
fn legacy_snapshot(db_path: &Path, password: &str) -> Snapshot {
    let conn = Connection::open(db_path).unwrap();
    let enc_count: u32 = conn
        .query_row("SELECT email FROM nswallet_properties LIMIT 1", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap()
        .parse()
        .unwrap_or(0);

    let mut active_items = BTreeMap::new();
    let mut deleted_items = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT item_id, name, deleted FROM nswallet_items")
            .unwrap();
        let rows: Vec<(String, Vec<u8>, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|x| x.unwrap())
            .collect();
        for (id, blob, deleted) in rows {
            if let Ok(pt) = legacy::decrypt(&blob, password, enc_count, None) {
                if deleted != 0 {
                    deleted_items.insert(id, pt);
                } else {
                    active_items.insert(id, pt);
                }
            }
        }
    }

    let mut active_fields = BTreeMap::new();
    let mut deleted_fields = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT item_id, field_id, value, deleted FROM nswallet_fields")
            .unwrap();
        let rows: Vec<(String, String, Vec<u8>, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(|x| x.unwrap())
            .collect();
        for (iid, fid, blob, deleted) in rows {
            if let Ok(pt) = legacy::decrypt(&blob, password, enc_count, None) {
                if deleted != 0 {
                    deleted_fields.insert((iid, fid), pt);
                } else {
                    active_fields.insert((iid, fid), pt);
                }
            }
        }
    }

    Snapshot { active_items, active_fields, deleted_items, deleted_fields }
}

/// Build the same snapshot via the public (v6) wallet API.
fn api_snapshot(wallet: &mut Wallet) -> Snapshot {
    let active_items = wallet
        .get_items()
        .unwrap()
        .iter()
        .filter(|i| !i.deleted)
        .map(|i| (i.item_id.clone(), i.name.clone()))
        .collect();
    let active_fields = wallet
        .get_fields()
        .unwrap()
        .iter()
        .filter(|f| !f.deleted)
        .map(|f| ((f.item_id.clone(), f.field_id.clone()), f.value.clone()))
        .collect();
    let deleted_items = wallet
        .get_deleted_items()
        .unwrap()
        .iter()
        .map(|i| (i.item_id.clone(), i.name.clone()))
        .collect();
    let deleted_fields = wallet
        .get_deleted_fields()
        .unwrap()
        .iter()
        .map(|f| ((f.item_id.clone(), f.field_id.clone()), f.value.clone()))
        .collect();
    Snapshot { active_items, active_fields, deleted_items, deleted_fields }
}

// ── raw helpers ─────────────────────────────────────────────────────────────

fn db_version(db_path: &Path) -> String {
    let conn = Connection::open(db_path).unwrap();
    conn.query_row("SELECT version FROM nswallet_properties LIMIT 1", [], |r| r.get(0))
        .unwrap()
}

fn crypto_table_exists(db_path: &Path) -> bool {
    let conn = Connection::open(db_path).unwrap();
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='nswallet_crypto'",
        [],
        |_| Ok(true),
    )
    .optional_exists()
}

trait OptExists {
    fn optional_exists(self) -> bool;
}
impl OptExists for rusqlite::Result<bool> {
    fn optional_exists(self) -> bool {
        matches!(self, Ok(true))
    }
}

/// All `(rowkey -> blob)` for items and fields, for byte-level comparisons.
fn all_blobs(db_path: &Path) -> BTreeMap<String, Vec<u8>> {
    let conn = Connection::open(db_path).unwrap();
    let mut out = BTreeMap::new();
    let mut s = conn.prepare("SELECT item_id, name FROM nswallet_items").unwrap();
    for row in s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))).unwrap() {
        let (id, blob) = row.unwrap();
        out.insert(format!("item:{id}"), blob);
    }
    let mut s = conn.prepare("SELECT item_id, field_id, value FROM nswallet_fields").unwrap();
    for row in s
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?)))
        .unwrap()
    {
        let (iid, fid, blob) = row.unwrap();
        out.insert(format!("field:{iid}/{fid}"), blob);
    }
    out
}

// ── A. golden snapshot equivalence ──────────────────────────────────────────

#[test]
fn migration_preserves_all_readable_data() {
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");

    // Capture readable plaintext BEFORE migrating, via the legacy scheme.
    let before = legacy_snapshot(&db, TEST_PASSWORD);
    assert!(!before.active_items.is_empty(), "sanity: real vault has active items");
    assert!(!before.active_fields.is_empty(), "sanity: real vault has active fields");

    // Migrate by unlocking, then snapshot via the v6 API.
    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    let after = api_snapshot(&mut wallet);

    assert_eq!(before.active_items, after.active_items, "active item names changed");
    assert_eq!(before.active_fields, after.active_fields, "active field values changed");
    assert_eq!(before.deleted_items, after.deleted_items, "readable deleted items changed");
    assert_eq!(before.deleted_fields, after.deleted_fields, "readable deleted fields changed");
}

// ── B. migration markers ────────────────────────────────────────────────────

#[test]
fn migration_sets_version_crypto_record_and_aead_blobs() {
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");

    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    drop(wallet);

    // Version bumped to the current DB version.
    assert_eq!(db_version(&db), iwcore::DB_VERSION);
    assert_eq!(iwcore::DB_VERSION, "6");

    // Crypto record present with the expected scheme/params.
    let conn = Connection::open(&db).unwrap();
    let (scheme, kdf_name, m, t, p, salt_len, wrapped_len): (i64, String, i64, i64, i64, i64, i64) =
        conn.query_row(
            "SELECT scheme, kdf, kdf_m_cost, kdf_t_cost, kdf_p_cost, length(kdf_salt), length(dek_wrapped)
             FROM nswallet_crypto WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
        )
        .unwrap();
    assert_eq!(scheme, 1);
    assert_eq!(kdf_name, "argon2id");
    assert!(m > 0 && t > 0 && p > 0);
    assert!(salt_len >= 16);
    assert!(wrapped_len >= 1 + 24 + 16); // tag + nonce + min(ct) + auth tag

    // Every remaining item/field blob is now a v6 AEAD blob (0x06 tag).
    for (key, blob) in all_blobs(&db) {
        assert!(aead::is_v6_blob(&blob), "{key} is not a v6 blob after migration");
    }
}

#[test]
fn migration_keeps_pre_v6_backup_equal_to_original() {
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");
    let before = legacy_snapshot(&db, TEST_PASSWORD);

    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    drop(wallet);

    // The kept snapshot exists and still reads as the original legacy vault.
    let bak = folder.join(PRE_V6_BACKUP);
    assert!(bak.exists(), "pre-v6 backup must be kept");
    let bak_snapshot = legacy_snapshot(&bak, TEST_PASSWORD);
    assert_eq!(before, bak_snapshot, "pre-v6 backup must equal the original readable data");
}

// ── C. idempotency ──────────────────────────────────────────────────────────

#[test]
fn second_unlock_does_not_remigrate() {
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");

    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    let blobs_after_first = all_blobs(&db);
    wallet.lock();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    drop(wallet);

    assert_eq!(db_version(&db), "6");
    // Re-opening and unlocking a v6 vault must not rewrite any blob.
    assert_eq!(blobs_after_first, all_blobs(&db), "second unlock must not re-migrate");
}

// ── D. wrong password does not mutate ───────────────────────────────────────

#[test]
fn wrong_password_does_not_migrate_or_mutate() {
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");

    let mut wallet = Wallet::open(&folder).unwrap();
    let blobs_before = all_blobs(&db);
    assert!(!wallet.unlock("definitely-wrong").unwrap());
    drop(wallet);

    assert_ne!(db_version(&db), "6", "must not bump version on wrong password");
    assert!(!crypto_table_exists(&db), "must not create crypto record on wrong password");
    assert!(!folder.join(PRE_V6_BACKUP).exists(), "must not snapshot on wrong password");
    assert_eq!(blobs_before, all_blobs(&db), "wrong password must not rewrite any blob");
}

// ── E. crash/rollback + purge policy ────────────────────────────────────────

#[test]
fn corrupt_active_record_aborts_and_rolls_back() {
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");

    // Corrupt one ACTIVE, non-root item's blob so it cannot be decrypted.
    {
        let conn = Connection::open(&db).unwrap();
        let victim: String = conn
            .query_row(
                "SELECT item_id FROM nswallet_items WHERE deleted = 0 AND item_id != '__ROOT__' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE nswallet_items SET name = ? WHERE item_id = ?",
            rusqlite::params![vec![0u8; 48], victim],
        )
        .unwrap();
    }

    let mut wallet = Wallet::open(&folder).unwrap();
    // Password is correct (root still decrypts), but an active record is broken:
    // migration must abort with an error.
    assert!(wallet.unlock(TEST_PASSWORD).is_err(), "active corruption must abort migration");
    drop(wallet);

    // Rolled back: still v5-era, no crypto record.
    assert_ne!(db_version(&db), "6");
    assert!(!crypto_table_exists(&db), "aborted migration must roll back the crypto record");
}

#[test]
fn failed_migration_rolls_back_to_working_v5_and_recovers_on_retry() {
    // Simulates a transient mid-migration failure: the re-encryption aborts part
    // way, the transaction rolls back, the vault stays a fully-working v5, and a
    // later retry (once the fault clears) migrates cleanly with no data lost.
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");
    let before = legacy_snapshot(&db, TEST_PASSWORD);

    // Stash an active, non-root item's valid blob, then corrupt it so the
    // migration aborts mid-pass.
    let (victim, original_blob): (String, Vec<u8>) = {
        let conn = Connection::open(&db).unwrap();
        conn.query_row(
            "SELECT item_id, name FROM nswallet_items WHERE deleted = 0 AND item_id != '__ROOT__' LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };
    {
        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE nswallet_items SET name = ? WHERE item_id = ?",
            rusqlite::params![vec![0u8; 48], victim],
        )
        .unwrap();
    }

    // Attempt 1: migration aborts and rolls back.
    {
        let mut wallet = Wallet::open(&folder).unwrap();
        assert!(wallet.unlock(TEST_PASSWORD).is_err(), "mid-migration failure must abort");
    }
    assert_ne!(db_version(&db), "6", "must not be v6 after a failed migration");
    assert!(!crypto_table_exists(&db), "crypto record must have rolled back");

    // The vault is still a working v5: the password verifies via the legacy
    // path (read-only, no migration), and a wrong password is still rejected.
    {
        let wallet = Wallet::open(&folder).unwrap();
        assert!(wallet.check_password(TEST_PASSWORD).unwrap(), "v5 vault must still verify");
        assert!(!wallet.check_password("wrong").unwrap());
    }

    // Clear the transient fault (restore the original blob) and retry.
    {
        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE nswallet_items SET name = ? WHERE item_id = ?",
            rusqlite::params![original_blob, victim],
        )
        .unwrap();
    }

    // Attempt 2: migrates cleanly, all readable data intact.
    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap(), "retry must migrate cleanly");
    assert_eq!(db_version(&db), "6");
    assert_eq!(before, api_snapshot(&mut wallet), "no data lost across a failed + retried migration");
}

#[test]
fn undecryptable_deleted_records_are_purged() {
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");

    // Count undecryptable deleted items before migration (the real vault has some).
    let conn = Connection::open(&db).unwrap();
    let enc_count: u32 = conn
        .query_row("SELECT email FROM nswallet_properties LIMIT 1", [], |r| r.get::<_, String>(0))
        .unwrap()
        .parse()
        .unwrap_or(0);
    let mut stmt = conn
        .prepare("SELECT item_id, name FROM nswallet_items WHERE deleted = 1")
        .unwrap();
    let unreadable: Vec<String> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))
        .unwrap()
        .map(|x| x.unwrap())
        .filter(|(_, blob)| legacy::decrypt(blob, TEST_PASSWORD, enc_count, None).is_err())
        .map(|(id, _)| id)
        .collect();
    drop(stmt);
    drop(conn);
    assert!(!unreadable.is_empty(), "sanity: real vault has unreadable deleted items");

    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    drop(wallet);

    // Those rows are gone after migration.
    let conn = Connection::open(&db).unwrap();
    for id in unreadable {
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM nswallet_items WHERE item_id = ?", [&id], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "unreadable deleted item {id} should have been purged");
    }
}

// ── F. change_password is a cheap re-wrap ───────────────────────────────────

#[test]
fn change_password_rewraps_dek_without_touching_data() {
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");

    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    let snapshot_before = api_snapshot(&mut wallet);
    let blobs_before = all_blobs(&db);
    let salt_before: Vec<u8> = Connection::open(&db)
        .unwrap()
        .query_row("SELECT kdf_salt FROM nswallet_crypto WHERE id = 1", [], |r| r.get(0))
        .unwrap();

    assert!(wallet.change_password("a-brand-new-password").unwrap());

    // Data blobs are byte-identical: only the wrapped DEK / salt changed.
    assert_eq!(blobs_before, all_blobs(&db), "change_password must not rewrite data blobs");
    let salt_after: Vec<u8> = Connection::open(&db)
        .unwrap()
        .query_row("SELECT kdf_salt FROM nswallet_crypto WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    assert_ne!(salt_before, salt_after, "a fresh salt must be used");

    // Old password no longer unlocks; new one does, with identical data.
    wallet.lock();
    assert!(!wallet.unlock(TEST_PASSWORD).unwrap());
    assert!(wallet.unlock("a-brand-new-password").unwrap());
    assert_eq!(snapshot_before, api_snapshot(&mut wallet));
}

// ── G. fresh wallet is born v6 ──────────────────────────────────────────────

#[test]
fn fresh_wallet_is_v6() {
    let temp = TempDir::new().unwrap();
    let folder = temp.path().to_path_buf();
    let db = folder.join("nswallet.dat");

    let mut wallet = Wallet::create(&folder, "pw12345", "en").unwrap();
    let item = wallet.add_item("Email", "mail", false, None).unwrap();
    wallet.add_field(&item, "PASS", "s3cr3t", None).unwrap();
    drop(wallet);

    assert_eq!(db_version(&db), "6");
    assert!(crypto_table_exists(&db));
    for (key, blob) in all_blobs(&db) {
        assert!(aead::is_v6_blob(&blob), "{key} should be a v6 blob in a fresh wallet");
    }

    // Reopen + unlock round-trips the data.
    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock("pw12345").unwrap());
    let fields = wallet.get_fields_by_item(&item).unwrap();
    assert_eq!(fields[0].value, "s3cr3t");
}

// ── H. backup matrix (both directions) ──────────────────────────────────────

#[test]
fn old_v5_backup_restores_and_migrates() {
    // Zip the real (legacy) vault as a backup, restore it, then unlock+migrate.
    let backups = TempDir::new().unwrap();
    let mgr = BackupManager::new(backups.path());
    let zip = mgr.create_backup_from_path(&testdata("nswallet.dat"), true).unwrap();

    let restore_dir = TempDir::new().unwrap();
    let db = mgr.extract_backup(&zip, restore_dir.path()).unwrap();
    assert_eq!(db, restore_dir.path().join("nswallet.dat"));

    let before = legacy_snapshot(&testdata("nswallet.dat"), TEST_PASSWORD);
    let mut wallet = Wallet::open(restore_dir.path()).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    assert_eq!(db_version(&restore_dir.path().join("nswallet.dat")), "6");
    assert_eq!(before, api_snapshot(&mut wallet));
}

#[test]
fn new_v6_backup_roundtrips() {
    // Migrate a vault, back it up, restore elsewhere, unlock via the v6 path.
    let (_t, folder) = fresh_real_vault();
    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    let migrated = api_snapshot(&mut wallet);
    drop(wallet);

    let backups = TempDir::new().unwrap();
    let mgr = BackupManager::new(backups.path());
    let zip = mgr.create_backup_from_path(&folder.join("nswallet.dat"), true).unwrap();

    let restore_dir = TempDir::new().unwrap();
    mgr.extract_backup(&zip, restore_dir.path()).unwrap();
    assert_eq!(db_version(&restore_dir.path().join("nswallet.dat")), "6");

    let mut wallet2 = Wallet::open(restore_dir.path()).unwrap();
    assert!(wallet2.unlock(TEST_PASSWORD).unwrap());
    assert_eq!(migrated, api_snapshot(&mut wallet2));
}

#[test]
fn v6_backup_compatibility_matrix() {
    // Produce a v6 backup.
    let (_t, folder) = fresh_real_vault();
    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    drop(wallet);

    let backups = TempDir::new().unwrap();
    let mgr = BackupManager::new(backups.path());
    let zip = mgr.create_backup_from_path(&folder.join("nswallet.dat"), true).unwrap();

    // A current (v6) app accepts it; a pre-v6 (v5) app rejects it.
    assert!(is_backup_compatible(&zip, "6").unwrap(), "v6 app must accept a v6 backup");
    assert!(!is_backup_compatible(&zip, "5").unwrap(), "v5 app must reject a v6 backup");
}

// ── J. stored KDF params are honoured (future-hardening path) ───────────────

#[test]
fn unlock_uses_stored_kdf_params_not_consts() {
    // Create a v6 wallet, then rewrite its crypto record to use NON-default
    // Argon2id params (with a correctly re-wrapped DEK). Unlock must still work,
    // proving the stored params - not the code consts - drive derivation.
    let temp = TempDir::new().unwrap();
    let folder = temp.path().to_path_buf();
    let db = folder.join("nswallet.dat");
    let pw = "hardening-pw";

    let mut wallet = Wallet::create(&folder, pw, "en").unwrap();
    let item = wallet.add_item("Acct", "doc", false, None).unwrap();
    wallet.add_field(&item, "PASS", "p@ss", None).unwrap();
    drop(wallet);

    // Recover the DEK using the ORIGINAL (default) params, then re-wrap under
    // deliberately different params + a fresh salt.
    let conn = Connection::open(&db).unwrap();
    let (m, t, p, salt, wrapped): (i64, i64, i64, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT kdf_m_cost, kdf_t_cost, kdf_p_cost, kdf_salt, dek_wrapped FROM nswallet_crypto WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    let orig = kdf::KdfParams { m_cost_kib: m as u32, t_cost: t as u32, p_cost: p as u32 };
    let kek = kdf::derive_kek(pw.as_bytes(), &salt, orig).unwrap();
    let dek_bytes = dek::unwrap_dek(&kek, &wrapped).unwrap();

    let custom = kdf::KdfParams { m_cost_kib: 8192, t_cost: 1, p_cost: 1 }; // distinct, fast
    assert_ne!((custom.m_cost_kib, custom.t_cost), (orig.m_cost_kib, orig.t_cost));
    let new_salt = vec![0xABu8; 16];
    let new_kek = kdf::derive_kek(pw.as_bytes(), &new_salt, custom).unwrap();
    let new_wrapped = dek::wrap_dek(&new_kek, &dek_bytes).unwrap();
    conn.execute(
        "UPDATE nswallet_crypto SET kdf_m_cost = ?, kdf_t_cost = ?, kdf_p_cost = ?, kdf_salt = ?, dek_wrapped = ? WHERE id = 1",
        rusqlite::params![custom.m_cost_kib as i64, custom.t_cost as i64, custom.p_cost as i64, new_salt, new_wrapped],
    )
    .unwrap();
    drop(conn);

    // Unlock must succeed using the stored custom params, and data must read.
    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(pw).unwrap(), "unlock must use stored (custom) KDF params");
    let fields = wallet.get_fields_by_item(&item).unwrap();
    assert_eq!(fields[0].value, "p@ss");
    assert_eq!(dek_bytes.len(), dek::DEK_LEN);
}
