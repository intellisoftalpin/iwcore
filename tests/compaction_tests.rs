//! After the v5 -> v6 upgrade the database file, its WAL and every backup
//! taken afterwards hold no bytes of the records in the old format, and the
//! pre-v6 snapshot is only retired by a backup of the same vault taken after
//! the file was rebuilt.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use iwcore::backup::BackupManager;
use iwcore::Wallet;
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "KuiperBelt30au";
const PRE_V6_BACKUP: &str = "nswallet.pre-v6.bak";
const CHUNK: usize = 16;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

fn fresh_real_vault() -> (TempDir, PathBuf) {
    let temp = TempDir::new().unwrap();
    let folder = temp.path().to_path_buf();
    fs::copy(testdata("nswallet.dat"), folder.join("nswallet.dat")).unwrap();
    (temp, folder)
}

/// Every item name and field value blob of the original v5 test vault.
fn legacy_blobs() -> Vec<Vec<u8>> {
    let conn = Connection::open(testdata("nswallet.dat")).unwrap();
    let mut blobs = Vec::new();
    for sql in ["SELECT name FROM nswallet_items", "SELECT value FROM nswallet_fields"] {
        let mut stmt = conn.prepare(sql).unwrap();
        let rows = stmt
            .query_map([], |r| r.get::<_, Option<Vec<u8>>>(0))
            .unwrap()
            .map(|r| r.unwrap());
        blobs.extend(rows.flatten().filter(|b| b.len() >= CHUNK));
    }
    assert!(blobs.len() > 3000, "the test vault has its legacy records");
    blobs
}

/// Blobs kept on purpose in the quarantine table (undecryptable records).
fn quarantined_blobs(db: &Path) -> HashSet<Vec<u8>> {
    let conn = Connection::open(db).unwrap();
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='nswallet_quarantine'",
            [],
            |_| Ok(()),
        )
        .is_ok();
    let mut out = HashSet::new();
    if !exists {
        return out;
    }
    let mut stmt = conn.prepare("SELECT * FROM nswallet_quarantine").unwrap();
    let cols = stmt.column_count();
    let mut rows = stmt.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        for i in 0..cols {
            if let ValueRef::Blob(b) = row.get_ref(i).unwrap() {
                out.insert(b.to_vec());
            }
        }
    }
    out
}

/// Every 16-byte chunk of the legacy blobs (minus quarantined ones). A
/// single leftover cipher block is enough to test password guesses, so the
/// search is per chunk, not per whole blob.
fn legacy_chunks(skip: &HashSet<Vec<u8>>) -> HashSet<[u8; CHUNK]> {
    legacy_blobs()
        .iter()
        .filter(|b| !skip.contains(*b))
        .flat_map(|b| b.chunks_exact(CHUNK).map(|c| <[u8; CHUNK]>::try_from(c).unwrap()).collect::<Vec<_>>())
        .filter(|c| c.iter().any(|&x| x != c[0]))
        .collect()
}

/// How many legacy chunks occur anywhere in `bytes`.
fn count_legacy(bytes: &[u8], chunks: &HashSet<[u8; CHUNK]>) -> usize {
    bytes
        .windows(CHUNK)
        .filter(|w| chunks.contains(<&[u8; CHUNK]>::try_from(*w).unwrap()))
        .count()
}

fn read_or_empty(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

fn wal(folder: &Path) -> PathBuf {
    folder.join("nswallet.dat-wal")
}

fn zip_entry(zip_path: &Path) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(fs::File::open(zip_path).unwrap()).unwrap();
    let mut entry = archive.by_name("nswallet.dat").unwrap();
    let mut out = Vec::new();
    entry.read_to_end(&mut out).unwrap();
    out
}

fn compacted_at(db: &Path) -> Option<String> {
    let conn = Connection::open(db).unwrap();
    conn.query_row("SELECT compacted_at FROM nswallet_compaction WHERE id = 1", [], |r| r.get(0))
        .ok()
}

#[test]
fn upgrade_leaves_no_legacy_bytes_in_the_database_wal_or_backup() {
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");
    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    assert!(compacted_at(&db).is_some());

    let chunks = legacy_chunks(&quarantined_blobs(&db));
    // The snapshot (old format by design) proves the search finds them.
    assert!(count_legacy(&fs::read(folder.join(PRE_V6_BACKUP)).unwrap(), &chunks) > 3000);

    let backups = TempDir::new().unwrap();
    let backup = BackupManager::new(backups.path())
        .create_backup(wallet.database().unwrap(), true)
        .unwrap();

    assert_eq!(count_legacy(&fs::read(&db).unwrap(), &chunks), 0, "database file");
    assert_eq!(count_legacy(&read_or_empty(&wal(&folder)), &chunks), 0, "WAL");
    assert_eq!(count_legacy(&zip_entry(&backup), &chunks), 0, "backup");

    assert!(wallet.retire_pre_v6_snapshot(backups.path()).unwrap());
    drop(wallet);
    assert_eq!(count_legacy(&fs::read(&db).unwrap(), &chunks), 0, "database file after close");
    assert_eq!(count_legacy(&read_or_empty(&wal(&folder)), &chunks), 0, "WAL after close");
}

/// Turn a cleanly upgraded vault into one upgraded the old way: legacy
/// blobs left in the unused space of its pages and no compaction marker.
/// The vault uses auto_vacuum, which drops wholly free pages, so each legacy
/// row shares its page with a zero-filled row that stays.
fn plant_legacy_remnants(db: &Path) {
    let conn = Connection::open(db).unwrap();
    conn.execute_batch(
        "PRAGMA secure_delete = OFF; CREATE TABLE leftover (old INTEGER, b BLOB);",
    )
    .unwrap();
    {
        let mut insert = conn.prepare("INSERT INTO leftover (old, b) VALUES (?, ?)").unwrap();
        for blob in legacy_blobs() {
            let filler = vec![0u8; blob.len()];
            insert.execute(rusqlite::params![1, blob]).unwrap();
            insert.execute(rusqlite::params![0, filler]).unwrap();
        }
    }
    conn.execute_batch(
        "PRAGMA wal_checkpoint(TRUNCATE);
         DELETE FROM leftover WHERE old = 1;
         DROP TABLE nswallet_compaction;
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .unwrap();
}

#[test]
fn a_vault_upgraded_without_compaction_is_compacted_once_at_unlock() {
    let (_t, folder) = fresh_real_vault();
    let db = folder.join("nswallet.dat");
    {
        let mut wallet = Wallet::open(&folder).unwrap();
        assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    }
    plant_legacy_remnants(&db);
    let chunks = legacy_chunks(&quarantined_blobs(&db));
    assert!(count_legacy(&fs::read(&db).unwrap(), &chunks) > 1000, "remnants planted");
    assert!(compacted_at(&db).is_none());

    // A backup taken now still carries them, and so does not count.
    let backups = TempDir::new().unwrap();
    let old_backup = BackupManager::new(backups.path()).create_backup_from_path(&db, true).unwrap();
    assert!(count_legacy(&zip_entry(&old_backup), &chunks) > 1000);

    // Opening alone changes nothing; a wrong password changes nothing.
    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(!wallet.unlock("wrong password").unwrap());
    assert!(compacted_at(&db).is_none());

    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    let marker = compacted_at(&db).expect("marker written at unlock");
    assert_eq!(count_legacy(&fs::read(&db).unwrap(), &chunks), 0, "database file");
    assert_eq!(count_legacy(&read_or_empty(&wal(&folder)), &chunks), 0, "WAL");
    assert!(wallet.get_items().unwrap().len() > 100, "data intact");

    // The backup from before the rebuild does not retire the snapshot.
    assert!(!wallet.retire_pre_v6_snapshot(backups.path()).unwrap());
    assert!(wallet.has_pre_v6_snapshot());

    // Later unlocks do not rebuild again.
    wallet.lock();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());
    assert_eq!(compacted_at(&db), Some(marker));

    // A backup taken after the rebuild does.
    let new_backup = BackupManager::new(backups.path())
        .create_backup(wallet.database().unwrap(), false)
        .unwrap();
    assert_eq!(count_legacy(&zip_entry(&new_backup), &chunks), 0);
    assert!(wallet.retire_pre_v6_snapshot(backups.path()).unwrap());
    assert!(!wallet.has_pre_v6_snapshot());
}

#[test]
fn a_backup_of_another_vault_does_not_retire_the_snapshot() {
    let (_t, folder) = fresh_real_vault();
    let mut wallet = Wallet::open(&folder).unwrap();
    assert!(wallet.unlock(TEST_PASSWORD).unwrap());

    // A current v6 vault with its own database id, backed up after creation.
    let other_temp = TempDir::new().unwrap();
    let other = Wallet::create(other_temp.path(), "other password", "en").unwrap();
    let backups = TempDir::new().unwrap();
    BackupManager::new(backups.path()).create_backup(other.database().unwrap(), true).unwrap();
    assert!(compacted_at(&other_temp.path().join("nswallet.dat")).is_some());

    assert!(!wallet.retire_pre_v6_snapshot(backups.path()).unwrap());
    assert!(wallet.has_pre_v6_snapshot());
}
