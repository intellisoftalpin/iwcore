//! Backup restoration
//!
//! Restores ZIP backup files containing the database.

use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{self, Read};
use zip::ZipArchive;
use crate::error::{Result, WalletError};
use crate::DATABASE_FILENAME;

/// Largest database a backup may restore. Far above any real wallet; it exists so
/// that a crafted backup (a "zip bomb" that claims or inflates to gigabytes)
/// fails with an error instead of exhausting memory or disk.
pub const MAX_RESTORED_DB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Restore a backup to the database path.
///
/// The database entry is streamed into a temporary file beside `db_path`,
/// never held in memory as a whole, and refused if it grows past
/// [`MAX_RESTORED_DB_BYTES`]. Only a complete, flushed copy replaces the
/// database, by an atomic rename, so a failure at any point leaves the
/// previous database untouched. Stale `-wal` / `-shm` files of the previous
/// database are removed, since they do not belong to the restored one.
///
/// The wallet using `db_path` must be closed while it is restored.
pub fn restore_backup(backup_path: &Path, db_path: &Path) -> Result<()> {
    restore_backup_capped(backup_path, db_path, MAX_RESTORED_DB_BYTES)
}

fn restore_backup_capped(backup_path: &Path, db_path: &Path, max_bytes: u64) -> Result<()> {
    let file = File::open(backup_path)
        .map_err(|e| WalletError::BackupError(format!("Failed to open backup: {}", e)))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| WalletError::BackupError(format!("Failed to read backup: {}", e)))?;
    let db_file = archive.by_name(DATABASE_FILENAME)
        .map_err(|e| WalletError::BackupError(format!("Database not found in backup: {}", e)))?;
    if db_file.size() > max_bytes {
        return Err(WalletError::BackupError(format!(
            "Database in backup is too large ({} bytes, limit {})",
            db_file.size(),
            max_bytes
        )));
    }

    let parent = match db_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&parent)?;

    // Same folder as the target, so the final rename is atomic.
    let mut temp = tempfile::NamedTempFile::new_in(&parent)
        .map_err(|e| WalletError::BackupError(format!("Failed to create temp file: {}", e)))?;
    // The declared size can lie; the limit is enforced on the bytes read.
    let copied = io::copy(&mut db_file.take(max_bytes + 1), temp.as_file_mut())
        .map_err(|e| WalletError::BackupError(format!("Failed to read database from backup: {}", e)))?;
    if copied > max_bytes {
        return Err(WalletError::BackupError(format!(
            "Database in backup is larger than the limit of {} bytes",
            max_bytes
        )));
    }
    temp.as_file_mut()
        .sync_all()
        .map_err(|e| WalletError::BackupError(format!("Failed to write database: {}", e)))?;

    for suffix in ["-wal", "-shm"] {
        let mut sidecar = db_path.as_os_str().to_owned();
        sidecar.push(suffix);
        match fs::remove_file(&sidecar) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(WalletError::BackupError(format!(
                    "Failed to remove stale {} file: {}",
                    suffix, e
                )))
            }
        }
    }

    temp.persist(db_path)
        .map_err(|e| WalletError::BackupError(format!("Failed to write database: {}", e.error)))?;
    Ok(())
}

/// Extract a backup to a folder, returning the path to the extracted database
pub fn extract_backup(backup_path: &Path, target_folder: &Path) -> Result<PathBuf> {
    // Ensure target folder exists
    fs::create_dir_all(target_folder)?;

    let db_path = target_folder.join(DATABASE_FILENAME);
    restore_backup(backup_path, &db_path)?;

    Ok(db_path)
}

/// Verify that a backup file is valid
pub fn verify_backup(backup_path: &Path) -> Result<bool> {
    // Open ZIP file
    let file = File::open(backup_path)
        .map_err(|e| WalletError::BackupError(format!("Failed to open backup: {}", e)))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| WalletError::BackupError(format!("Failed to read backup: {}", e)))?;

    // Check if database file exists
    match archive.by_name(DATABASE_FILENAME) {
        Ok(file) => {
            // Verify it has content
            Ok(file.size() > 0)
        }
        Err(_) => Ok(false),
    }
}

/// Create a temporary directory inside the given base folder.
///
/// On some platforms (notably Android/Pixel) the OS default temp location is
/// not writable by the app sandbox, causing "permission denied". Callers can
/// pass an app-controlled, writable base folder to avoid that.
fn temp_dir_in(base: &Path) -> Result<tempfile::TempDir> {
    fs::create_dir_all(base)
        .map_err(|e| WalletError::BackupError(format!("Failed to create temp base folder: {}", e)))?;
    tempfile::TempDir::new_in(base)
        .map_err(|e| WalletError::BackupError(format!("Failed to create temp dir: {}", e)))
}

/// Check database version from a backup without fully restoring.
///
/// Uses the OS default temp location. Prefer [`get_backup_db_version_in`] on
/// platforms where the default temp folder may not be writable.
pub fn get_backup_db_version(backup_path: &Path) -> Result<String> {
    use tempfile::TempDir;

    let temp_dir = TempDir::new()
        .map_err(|e| WalletError::BackupError(format!("Failed to create temp dir: {}", e)))?;
    db_version_from_extracted(backup_path, temp_dir.path())
}

/// Check database version from a backup, extracting into the given temp base folder.
pub fn get_backup_db_version_in(backup_path: &Path, temp_base: &Path) -> Result<String> {
    let temp_dir = temp_dir_in(temp_base)?;
    db_version_from_extracted(backup_path, temp_dir.path())
}

/// Extract a backup into `target` and read its database version.
fn db_version_from_extracted(backup_path: &Path, target: &Path) -> Result<String> {
    use rusqlite::Connection;

    let db_path = extract_backup(backup_path, target)?;

    let conn = Connection::open(&db_path)
        .map_err(|e| WalletError::DatabaseError(format!("Failed to open database: {}", e)))?;

    let version: String = conn.query_row(
        "SELECT version FROM nswallet_properties LIMIT 1",
        [],
        |row| row.get(0),
    ).unwrap_or_else(|_| "1".to_string());

    Ok(version)
}

/// Check if a backup's database version is compatible.
///
/// Uses the OS default temp location. Prefer [`is_backup_compatible_in`] on
/// platforms where the default temp folder may not be writable.
pub fn is_backup_compatible(backup_path: &Path, current_version: &str) -> Result<bool> {
    compatible(get_backup_db_version(backup_path)?, current_version)
}

/// Check if a backup's database version is compatible, extracting into the
/// given app-writable temp base folder.
pub fn is_backup_compatible_in(backup_path: &Path, current_version: &str, temp_base: &Path) -> Result<bool> {
    compatible(get_backup_db_version_in(backup_path, temp_base)?, current_version)
}

/// Compare a backup version string against the current version string.
fn compatible(backup_version: String, current_version: &str) -> Result<bool> {
    let backup_v: u32 = backup_version.parse().unwrap_or(1);
    let current_v: u32 = current_version.parse().unwrap_or(4);

    // Backup version should be <= current version
    Ok(backup_v <= current_v)
}

/// Verify a password against a backup database, extracting into the given
/// app-writable temp base folder.
pub fn check_backup_password_in(backup_path: &Path, password: &str, temp_base: &Path) -> Result<bool> {
    use crate::business::Wallet;

    let temp_dir = temp_dir_in(temp_base)?;
    extract_backup(backup_path, temp_dir.path())?;
    let wallet = Wallet::open(temp_dir.path())?;
    wallet.check_password(password)
}

/// Check database version directly from a database file (not a backup)
pub fn get_db_version(db_path: &Path) -> Result<String> {
    use rusqlite::Connection;

    let conn = Connection::open(db_path)
        .map_err(|e| WalletError::DatabaseError(format!("Failed to open database: {}", e)))?;

    let version: String = conn.query_row(
        "SELECT version FROM nswallet_properties LIMIT 1",
        [],
        |row| row.get(0),
    ).unwrap_or_else(|_| "1".to_string());

    Ok(version)
}

/// Check if a database version is compatible with the current app version
pub fn check_db_version(db_path: &Path) -> Result<bool> {
    use crate::DB_VERSION;

    let db_version = get_db_version(db_path)?;
    let db_v: u32 = db_version.parse().unwrap_or(1);
    let current_v: u32 = DB_VERSION.parse().unwrap_or(4);

    // DB version should be <= current app version
    Ok(db_v <= current_v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::io::Write;

    fn create_test_backup(dir: &Path) -> PathBuf {
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        let backup_path = dir.join("test-backup.zip");
        let file = File::create(&backup_path).unwrap();
        let mut zip = ZipWriter::new(file);

        let options = SimpleFileOptions::default();
        zip.start_file(DATABASE_FILENAME, options).unwrap();
        zip.write_all(b"test database content").unwrap();
        zip.finish().unwrap();

        backup_path
    }

    #[test]
    fn test_verify_backup() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());

        assert!(verify_backup(&backup_path).unwrap());
    }

    #[test]
    fn test_extract_backup() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());

        let target_dir = temp_dir.path().join("extracted");
        let db_path = extract_backup(&backup_path, &target_dir).unwrap();

        assert!(db_path.exists());
        let content = fs::read_to_string(&db_path).unwrap();
        assert_eq!(content, "test database content");
    }

    #[test]
    fn test_restore_backup() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());

        let db_path = temp_dir.path().join("restored").join(DATABASE_FILENAME);
        restore_backup(&backup_path, &db_path).unwrap();

        assert!(db_path.exists());
        let content = fs::read_to_string(&db_path).unwrap();
        assert_eq!(content, "test database content");
    }

    #[test]
    fn restore_replaces_an_existing_database() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let db_path = temp_dir.path().join("w").join(DATABASE_FILENAME);
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        fs::write(&db_path, b"OLD DATABASE").unwrap();

        restore_backup(&backup_path, &db_path).unwrap();
        assert_eq!(fs::read_to_string(&db_path).unwrap(), "test database content");
    }

    #[test]
    fn restore_refuses_an_entry_over_the_limit_and_keeps_the_old_database() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let db_path = temp_dir.path().join("w").join(DATABASE_FILENAME);
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        fs::write(&db_path, b"OLD DATABASE").unwrap();

        // "test database content" is 21 bytes.
        let err = restore_backup_capped(&backup_path, &db_path, 20).unwrap_err();
        assert!(matches!(err, WalletError::BackupError(_)));
        assert_eq!(fs::read_to_string(&db_path).unwrap(), "OLD DATABASE");
        // No temp file left behind.
        let leftovers: Vec<_> = fs::read_dir(db_path.parent().unwrap()).unwrap().collect();
        assert_eq!(leftovers.len(), 1);

        // Exactly at the limit is fine.
        restore_backup_capped(&backup_path, &db_path, 21).unwrap();
        assert_eq!(fs::read_to_string(&db_path).unwrap(), "test database content");
    }

    #[test]
    fn failed_restore_keeps_the_old_database() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join(DATABASE_FILENAME);
        fs::write(&db_path, b"OLD DATABASE").unwrap();

        // Not a zip at all.
        let bogus = temp_dir.path().join("bogus.zip");
        fs::write(&bogus, b"not a zip").unwrap();
        assert!(restore_backup(&bogus, &db_path).is_err());

        // A zip without the database entry.
        let empty = temp_dir.path().join("empty.zip");
        {
            let mut zip = zip::ZipWriter::new(File::create(&empty).unwrap());
            zip.start_file("other.txt", zip::write::SimpleFileOptions::default()).unwrap();
            zip.finish().unwrap();
        }
        assert!(restore_backup(&empty, &db_path).is_err());

        assert_eq!(fs::read_to_string(&db_path).unwrap(), "OLD DATABASE");
    }

    #[test]
    fn restore_removes_stale_sidecars_of_the_previous_database() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let db_path = temp_dir.path().join(DATABASE_FILENAME);
        fs::write(&db_path, b"OLD").unwrap();
        let wal = temp_dir.path().join(format!("{DATABASE_FILENAME}-wal"));
        let shm = temp_dir.path().join(format!("{DATABASE_FILENAME}-shm"));
        fs::write(&wal, b"stale wal").unwrap();
        fs::write(&shm, b"stale shm").unwrap();

        restore_backup(&backup_path, &db_path).unwrap();
        assert!(!wal.exists() && !shm.exists());
        assert_eq!(fs::read_to_string(&db_path).unwrap(), "test database content");
    }

    #[test]
    fn restore_creates_missing_parent_folders() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let target = temp_dir.path().join("x").join("y").join(DATABASE_FILENAME);
        restore_backup(&backup_path, &target).unwrap();
        assert!(target.exists());
    }

    #[test]
    fn test_get_backup_db_version_in_uses_base() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());

        // App-controlled temp base that does not yet exist (must be created)
        let base = temp_dir.path().join("app_temp").join("nested");
        let version = get_backup_db_version_in(&backup_path, &base).unwrap();

        // Dummy backup has no valid properties table → defaults to "1"
        assert_eq!(version, "1");
        assert!(base.exists(), "temp base folder should have been created");
    }

    #[test]
    fn test_is_backup_compatible_in() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let base = temp_dir.path().join("app_temp");

        // version "1" backup is compatible with current "5"
        assert!(is_backup_compatible_in(&backup_path, "5", &base).unwrap());
    }

    /// Test: CheckFutureVersionOfDb from C# BackupFixture
    /// Database with version 999 should NOT be compatible
    #[test]
    fn test_future_version_db_not_compatible() {
        let testdata_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("nswallet_from_future.dat");

        if !testdata_path.exists() {
            eprintln!("Skipping test: testdata/nswallet_from_future.dat not found");
            return;
        }

        // Get version - should be 999
        let version = get_db_version(&testdata_path).unwrap();
        assert_eq!(version, "999", "Version should be 999");

        // Check compatibility - should be FALSE (future version not accepted)
        let is_ok = check_db_version(&testdata_path).unwrap();
        assert!(!is_ok, "Backup with DB version higher than current was accepted - huge mistake");
    }

    /// Test: CheckOldVersionOfDb from C# BackupFixture
    /// Database with version 1 should be compatible
    #[test]
    fn test_old_version_db_is_compatible() {
        let testdata_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("nswallet_old.dat");

        if !testdata_path.exists() {
            eprintln!("Skipping test: testdata/nswallet_old.dat not found");
            return;
        }

        // Get version - should be 1
        let version = get_db_version(&testdata_path).unwrap();
        assert_eq!(version, "1", "Version should be 1");

        // Check compatibility - should be TRUE (old version is accepted)
        let is_ok = check_db_version(&testdata_path).unwrap();
        assert!(is_ok, "Lower backup version should fit, but app declined it!");
    }

    /// Test: CheckPointDBVersion from C# BackupFixture
    /// Verify version 999 is correctly retrieved
    #[test]
    fn test_get_db_version_from_future_db() {
        let testdata_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("nswallet_from_future.dat");

        if !testdata_path.exists() {
            eprintln!("Skipping test: testdata/nswallet_from_future.dat not found");
            return;
        }

        let version = get_db_version(&testdata_path).unwrap();
        assert_eq!(version, "999", "Version DB is not retrieved correctly");
    }
}
