//! Backup restoration
//!
//! Restores ZIP backup files containing the database.

use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{Read, Write};
use zip::ZipArchive;
use crate::error::{Result, WalletError};
use crate::DATABASE_FILENAME;

/// Restore a backup to the database path
pub fn restore_backup(backup_path: &Path, db_path: &Path) -> Result<()> {
    // Open ZIP file
    let file = File::open(backup_path)
        .map_err(|e| WalletError::BackupError(format!("Failed to open backup: {}", e)))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| WalletError::BackupError(format!("Failed to read backup: {}", e)))?;

    // Find the database file in the archive
    let mut db_file = archive.by_name(DATABASE_FILENAME)
        .map_err(|e| WalletError::BackupError(format!("Database not found in backup: {}", e)))?;

    // Read the database content
    let mut db_data = Vec::new();
    db_file.read_to_end(&mut db_data)
        .map_err(|e| WalletError::BackupError(format!("Failed to read database from backup: {}", e)))?;

    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write to target path
    let mut output = File::create(db_path)
        .map_err(|e| WalletError::BackupError(format!("Failed to create database file: {}", e)))?;
    output.write_all(&db_data)
        .map_err(|e| WalletError::BackupError(format!("Failed to write database: {}", e)))?;

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

/// Check database version from a backup without fully restoring
pub fn get_backup_db_version(backup_path: &Path) -> Result<String> {
    use rusqlite::Connection;
    use tempfile::TempDir;

    // Extract to temp location
    let temp_dir = TempDir::new()
        .map_err(|e| WalletError::BackupError(format!("Failed to create temp dir: {}", e)))?;
    let db_path = extract_backup(backup_path, temp_dir.path())?;

    // Open and check version
    let conn = Connection::open(&db_path)
        .map_err(|e| WalletError::DatabaseError(format!("Failed to open database: {}", e)))?;

    let version: String = conn.query_row(
        "SELECT version FROM nswallet_properties LIMIT 1",
        [],
        |row| row.get(0),
    ).unwrap_or_else(|_| "1".to_string());

    Ok(version)
}

/// Check if a backup's database version is compatible
pub fn is_backup_compatible(backup_path: &Path, current_version: &str) -> Result<bool> {
    let backup_version = get_backup_db_version(backup_path)?;
    let backup_v: u32 = backup_version.parse().unwrap_or(1);
    let current_v: u32 = current_version.parse().unwrap_or(4);

    // Backup version should be <= current version
    Ok(backup_v <= current_v)
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
