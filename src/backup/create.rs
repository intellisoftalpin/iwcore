//! Backup creation
//!
//! Creates ZIP backup files containing the database.

use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{Read, Write};
use chrono::Utc;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;
use crate::error::{Result, WalletError};
use crate::database::Database;
use crate::DATABASE_FILENAME;
use super::{BACKUP_PREFIX, BACKUP_AUTO, BACKUP_MANUAL, BACKUP_DATE_FORMAT};

/// Create a backup of the database
///
/// Performs a WAL checkpoint before creating the backup to ensure all data
/// is written to the main database file.
pub fn create_backup(backup_folder: &Path, db: &Database, manual: bool) -> Result<PathBuf> {
    // Checkpoint WAL to ensure all data is in main file
    db.checkpoint()?;

    // Ensure backup folder exists
    fs::create_dir_all(backup_folder)?;

    // Generate backup filename
    let now = Utc::now();
    let type_str = if manual { BACKUP_MANUAL } else { BACKUP_AUTO };
    let filename = format!(
        "{}-{}-{}.zip",
        BACKUP_PREFIX,
        now.format(BACKUP_DATE_FORMAT),
        type_str
    );
    let backup_path = backup_folder.join(&filename);

    // Read database file
    let db_path = db.path();
    let mut db_file = File::open(db_path)
        .map_err(|e| WalletError::BackupError(format!("Failed to open database: {}", e)))?;
    let mut db_data = Vec::new();
    db_file.read_to_end(&mut db_data)
        .map_err(|e| WalletError::BackupError(format!("Failed to read database: {}", e)))?;

    // Create ZIP file
    let zip_file = File::create(&backup_path)
        .map_err(|e| WalletError::BackupError(format!("Failed to create backup file: {}", e)))?;
    let mut zip = ZipWriter::new(zip_file);

    // Add database to ZIP
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);

    zip.start_file(DATABASE_FILENAME, options)
        .map_err(|e| WalletError::BackupError(format!("Failed to add file to zip: {}", e)))?;
    zip.write_all(&db_data)
        .map_err(|e| WalletError::BackupError(format!("Failed to write to zip: {}", e)))?;

    zip.finish()
        .map_err(|e| WalletError::BackupError(format!("Failed to finalize zip: {}", e)))?;

    Ok(backup_path)
}

/// Create a backup from a raw database file path (DB must be closed)
///
/// Unlike `create_backup`, this does not perform a WAL checkpoint since the
/// database is expected to be closed. Takes a file path instead of a Database reference.
pub fn create_backup_from_path(backup_folder: &Path, db_path: &Path, manual: bool) -> Result<PathBuf> {
    // Verify source file exists
    if !db_path.exists() {
        return Err(WalletError::BackupError(
            format!("Database file not found: {}", db_path.display()),
        ));
    }

    // Ensure backup folder exists
    fs::create_dir_all(backup_folder)?;

    // Generate backup filename
    let now = Utc::now();
    let type_str = if manual { BACKUP_MANUAL } else { BACKUP_AUTO };
    let filename = format!(
        "{}-{}-{}.zip",
        BACKUP_PREFIX,
        now.format(BACKUP_DATE_FORMAT),
        type_str
    );
    let backup_path = backup_folder.join(&filename);

    // Read database file
    let mut db_file = File::open(db_path)
        .map_err(|e| WalletError::BackupError(format!("Failed to open database: {}", e)))?;
    let mut db_data = Vec::new();
    db_file.read_to_end(&mut db_data)
        .map_err(|e| WalletError::BackupError(format!("Failed to read database: {}", e)))?;

    // Create ZIP file
    let zip_file = File::create(&backup_path)
        .map_err(|e| WalletError::BackupError(format!("Failed to create backup file: {}", e)))?;
    let mut zip = ZipWriter::new(zip_file);

    // Add database to ZIP
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);

    zip.start_file(DATABASE_FILENAME, options)
        .map_err(|e| WalletError::BackupError(format!("Failed to add file to zip: {}", e)))?;
    zip.write_all(&db_data)
        .map_err(|e| WalletError::BackupError(format!("Failed to write to zip: {}", e)))?;

    zip.finish()
        .map_err(|e| WalletError::BackupError(format!("Failed to finalize zip: {}", e)))?;

    Ok(backup_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_backup() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        let db_path = temp_dir.path().join("nswallet.dat");

        // Create a real database
        let db = Database::create(&db_path).unwrap();

        // Create backup
        let backup_path = create_backup(&backup_dir, &db, true).unwrap();

        assert!(backup_path.exists());
        assert!(backup_path.file_name().unwrap().to_str().unwrap().contains("manual"));
    }

    #[test]
    fn test_create_auto_backup() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        let db_path = temp_dir.path().join("nswallet.dat");

        // Create a real database
        let db = Database::create(&db_path).unwrap();

        // Create backup
        let backup_path = create_backup(&backup_dir, &db, false).unwrap();

        assert!(backup_path.exists());
        assert!(backup_path.file_name().unwrap().to_str().unwrap().contains("auto"));
    }

    #[test]
    fn test_create_backup_from_path() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        let db_path = temp_dir.path().join("nswallet.dat");

        // Create a raw .dat file
        std::fs::write(&db_path, b"fake database content").unwrap();

        let backup_path = create_backup_from_path(&backup_dir, &db_path, true).unwrap();

        assert!(backup_path.exists());
        assert!(backup_path.file_name().unwrap().to_str().unwrap().contains("manual"));

        // Verify ZIP contains nswallet.dat
        let zip_file = File::open(&backup_path).unwrap();
        let mut archive = zip::ZipArchive::new(zip_file).unwrap();
        assert_eq!(archive.len(), 1);
        let file = archive.by_name(DATABASE_FILENAME).unwrap();
        assert!(file.size() > 0);
    }

    #[test]
    fn test_create_backup_from_path_auto() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        let db_path = temp_dir.path().join("nswallet.dat");

        std::fs::write(&db_path, b"fake database content").unwrap();

        let backup_path = create_backup_from_path(&backup_dir, &db_path, false).unwrap();

        assert!(backup_path.exists());
        assert!(backup_path.file_name().unwrap().to_str().unwrap().contains("auto"));
    }

    #[test]
    fn test_create_backup_from_nonexistent_path() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        let db_path = temp_dir.path().join("nonexistent.dat");

        let result = create_backup_from_path(&backup_dir, &db_path, false);
        assert!(result.is_err());
    }
}
