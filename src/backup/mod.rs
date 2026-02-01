//! Backup and restore functionality
//!
//! Handles creation and restoration of ZIP backup files.

mod create;
mod restore;

// Re-export version checking functions
pub use restore::{
    get_backup_db_version,
    is_backup_compatible,
    get_db_version,
    check_db_version,
};

use std::path::{Path, PathBuf};
use std::fs;
use chrono::{DateTime, Utc, TimeZone, NaiveDateTime};
use crate::database::Database;
use crate::error::Result;

/// Backup file prefix
pub const BACKUP_PREFIX: &str = "iwb";

/// Legacy backup file prefix (for parsing old files)
pub const BACKUP_PREFIX_LEGACY: &str = "nswb";

/// Auto backup suffix
pub const BACKUP_AUTO: &str = "auto";

/// Manual backup suffix
pub const BACKUP_MANUAL: &str = "manual";

/// Imported backup suffix
pub const BACKUP_IMPORTED: &str = "imported";

/// Backup date format
pub const BACKUP_DATE_FORMAT: &str = "%Y%m%d-%H%M%S";

/// Backup type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupType {
    Auto,
    Manual,
    Imported,
}

/// Backup manager
pub struct BackupManager {
    /// Backup folder path
    folder: PathBuf,
}

impl BackupManager {
    /// Create a new backup manager
    pub fn new(folder: &Path) -> Self {
        Self {
            folder: folder.to_path_buf(),
        }
    }

    /// Get the backup folder path
    pub fn folder(&self) -> &Path {
        &self.folder
    }

    /// Create a backup
    ///
    /// Requires a database reference to perform WAL checkpoint before backup.
    pub fn create_backup(&self, db: &Database, manual: bool) -> Result<PathBuf> {
        create::create_backup(&self.folder, db, manual)
    }

    /// Create a backup from a raw database file path (DB must be closed)
    ///
    /// Unlike `create_backup`, this does not perform a WAL checkpoint since the
    /// database is expected to be closed.
    pub fn create_backup_from_path(&self, db_path: &Path, manual: bool) -> Result<PathBuf> {
        create::create_backup_from_path(&self.folder, db_path, manual)
    }

    /// Restore from a backup
    pub fn restore_backup(&self, backup_path: &Path, db_path: &Path) -> Result<()> {
        restore::restore_backup(backup_path, db_path)
    }

    /// Extract a backup to a folder (for inspection)
    pub fn extract_backup(&self, backup_path: &Path, target_folder: &Path) -> Result<PathBuf> {
        restore::extract_backup(backup_path, target_folder)
    }

    /// List available backups
    pub fn list_backups(&self) -> Result<Vec<BackupInfo>> {
        let mut backups = Vec::new();

        if !self.folder.exists() {
            return Ok(backups);
        }

        for entry in fs::read_dir(&self.folder)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if (filename.starts_with(BACKUP_PREFIX) || filename.starts_with(BACKUP_PREFIX_LEGACY))
                        && filename.ends_with(".zip")
                    {
                        if let Some(info) = parse_backup_filename(filename, &path) {
                            backups.push(info);
                        }
                    }
                }
            }
        }

        // Sort by timestamp, newest first
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(backups)
    }

    /// Verify a backup file
    pub fn verify_backup(&self, backup_path: &Path) -> Result<bool> {
        restore::verify_backup(backup_path)
    }

    /// Clean up old backups, keeping only the specified number
    pub fn cleanup_old_backups(&self, keep_count: usize) -> Result<usize> {
        let backups = self.list_backups()?;

        if backups.len() <= keep_count {
            return Ok(0);
        }

        let mut deleted = 0;
        for backup in backups.iter().skip(keep_count) {
            fs::remove_file(&backup.path)?;
            deleted += 1;
        }

        Ok(deleted)
    }

    /// Get the latest backup
    pub fn get_latest_backup(&self) -> Result<Option<BackupInfo>> {
        let backups = self.list_backups()?;
        Ok(backups.into_iter().next())
    }

    /// Clean up old automatic backups based on age
    ///
    /// Only deletes automatic backups. Manual and imported backups are never touched.
    /// Keeps at least `min_keep` auto backups regardless of age.
    /// Deletes auto backups older than `max_age_days` only if enough newer ones exist.
    /// Returns the number of deleted backups.
    pub fn cleanup_auto_backups(&self, min_keep: usize, max_age_days: u32) -> Result<usize> {
        let backups = self.list_backups()?;

        // Filter to auto backups only (already sorted newest first)
        let auto_backups: Vec<&BackupInfo> = backups.iter().filter(|b| b.backup_type == BackupType::Auto).collect();

        if auto_backups.len() <= min_keep {
            return Ok(0);
        }

        let cutoff = Utc::now() - chrono::Duration::days(max_age_days as i64);
        let mut deleted = 0;

        for backup in auto_backups.iter().skip(min_keep) {
            if backup.timestamp < cutoff {
                fs::remove_file(&backup.path)?;
                deleted += 1;
            }
        }

        Ok(deleted)
    }
}

/// Information about a backup file
#[derive(Debug, Clone)]
pub struct BackupInfo {
    /// Path to the backup file
    pub path: PathBuf,
    /// Backup timestamp
    pub timestamp: DateTime<Utc>,
    /// Backup type (auto, manual, or imported)
    pub backup_type: BackupType,
    /// File size in bytes
    pub size: u64,
}

/// Parse backup filename to extract information
fn parse_backup_filename(filename: &str, path: &Path) -> Option<BackupInfo> {
    // Format: {iwb|nswb}-YYYYMMDD-HHMMSS-{auto|manual|imported}.zip
    let parts: Vec<&str> = filename.split('-').collect();

    if parts.len() != 4 {
        return None;
    }

    if parts[0] != BACKUP_PREFIX && parts[0] != BACKUP_PREFIX_LEGACY {
        return None;
    }

    // Parse date and time
    let date_str = parts[1];
    let time_str = parts[2];

    if date_str.len() != 8 || time_str.len() != 6 {
        return None;
    }

    let datetime_str = format!("{}-{}", date_str, time_str);
    let ndt = NaiveDateTime::parse_from_str(&datetime_str, BACKUP_DATE_FORMAT).ok()?;
    let timestamp = Utc.from_utc_datetime(&ndt);

    // Parse type
    let type_str = parts[3].trim_end_matches(".zip");
    let backup_type = match type_str {
        BACKUP_MANUAL => BackupType::Manual,
        BACKUP_IMPORTED => BackupType::Imported,
        _ => BackupType::Auto,
    };

    // Get file size
    let size = path.metadata().ok()?.len();

    Some(BackupInfo {
        path: path.to_path_buf(),
        timestamp,
        backup_type,
        size,
    })
}

/// Parse date from backup filename (for compatibility)
pub fn get_date_from_backup_filename(filename: &str) -> Option<DateTime<Utc>> {
    let name = Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())?;

    let parts: Vec<&str> = name.split('-').collect();

    if parts.len() < 3 {
        return None;
    }

    let date_str = parts[1];
    let time_str = parts[2];

    if date_str.len() != 8 || time_str.len() != 6 {
        return None;
    }

    let datetime_str = format!("{}-{}", date_str, time_str);
    let ndt = NaiveDateTime::parse_from_str(&datetime_str, BACKUP_DATE_FORMAT).ok()?;
    Some(Utc.from_utc_datetime(&ndt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_parse_backup_filename() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("iwb-20171203-113108-auto.zip");

        // Create a dummy file so metadata works
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"test").unwrap();

        let info = parse_backup_filename("iwb-20171203-113108-auto.zip", &path).unwrap();

        assert_eq!(info.backup_type, BackupType::Auto);
        assert_eq!(info.timestamp.year(), 2017);
        assert_eq!(info.timestamp.month(), 12);
        assert_eq!(info.timestamp.day(), 3);
    }

    #[test]
    fn test_parse_legacy_backup_filename() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("nswb-20171203-113108-auto.zip");

        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"test").unwrap();

        let info = parse_backup_filename("nswb-20171203-113108-auto.zip", &path).unwrap();

        assert_eq!(info.backup_type, BackupType::Auto);
        assert_eq!(info.timestamp.year(), 2017);
        assert_eq!(info.timestamp.month(), 12);
        assert_eq!(info.timestamp.day(), 3);
    }

    #[test]
    fn test_parse_imported_backup_filename() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("iwb-20231215-143022-imported.zip");

        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"test").unwrap();

        let info = parse_backup_filename("iwb-20231215-143022-imported.zip", &path).unwrap();

        assert_eq!(info.backup_type, BackupType::Imported);
        assert_eq!(info.timestamp.year(), 2023);
        assert_eq!(info.timestamp.month(), 12);
        assert_eq!(info.timestamp.day(), 15);
    }

    #[test]
    fn test_get_date_from_backup_filename() {
        let date = get_date_from_backup_filename("iwb-20171203-113108-auto.zip").unwrap();
        assert_eq!(date.year(), 2017);
        assert_eq!(date.month(), 12);
        assert_eq!(date.day(), 3);
        assert_eq!(date.hour(), 11);
        assert_eq!(date.minute(), 31);
        assert_eq!(date.second(), 8);
    }

    #[test]
    fn test_get_date_from_legacy_backup_filename() {
        let date = get_date_from_backup_filename("nswb-20171203-113108-auto.zip").unwrap();
        assert_eq!(date.year(), 2017);
        assert_eq!(date.month(), 12);
        assert_eq!(date.day(), 3);
        assert_eq!(date.hour(), 11);
        assert_eq!(date.minute(), 31);
        assert_eq!(date.second(), 8);
    }

    #[test]
    fn test_get_date_from_full_path_iwb_prefix() {
        // Full path with new iwb- prefix should parse correctly
        let date = get_date_from_backup_filename("/var/backups/wallet/iwb-20231215-143022-manual.zip").unwrap();
        assert_eq!(date.year(), 2023);
        assert_eq!(date.month(), 12);
        assert_eq!(date.day(), 15);
        assert_eq!(date.hour(), 14);
        assert_eq!(date.minute(), 30);
        assert_eq!(date.second(), 22);
    }

    #[test]
    fn test_invalid_filename() {
        assert!(get_date_from_backup_filename("some text").is_none());
        // A path with full path should still work because we extract just the filename
        assert!(get_date_from_backup_filename("path/a/b/iwb-20171203-113108-auto.zip").is_some());
        assert!(get_date_from_backup_filename("path/a/b/nswb-20171203-113108-auto.zip").is_some());
        // But invalid format should fail
        assert!(get_date_from_backup_filename("invalid-format.zip").is_none());
    }

    #[test]
    fn test_backup_manager_folder() {
        let temp_dir = TempDir::new().unwrap();
        let mgr = BackupManager::new(temp_dir.path());
        assert_eq!(mgr.folder(), temp_dir.path());
    }

    #[test]
    fn test_list_backups_empty() {
        let temp_dir = TempDir::new().unwrap();
        let mgr = BackupManager::new(temp_dir.path());
        let backups = mgr.list_backups().unwrap();
        assert!(backups.is_empty());
    }

    #[test]
    fn test_list_backups_nonexistent_folder() {
        let mgr = BackupManager::new(Path::new("/nonexistent/path/12345"));
        let backups = mgr.list_backups().unwrap();
        assert!(backups.is_empty());
    }

    #[test]
    fn test_list_backups_with_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create some backup files (mix of new and legacy prefixes)
        let file1 = temp_dir.path().join("iwb-20231201-100000-auto.zip");
        let file2 = temp_dir.path().join("iwb-20231202-120000-manual.zip");
        let file3 = temp_dir.path().join("other-file.txt");

        std::fs::File::create(&file1).unwrap().write_all(b"test1").unwrap();
        std::fs::File::create(&file2).unwrap().write_all(b"test2").unwrap();
        std::fs::File::create(&file3).unwrap().write_all(b"test3").unwrap();

        let mgr = BackupManager::new(temp_dir.path());
        let backups = mgr.list_backups().unwrap();

        assert_eq!(backups.len(), 2);
        // Should be sorted newest first
        assert_eq!(backups[0].backup_type, BackupType::Manual); // Dec 2 is newer
        assert_eq!(backups[1].backup_type, BackupType::Auto); // Dec 1 is older
    }

    #[test]
    fn test_list_backups_with_legacy_files() {
        let temp_dir = TempDir::new().unwrap();

        // Legacy prefix files should also be listed
        let file1 = temp_dir.path().join("nswb-20231201-100000-auto.zip");
        let file2 = temp_dir.path().join("nswb-20231202-120000-manual.zip");

        std::fs::File::create(&file1).unwrap().write_all(b"test1").unwrap();
        std::fs::File::create(&file2).unwrap().write_all(b"test2").unwrap();

        let mgr = BackupManager::new(temp_dir.path());
        let backups = mgr.list_backups().unwrap();

        assert_eq!(backups.len(), 2);
        assert_eq!(backups[0].backup_type, BackupType::Manual);
        assert_eq!(backups[1].backup_type, BackupType::Auto);
    }

    #[test]
    fn test_get_latest_backup() {
        let temp_dir = TempDir::new().unwrap();

        // Empty folder
        let mgr = BackupManager::new(temp_dir.path());
        assert!(mgr.get_latest_backup().unwrap().is_none());

        // Create backup files
        let file1 = temp_dir.path().join("iwb-20231201-100000-auto.zip");
        let file2 = temp_dir.path().join("iwb-20231202-120000-manual.zip");
        std::fs::File::create(&file1).unwrap().write_all(b"test1").unwrap();
        std::fs::File::create(&file2).unwrap().write_all(b"test2").unwrap();

        let latest = mgr.get_latest_backup().unwrap().unwrap();
        assert_eq!(latest.backup_type, BackupType::Manual); // Dec 2 is newest
    }

    #[test]
    fn test_cleanup_old_backups() {
        let temp_dir = TempDir::new().unwrap();

        // Create 5 backup files
        for i in 1..=5 {
            let file = temp_dir.path().join(format!("iwb-2023120{}-100000-auto.zip", i));
            std::fs::File::create(&file).unwrap().write_all(b"test").unwrap();
        }

        let mgr = BackupManager::new(temp_dir.path());
        assert_eq!(mgr.list_backups().unwrap().len(), 5);

        // Keep only 2
        let deleted = mgr.cleanup_old_backups(2).unwrap();
        assert_eq!(deleted, 3);
        assert_eq!(mgr.list_backups().unwrap().len(), 2);
    }

    #[test]
    fn test_cleanup_nothing_to_delete() {
        let temp_dir = TempDir::new().unwrap();

        // Create 2 backup files
        let file1 = temp_dir.path().join("iwb-20231201-100000-auto.zip");
        let file2 = temp_dir.path().join("iwb-20231202-100000-auto.zip");
        std::fs::File::create(&file1).unwrap().write_all(b"test").unwrap();
        std::fs::File::create(&file2).unwrap().write_all(b"test").unwrap();

        let mgr = BackupManager::new(temp_dir.path());

        // Keep 5 but only have 2
        let deleted = mgr.cleanup_old_backups(5).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(mgr.list_backups().unwrap().len(), 2);
    }

    #[test]
    fn test_parse_manual_backup() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("iwb-20231215-143022-manual.zip");
        std::fs::File::create(&path).unwrap().write_all(b"test").unwrap();

        let info = parse_backup_filename("iwb-20231215-143022-manual.zip", &path).unwrap();
        assert_eq!(info.backup_type, BackupType::Manual);
        assert_eq!(info.timestamp.year(), 2023);
        assert_eq!(info.timestamp.month(), 12);
        assert_eq!(info.timestamp.day(), 15);
    }

    #[test]
    fn test_cleanup_auto_backups_deletes_old() {
        let temp_dir = TempDir::new().unwrap();

        // Create 5 auto backups, all old (2020)
        for i in 1..=5 {
            let file = temp_dir.path().join(format!("iwb-2020010{}-100000-auto.zip", i));
            std::fs::File::create(&file).unwrap().write_all(b"test").unwrap();
        }

        let mgr = BackupManager::new(temp_dir.path());
        assert_eq!(mgr.list_backups().unwrap().len(), 5);

        // min_keep=3, max_age_days=30 → deletes 2 oldest
        let deleted = mgr.cleanup_auto_backups(3, 30).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(mgr.list_backups().unwrap().len(), 3);
    }

    #[test]
    fn test_cleanup_auto_backups_below_minimum() {
        let temp_dir = TempDir::new().unwrap();

        // Create 2 auto backups
        let file1 = temp_dir.path().join("iwb-20200101-100000-auto.zip");
        let file2 = temp_dir.path().join("iwb-20200102-100000-auto.zip");
        std::fs::File::create(&file1).unwrap().write_all(b"test").unwrap();
        std::fs::File::create(&file2).unwrap().write_all(b"test").unwrap();

        let mgr = BackupManager::new(temp_dir.path());

        // min_keep=3, but only 2 exist → delete nothing
        let deleted = mgr.cleanup_auto_backups(3, 30).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(mgr.list_backups().unwrap().len(), 2);
    }

    #[test]
    fn test_cleanup_auto_backups_ignores_manual() {
        let temp_dir = TempDir::new().unwrap();

        // Create 5 auto + 3 manual, all old
        for i in 1..=5 {
            let file = temp_dir.path().join(format!("iwb-2020010{}-100000-auto.zip", i));
            std::fs::File::create(&file).unwrap().write_all(b"test").unwrap();
        }
        for i in 6..=8 {
            let file = temp_dir.path().join(format!("iwb-2020010{}-100000-manual.zip", i));
            std::fs::File::create(&file).unwrap().write_all(b"test").unwrap();
        }

        let mgr = BackupManager::new(temp_dir.path());
        assert_eq!(mgr.list_backups().unwrap().len(), 8);

        // min_keep=3, max_age_days=30 → deletes 2 old auto, manual untouched
        let deleted = mgr.cleanup_auto_backups(3, 30).unwrap();
        assert_eq!(deleted, 2);

        let remaining = mgr.list_backups().unwrap();
        assert_eq!(remaining.len(), 6); // 3 auto + 3 manual
        let manual_count = remaining.iter().filter(|b| b.backup_type == BackupType::Manual).count();
        assert_eq!(manual_count, 3);
    }

    #[test]
    fn test_cleanup_auto_backups_ignores_imported() {
        let temp_dir = TempDir::new().unwrap();

        // Create 5 auto + 2 imported, all old
        for i in 1..=5 {
            let file = temp_dir.path().join(format!("iwb-2020010{}-100000-auto.zip", i));
            std::fs::File::create(&file).unwrap().write_all(b"test").unwrap();
        }
        for i in 6..=7 {
            let file = temp_dir.path().join(format!("iwb-2020010{}-100000-imported.zip", i));
            std::fs::File::create(&file).unwrap().write_all(b"test").unwrap();
        }

        let mgr = BackupManager::new(temp_dir.path());
        assert_eq!(mgr.list_backups().unwrap().len(), 7);

        // min_keep=3, max_age_days=30 → deletes 2 old auto, imported untouched
        let deleted = mgr.cleanup_auto_backups(3, 30).unwrap();
        assert_eq!(deleted, 2);

        let remaining = mgr.list_backups().unwrap();
        assert_eq!(remaining.len(), 5); // 3 auto + 2 imported
        let imported_count = remaining.iter().filter(|b| b.backup_type == BackupType::Imported).count();
        assert_eq!(imported_count, 2);
    }

    #[test]
    fn test_cleanup_auto_backups_mixed_ages() {
        let temp_dir = TempDir::new().unwrap();

        // 3 recent auto backups (today-ish via current year)
        let now = Utc::now();
        for i in 0..3 {
            let ts = now - chrono::Duration::days(i);
            let file = temp_dir.path().join(format!(
                "iwb-{}-auto.zip",
                ts.format(BACKUP_DATE_FORMAT)
            ));
            std::fs::File::create(&file).unwrap().write_all(b"test").unwrap();
        }
        // 2 old auto backups
        let file_old1 = temp_dir.path().join("iwb-20200101-100000-auto.zip");
        let file_old2 = temp_dir.path().join("iwb-20200102-100000-auto.zip");
        std::fs::File::create(&file_old1).unwrap().write_all(b"test").unwrap();
        std::fs::File::create(&file_old2).unwrap().write_all(b"test").unwrap();

        let mgr = BackupManager::new(temp_dir.path());
        assert_eq!(mgr.list_backups().unwrap().len(), 5);

        // min_keep=3, max_age_days=30 → deletes 2 old ones beyond the 3 newest
        let deleted = mgr.cleanup_auto_backups(3, 30).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(mgr.list_backups().unwrap().len(), 3);
    }

    #[test]
    fn test_cleanup_auto_backups_empty() {
        let temp_dir = TempDir::new().unwrap();
        let mgr = BackupManager::new(temp_dir.path());

        let deleted = mgr.cleanup_auto_backups(3, 30).unwrap();
        assert_eq!(deleted, 0);
    }
}
