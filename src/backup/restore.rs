//! Backup restoration
//!
//! Restores ZIP backup files containing the database.

use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use zip::ZipArchive;
use crate::error::{Result, WalletError};
use crate::DATABASE_FILENAME;
use super::untrusted::{has_sqlite_header, SQLITE_HEADER};

/// Largest database a backup may restore. Real vaults are kilobytes to a few
/// megabytes; the limit keeps a crafted backup that inflates far beyond its
/// own size from filling the device's storage.
pub const MAX_RESTORED_DB_BYTES: u64 = 256 * 1024 * 1024;

/// Highest compression ratio accepted for the database entry. Deflate cannot
/// go much beyond about 1030:1, and real databases stay far below this.
const MAX_COMPRESSION_RATIO: u64 = 1000;

/// Entries up to this size are not held to [`MAX_COMPRESSION_RATIO`].
const RATIO_EXEMPT_BYTES: u64 = 1024 * 1024;

/// How many bytes the database entry may inflate to, given the size limit
/// and its compressed size.
fn entry_limit(max_bytes: u64, compressed_size: u64) -> u64 {
    compressed_size
        .saturating_mul(MAX_COMPRESSION_RATIO)
        .max(RATIO_EXEMPT_BYTES)
        .min(max_bytes)
}

/// Restore a backup to the database path.
///
/// The database entry must start with the SQLite header, which is checked
/// before anything is written. Before it replaces the database, the copy
/// must pass the checks of [`inspect_backup_in`] and hold no triggers, no
/// views (except the labels view of older vaults), no virtual tables, no
/// generated columns and no expression or partial indexes. The entry is then streamed into a temporary
/// file beside `db_path`, never held in memory as a whole, and refused if it
/// grows past [`MAX_RESTORED_DB_BYTES`] or inflates more than 1000 times its
/// compressed size (entries up to 1 MiB are exempt from the ratio). Only a
/// complete, flushed copy replaces the database, by an atomic rename, so a
/// failure at any point leaves the previous database untouched.
///
/// The `-wal`, `-shm` and `-journal` files of the previous database do not
/// belong to the restored one. They are renamed aside before the rename and
/// deleted after it; if the new database cannot be moved in, they are put
/// back, so the previous database keeps everything it had. On Unix the
/// folder is synced after the rename.
///
/// The wallet using `db_path` must be closed while it is restored.
pub fn restore_backup(backup_path: &Path, db_path: &Path) -> Result<()> {
    restore_backup_capped(backup_path, db_path, MAX_RESTORED_DB_BYTES)
}

fn restore_backup_capped(backup_path: &Path, db_path: &Path, max_bytes: u64) -> Result<()> {
    restore_backup_with(backup_path, db_path, max_bytes, persist_temp)
}

fn restore_backup_with(
    backup_path: &Path,
    db_path: &Path,
    max_bytes: u64,
    persist: impl FnOnce(tempfile::NamedTempFile, &Path) -> io::Result<()>,
) -> Result<()> {
    let file = File::open(backup_path)
        .map_err(|e| WalletError::BackupError(format!("Failed to open backup: {}", e)))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| WalletError::BackupError(format!("Failed to read backup: {}", e)))?;
    let mut db_file = archive.by_name(DATABASE_FILENAME)
        .map_err(|e| WalletError::BackupError(format!("Database not found in backup: {}", e)))?;
    let limit = entry_limit(max_bytes, db_file.compressed_size());
    if db_file.size() > limit {
        return Err(WalletError::BackupError(format!(
            "Database in backup is too large ({} bytes, limit {})",
            db_file.size(),
            limit
        )));
    }

    // Nothing is written unless the entry starts like an SQLite database.
    let mut head = [0u8; SQLITE_HEADER.len()];
    db_file.read_exact(&mut head).map_err(|_| {
        WalletError::BackupError("The backup does not hold a wallet database: the entry is too short".to_string())
    })?;
    if !has_sqlite_header(&head) {
        return Err(WalletError::BackupError(
            "The backup does not hold a wallet database: the entry is not an SQLite database".to_string(),
        ));
    }

    let parent = match db_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&parent)?;

    // Same folder as the target, so the final rename is atomic.
    let mut temp = tempfile::NamedTempFile::new_in(&parent)
        .map_err(|e| WalletError::BackupError(format!("Failed to create temp file: {}", e)))?;
    temp.as_file_mut()
        .write_all(&head)
        .map_err(|e| WalletError::BackupError(format!("Failed to write database: {}", e)))?;
    // The declared size can lie; the limit is enforced on the bytes read.
    let head_len = head.len() as u64;
    let rest_limit = limit.saturating_sub(head_len).saturating_add(1);
    let copied = io::copy(&mut db_file.take(rest_limit), temp.as_file_mut())
        .map_err(|e| WalletError::BackupError(format!("Failed to read database from backup: {}", e)))?;
    if head_len.saturating_add(copied) > limit {
        return Err(WalletError::BackupError(format!(
            "Database in backup is larger than the limit of {} bytes",
            limit
        )));
    }
    temp.as_file_mut()
        .sync_all()
        .map_err(|e| WalletError::BackupError(format!("Failed to write database: {}", e)))?;

    // The copy is checked like any untrusted database, and its schema must be
    // safe to open as the live vault, before it replaces anything.
    {
        let conn = super::untrusted::open_untrusted(temp.path())?;
        super::untrusted::check_restorable_schema(&conn)?;
    }

    replace_database(temp, db_path, persist)
}

/// Files SQLite keeps beside a database. They belong to the database they
/// were written for and must not survive into the restored one.
const SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Suffix of a sidecar moved aside while the database is replaced.
const PARKED_SUFFIX: &str = ".pre-restore";

/// `db_path` with `suffix` appended to its file name.
fn with_suffix(db_path: &Path, suffix: &str) -> PathBuf {
    let mut name = db_path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Move the sidecars in `parked` back to their own names. Best effort: it
/// runs only on a path that already reports an error.
fn unpark(parked: &[(PathBuf, PathBuf)]) {
    for (sidecar, aside) in parked.iter().rev() {
        let _ = fs::rename(aside, sidecar);
    }
}

/// Put `temp` in place of `db_path`. The previous database's sidecars are
/// first renamed aside (`<name>-wal.pre-restore` and so on), then the new
/// file is moved in, then the parked sidecars are deleted. If moving them
/// aside or moving the new file in fails, the sidecars go back to their names,
/// so the previous database stays complete.
fn replace_database(
    temp: tempfile::NamedTempFile,
    db_path: &Path,
    persist: impl FnOnce(tempfile::NamedTempFile, &Path) -> io::Result<()>,
) -> Result<()> {
    let mut parked: Vec<(PathBuf, PathBuf)> = Vec::new();
    for suffix in SIDECAR_SUFFIXES {
        let sidecar = with_suffix(db_path, suffix);
        if fs::symlink_metadata(&sidecar).is_err() {
            continue;
        }
        let aside = with_suffix(db_path, &format!("{suffix}{PARKED_SUFFIX}"));
        let moved = match fs::remove_file(&aside) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => fs::rename(&sidecar, &aside),
        };
        if let Err(e) = moved {
            unpark(&parked);
            return Err(WalletError::BackupError(format!(
                "Failed to move the {suffix} file aside: {e}"
            )));
        }
        parked.push((sidecar, aside));
    }

    if let Err(e) = persist(temp, db_path) {
        unpark(&parked);
        return Err(WalletError::BackupError(format!("Failed to write database: {e}")));
    }
    sync_parent_dir(db_path);

    for (_, aside) in &parked {
        let _ = fs::remove_file(aside);
    }
    Ok(())
}

/// Move the finished temp file onto `db_path`.
fn persist_temp(temp: tempfile::NamedTempFile, db_path: &Path) -> io::Result<()> {
    temp.persist(db_path).map(drop).map_err(|e| e.error)
}

/// Flush the directory entry of a rename to disk, where the platform allows
/// it. Best effort: the rename itself has already succeeded.
fn sync_parent_dir(db_path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = db_path.parent() {
        let dir = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
        if let Ok(f) = File::open(dir) {
            let _ = f.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = db_path;
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
    let db_path = extract_backup(backup_path, target)?;
    let conn = super::untrusted::open_untrusted(&db_path)?;
    super::untrusted::read_db_version(&conn)
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
/// app-writable temp base folder. The extracted copy is checked and read
/// through a read-only connection (see [`inspect_backup_in`]); nothing in it
/// is changed.
pub fn check_backup_password_in(backup_path: &Path, password: &str, temp_base: &Path) -> Result<bool> {
    let temp_dir = temp_dir_in(temp_base)?;
    let db_path = extract_backup(backup_path, temp_dir.path())?;
    let conn = super::untrusted::open_untrusted(&db_path)?;
    check_backup_kdf_params(&conn)?;
    crate::business::wallet::check_password_on(&conn, password)
}

/// Refuse a backup whose key derivation costs more than a backup may ask for
/// (see [`crate::crypto::kdf::KdfParams::check_backup`]), before any
/// derivation runs.
fn check_backup_kdf_params(conn: &rusqlite::Connection) -> Result<()> {
    if let Some(rec) = crate::database::queries::get_crypto_record(conn)? {
        crate::crypto::kdf::KdfParams { m_cost_kib: rec.m_cost_kib, t_cost: rec.t_cost, p_cost: rec.p_cost }
            .check_backup()
            .map_err(|e| WalletError::BackupError(format!("crypto record: {e}")))?;
    }
    Ok(())
}

/// What a backup holds, read without its password. Lets an app warn before a
/// restore replaces newer data, for example passkeys a pre-passkey backup has
/// never seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInspection {
    /// The database version string (`"6"` for current vaults).
    pub db_version: String,
    /// When the backup was made, from its file name, if it follows the naming.
    pub created: Option<chrono::DateTime<chrono::Utc>>,
    /// Live entries (not folders, not in the trash).
    pub item_count: u32,
    /// Live passkeys on live entries.
    pub passkey_count: u32,
}

/// Inspect a backup without its password, extracting into the given
/// app-writable temp base folder. Item and field types are stored unencrypted,
/// so counting needs no key.
///
/// The backup's database is untrusted: before any query it must carry the
/// SQLite header, pass `PRAGMA quick_check` and hold its wallet tables as real
/// tables. It is opened read-only, with SQLite's defensive mode on, the schema
/// untrusted and a fixed work budget, so a crafted file fails with an error
/// instead of running for long.
pub fn inspect_backup_in(backup_path: &Path, temp_base: &Path) -> Result<BackupInspection> {
    let temp_dir = temp_dir_in(temp_base)?;
    let db_path = extract_backup(backup_path, temp_dir.path())?;
    let conn = super::untrusted::open_untrusted(&db_path)?;

    let db_version = super::untrusted::read_db_version(&conn)?;
    let item_count: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_items
         WHERE COALESCE(deleted, 0) = 0 AND COALESCE(folder, 0) = 0 AND item_id <> ?1",
        [crate::ROOT_ID],
        |row| row.get(0),
    )?;
    let passkey_count: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_fields f
         JOIN nswallet_items i ON i.item_id = f.item_id
         WHERE f.type = ?1 AND COALESCE(f.deleted, 0) = 0
           AND COALESCE(i.deleted, 0) = 0 AND COALESCE(i.folder, 0) = 0",
        [crate::passkey::FIELD_PASSKEY],
        |row| row.get(0),
    )?;
    let created = backup_path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(super::get_date_from_backup_filename);

    Ok(BackupInspection { db_version, created, item_count, passkey_count })
}

/// Which vault a backup belongs to and whether its file was rebuilt after
/// the format upgrade. Read without the backup's password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackupOrigin {
    /// The database version string (`"6"` for current vaults).
    pub(crate) db_version: String,
    /// The vault's `database_id`, if the properties row has one.
    pub(crate) database_id: Option<String>,
    /// The compaction marker the backup's database carries, if any.
    pub(crate) compacted_at: Option<String>,
}

/// Read a backup's [`BackupOrigin`], with the same untrusted-file checks as
/// [`inspect_backup_in`].
pub(crate) fn backup_origin_in(backup_path: &Path, temp_base: &Path) -> Result<BackupOrigin> {
    use rusqlite::OptionalExtension;

    let temp_dir = temp_dir_in(temp_base)?;
    let db_path = extract_backup(backup_path, temp_dir.path())?;
    let conn = super::untrusted::open_untrusted(&db_path)?;

    let db_version = super::untrusted::read_db_version(&conn)?;
    let database_id = conn
        .query_row("SELECT database_id FROM nswallet_properties LIMIT 1", [], |row| {
            row.get::<_, Option<String>>(0)
        })
        .optional()?
        .flatten();
    let compacted_at = crate::database::queries::get_compacted_at(&conn)?;
    Ok(BackupOrigin { db_version, database_id, compacted_at })
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

    /// Bytes that start like an SQLite database but are not one.
    const FAKE_DB: &str = "SQLite format 3\0test database content";

    /// Entry content of [`create_test_backup`]: an empty wallet database.
    fn test_db() -> Vec<u8> {
        static DB: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        DB.get_or_init(|| {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("t.db");
            drop(crate::database::Database::create(&path).unwrap());
            fs::read(&path).unwrap()
        })
        .clone()
    }

    fn test_db_len() -> u64 {
        test_db().len() as u64
    }

    fn create_test_backup(dir: &Path) -> PathBuf {
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        let backup_path = dir.join("test-backup.zip");
        let file = File::create(&backup_path).unwrap();
        let mut zip = ZipWriter::new(file);

        let options = SimpleFileOptions::default();
        zip.start_file(DATABASE_FILENAME, options).unwrap();
        zip.write_all(&test_db()).unwrap();
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
        assert_eq!(fs::read(&db_path).unwrap(), test_db());
    }

    #[test]
    fn test_restore_backup() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());

        let db_path = temp_dir.path().join("restored").join(DATABASE_FILENAME);
        restore_backup(&backup_path, &db_path).unwrap();

        assert!(db_path.exists());
        assert_eq!(fs::read(&db_path).unwrap(), test_db());
    }

    #[test]
    fn restore_replaces_an_existing_database() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let db_path = temp_dir.path().join("w").join(DATABASE_FILENAME);
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        fs::write(&db_path, b"OLD DATABASE").unwrap();

        restore_backup(&backup_path, &db_path).unwrap();
        assert_eq!(fs::read(&db_path).unwrap(), test_db());
    }

    #[test]
    fn restore_refuses_an_entry_over_the_limit_and_keeps_the_old_database() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let db_path = temp_dir.path().join("w").join(DATABASE_FILENAME);
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        fs::write(&db_path, b"OLD DATABASE").unwrap();

        let err = restore_backup_capped(&backup_path, &db_path, test_db_len() - 1).unwrap_err();
        assert!(matches!(err, WalletError::BackupError(_)));
        assert_eq!(fs::read_to_string(&db_path).unwrap(), "OLD DATABASE");
        // No temp file left behind.
        let leftovers: Vec<_> = fs::read_dir(db_path.parent().unwrap()).unwrap().collect();
        assert_eq!(leftovers.len(), 1);

        // Exactly at the limit is fine.
        restore_backup_capped(&backup_path, &db_path, test_db_len()).unwrap();
        assert_eq!(fs::read(&db_path).unwrap(), test_db());
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
    fn restore_removes_wal_and_shm_of_the_previous_database() {
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
        assert_eq!(fs::read(&db_path).unwrap(), test_db());
    }

    #[test]
    fn restore_creates_missing_parent_folders() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let target = temp_dir.path().join("x").join("y").join(DATABASE_FILENAME);
        restore_backup(&backup_path, &target).unwrap();
        assert!(target.exists());
    }

    fn zip_with_db_entry(path: &Path, content: &[u8]) {
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        zip.start_file(DATABASE_FILENAME, zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(content).unwrap();
        zip.finish().unwrap();
    }

    /// Rewrite the uncompressed size the archive declares for its only entry,
    /// in both the local header and the central directory.
    fn declare_uncompressed_size(path: &Path, size: u32) {
        let mut bytes = fs::read(path).unwrap();
        let patch = |bytes: &mut Vec<u8>, signature: &[u8], offset: usize| {
            let at = bytes.windows(4).position(|w| w == signature).unwrap() + offset;
            bytes[at..at + 4].copy_from_slice(&size.to_le_bytes());
        };
        patch(&mut bytes, b"PK\x03\x04", 22);
        patch(&mut bytes, b"PK\x01\x02", 24);
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn the_restore_limit_is_256_mebibytes() {
        assert_eq!(MAX_RESTORED_DB_BYTES, 256 << 20);
    }

    #[test]
    fn the_entry_limit_follows_size_and_ratio() {
        let max = MAX_RESTORED_DB_BYTES;
        // Small entries are exempt from the ratio.
        assert_eq!(entry_limit(max, 0), RATIO_EXEMPT_BYTES);
        assert_eq!(entry_limit(max, 100), RATIO_EXEMPT_BYTES);
        assert_eq!(entry_limit(max, 4096), 4096 * MAX_COMPRESSION_RATIO);
        assert_eq!(entry_limit(max, u64::MAX), max);
        // The size cap always wins.
        assert_eq!(entry_limit(20, 0), 20);
    }

    /// Write a zip whose database entry is `head` followed by `zeros` zero
    /// bytes, deflated.
    fn deflated_zip(path: &Path, head: &[u8], zeros: usize) {
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(9));
        zip.start_file(DATABASE_FILENAME, options).unwrap();
        zip.write_all(head).unwrap();
        let chunk = vec![0u8; 1 << 20];
        let mut left = zeros;
        while left > 0 {
            let n = left.min(chunk.len());
            zip.write_all(&chunk[..n]).unwrap();
            left -= n;
        }
        zip.finish().unwrap();
    }

    #[test]
    fn an_entry_that_is_not_sqlite_is_refused_before_anything_is_written() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = temp_dir.path().join("zeros.zip");
        deflated_zip(&backup_path, b"", 32 << 20);
        let target = temp_dir.path().join("w");
        fs::create_dir_all(&target).unwrap();

        let started = std::time::Instant::now();
        let err = restore_backup(&backup_path, &target.join(DATABASE_FILENAME)).unwrap_err();
        assert!(matches!(err, WalletError::BackupError(_)));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        // The header is checked before the temp file exists.
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);

        // Through the preview path too, nothing stays behind.
        let base = temp_dir.path().join("tmp");
        assert!(inspect_backup_in(&backup_path, &base).is_err());
        assert_eq!(fs::read_dir(&base).unwrap().count(), 0);
    }

    #[test]
    fn an_entry_shorter_than_the_header_is_refused() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = temp_dir.path().join("short.zip");
        zip_with_db_entry(&backup_path, b"SQLite");
        let db_path = temp_dir.path().join(DATABASE_FILENAME);
        assert!(matches!(restore_backup(&backup_path, &db_path), Err(WalletError::BackupError(_))));
        assert!(!db_path.exists());
    }

    #[test]
    fn an_entry_that_inflates_beyond_the_ratio_is_refused() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = temp_dir.path().join("ratio.zip");
        deflated_zip(&backup_path, SQLITE_HEADER, 8 << 20);
        let db_path = temp_dir.path().join("w").join(DATABASE_FILENAME);

        let err = restore_backup(&backup_path, &db_path).unwrap_err();
        assert!(matches!(err, WalletError::BackupError(_)), "{err:?}");
        assert!(!db_path.parent().unwrap().exists());

        // The same when the entry declares a small size: the bytes read count.
        declare_uncompressed_size(&backup_path, 16);
        let err = restore_backup(&backup_path, &db_path).unwrap_err();
        assert!(matches!(err, WalletError::BackupError(_)), "{err:?}");
        assert!(!db_path.exists());
        assert_eq!(fs::read_dir(db_path.parent().unwrap()).unwrap().count(), 0);
    }

    #[test]
    fn an_entry_declared_larger_than_the_limit_is_refused() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        declare_uncompressed_size(&backup_path, u32::MAX);
        let db_path = temp_dir.path().join(DATABASE_FILENAME);
        let err = restore_backup(&backup_path, &db_path).unwrap_err();
        assert!(matches!(err, WalletError::BackupError(_)));
        assert!(!db_path.exists());
    }

    #[test]
    fn a_real_vault_backup_restores() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("src").join(DATABASE_FILENAME);
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let db = crate::database::Database::create(&db_path).unwrap();
        let backup = super::super::create::create_backup(&temp_dir.path().join("b"), &db, true).unwrap();
        drop(db);
        let target = temp_dir.path().join("dst").join(DATABASE_FILENAME);
        restore_backup(&backup, &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), fs::read(&db_path).unwrap());
    }

    #[test]
    fn restore_enforces_the_limit_on_the_bytes_read_when_the_declared_size_lies() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        declare_uncompressed_size(&backup_path, u32::try_from(test_db_len() - 1).unwrap());
        let db_path = temp_dir.path().join("w").join(DATABASE_FILENAME);
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        fs::write(&db_path, b"OLD DATABASE").unwrap();

        // Declares exactly the limit, inflates one byte past it.
        let err = restore_backup_capped(&backup_path, &db_path, test_db_len() - 1).unwrap_err();
        assert!(matches!(err, WalletError::BackupError(_)));
        assert_eq!(fs::read_to_string(&db_path).unwrap(), "OLD DATABASE");
    }

    fn sidecar(dir: &Path, suffix: &str) -> PathBuf {
        dir.join(format!("{DATABASE_FILENAME}{suffix}"))
    }

    /// An old database with all three sidecars, each holding its own name.
    fn old_database_with_sidecars(dir: &Path) -> PathBuf {
        let db_path = dir.join(DATABASE_FILENAME);
        fs::write(&db_path, b"OLD DATABASE").unwrap();
        for suffix in SIDECAR_SUFFIXES {
            fs::write(sidecar(dir, suffix), suffix.as_bytes()).unwrap();
        }
        db_path
    }

    fn assert_old_database_intact(dir: &Path, db_path: &Path) {
        assert_eq!(fs::read_to_string(db_path).unwrap(), "OLD DATABASE");
        for suffix in SIDECAR_SUFFIXES {
            assert_eq!(fs::read_to_string(sidecar(dir, suffix)).unwrap(), suffix, "{suffix}");
            assert!(!sidecar(dir, &format!("{suffix}{PARKED_SUFFIX}")).exists(), "{suffix} parked");
        }
    }

    #[test]
    fn restore_removes_every_sidecar_of_the_previous_database() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let dir = temp_dir.path().join("w");
        fs::create_dir_all(&dir).unwrap();
        let db_path = old_database_with_sidecars(&dir);

        restore_backup(&backup_path, &db_path).unwrap();
        assert_eq!(fs::read(&db_path).unwrap(), test_db());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "only the database is left");
    }

    #[test]
    fn a_failed_rename_keeps_the_previous_database_and_its_sidecars() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let dir = temp_dir.path().join("w");
        fs::create_dir_all(&dir).unwrap();
        let db_path = old_database_with_sidecars(&dir);

        let err = restore_backup_with(&backup_path, &db_path, MAX_RESTORED_DB_BYTES, |_, _| {
            Err(io::Error::other("simulated"))
        })
        .unwrap_err();
        assert!(matches!(err, WalletError::BackupError(_)));
        assert_old_database_intact(&dir, &db_path);
        // The temp copy is gone as well.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1 + SIDECAR_SUFFIXES.len());
    }

    #[test]
    fn a_sidecar_that_cannot_be_moved_aside_fails_the_restore() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let dir = temp_dir.path().join("w");
        fs::create_dir_all(&dir).unwrap();
        let db_path = old_database_with_sidecars(&dir);
        // A non-empty folder where the parked `-shm` would go blocks it, after
        // `-wal` has already been moved aside.
        let blocker = sidecar(&dir, &format!("-shm{PARKED_SUFFIX}"));
        fs::create_dir(&blocker).unwrap();
        fs::write(blocker.join("x"), b"x").unwrap();

        let err = restore_backup(&backup_path, &db_path).unwrap_err();
        assert!(matches!(err, WalletError::BackupError(_)));
        fs::remove_dir_all(&blocker).unwrap();
        assert_old_database_intact(&dir, &db_path);
    }

    #[test]
    fn a_stale_parked_sidecar_is_replaced() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let dir = temp_dir.path().join("w");
        fs::create_dir_all(&dir).unwrap();
        let db_path = old_database_with_sidecars(&dir);
        fs::write(sidecar(&dir, &format!("-wal{PARKED_SUFFIX}")), b"stale").unwrap();

        restore_backup(&backup_path, &db_path).unwrap();
        assert_eq!(fs::read(&db_path).unwrap(), test_db());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn a_parked_sidecar_that_cannot_be_deleted_does_not_fail_the_restore() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let db_path = temp_dir.path().join(DATABASE_FILENAME);
        fs::write(&db_path, b"OLD DATABASE").unwrap();
        // A folder named like the `-wal` file is moved aside but is not a file.
        fs::create_dir(sidecar(temp_dir.path(), "-wal")).unwrap();

        restore_backup(&backup_path, &db_path).unwrap();
        assert_eq!(fs::read(&db_path).unwrap(), test_db());
        assert!(!sidecar(temp_dir.path(), "-wal").exists());
    }

    #[test]
    fn a_leftover_journal_of_the_previous_database_is_removed() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path();
        // The backup: a database with one row.
        let backup_path = zip_of_db(
            dir,
            "new.zip",
            &format!("{MINIMAL_WALLET_SCHEMA} CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('restored');"),
        );
        // The previous database plus a leftover rollback journal.
        let db_path = dir.join("w").join(DATABASE_FILENAME);
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        fs::write(&db_path, b"OLD DATABASE").unwrap();
        fs::write(with_suffix(&db_path, "-journal"), vec![0xD9u8; 4096]).unwrap();

        restore_backup(&backup_path, &db_path).unwrap();
        assert!(!with_suffix(&db_path, "-journal").exists());
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "restored");
    }

    #[test]
    fn a_small_entry_without_the_sqlite_header_is_refused() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = temp_dir.path().join("text.zip");
        zip_with_db_entry(&backup_path, b"this is plain text, not a database file");
        let db_path = temp_dir.path().join("w").join(DATABASE_FILENAME);
        let err = restore_backup(&backup_path, &db_path).unwrap_err();
        assert!(err.to_string().contains("not an SQLite database"), "{err}");
        assert!(!db_path.parent().unwrap().exists());
    }

    #[test]
    fn a_tiny_cap_refuses_an_entry_declared_above_it() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        let db_path = temp_dir.path().join(DATABASE_FILENAME);
        let err = restore_backup_capped(&backup_path, &db_path, 8).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
        assert!(!db_path.exists());
    }

    #[test]
    fn a_bare_file_name_restores_into_the_current_folder() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = create_test_backup(temp_dir.path());
        // A relative path without a folder: the temp file and the rename go
        // to the current folder. Persisting is replaced so nothing lands in
        // the real working directory.
        let name = Path::new("iwcore-restore-bare-name.dat");
        let mut seen = None;
        restore_backup_with(&backup_path, name, MAX_RESTORED_DB_BYTES, |temp, path| {
            seen = Some((temp.path().parent().map(Path::to_path_buf), path.to_path_buf()));
            Ok(())
        })
        .unwrap();
        let (temp_parent, path) = seen.unwrap();
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(temp_parent.unwrap().canonicalize().unwrap(), cwd);
        assert_eq!(path, name);
        assert!(!name.exists());
    }

    #[test]
    fn a_backup_without_a_database_entry_does_not_verify() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = temp_dir.path().join("other.zip");
        let mut zip = zip::ZipWriter::new(File::create(&backup_path).unwrap());
        zip.start_file("readme.txt", zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(b"hello").unwrap();
        zip.finish().unwrap();

        assert!(!verify_backup(&backup_path).unwrap());
        let err = restore_backup(&backup_path, &temp_dir.path().join(DATABASE_FILENAME)).unwrap_err();
        assert!(err.to_string().contains("Database not found"), "{err}");
    }

    #[test]
    fn a_backup_with_an_empty_database_does_not_verify() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = temp_dir.path().join("empty-db.zip");
        zip_with_db_entry(&backup_path, b"");

        assert!(!verify_backup(&backup_path).unwrap());
    }

    #[test]
    fn a_backup_from_a_newer_database_version_is_not_compatible() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = zip_of_db(
            temp_dir.path(),
            "future.zip",
            &format!("{MINIMAL_WALLET_SCHEMA} INSERT INTO nswallet_properties (version) VALUES ('999');"),
        );
        let base = temp_dir.path().join("app_temp");

        assert!(!is_backup_compatible_in(&backup_path, "6", &base).unwrap());
        assert!(is_backup_compatible_in(&backup_path, "999", &base).unwrap());
    }

    #[test]
    fn test_get_backup_db_version_in_uses_base() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = zip_of_db(temp_dir.path(), "v.zip", MINIMAL_WALLET_SCHEMA);

        // App-controlled temp base that does not yet exist (must be created)
        let base = temp_dir.path().join("app_temp").join("nested");
        let version = get_backup_db_version_in(&backup_path, &base).unwrap();

        // No properties row → defaults to "1"
        assert_eq!(version, "1");
        assert!(base.exists(), "temp base folder should have been created");
    }

    #[test]
    fn test_is_backup_compatible_in() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = zip_of_db(temp_dir.path(), "v.zip", MINIMAL_WALLET_SCHEMA);
        let base = temp_dir.path().join("app_temp");

        // version "1" backup is compatible with current "5"
        assert!(is_backup_compatible_in(&backup_path, "5", &base).unwrap());
        assert!(is_backup_compatible(&backup_path, "5").unwrap());
        assert_eq!(get_backup_db_version(&backup_path).unwrap(), "1");
    }

    /// Tables a wallet database must have, without anything else.
    const MINIMAL_WALLET_SCHEMA: &str = "
        CREATE TABLE nswallet_properties (database_id TEXT, version TEXT, email TEXT);
        CREATE TABLE nswallet_items (item_id TEXT, name BLOB, deleted INT, folder INT);
        CREATE TABLE nswallet_fields (item_id TEXT, type TEXT, value BLOB, deleted INT);";

    /// Build an SQLite database from `sql` and wrap it in a backup zip.
    fn zip_of_db(dir: &Path, zip_name: &str, sql: &str) -> PathBuf {
        let db_path = dir.join(format!("{zip_name}.db"));
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch(sql).unwrap();
        }
        let backup_path = dir.join(zip_name);
        zip_with_db_entry(&backup_path, &fs::read(&db_path).unwrap());
        backup_path
    }

    /// A backup whose `nswallet_items` is a view over a query without end.
    fn endless_view_backup(dir: &Path) -> PathBuf {
        zip_of_db(
            dir,
            "iwb-20261031-140053-manual.zip",
            "CREATE TABLE nswallet_properties (database_id TEXT, version TEXT, email TEXT);
             INSERT INTO nswallet_properties VALUES ('x', '6', NULL);
             CREATE VIEW nswallet_items AS
               WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r)
               SELECT 'x' AS item_id, x'00' AS name, 0 AS deleted, 0 AS folder FROM r;
             CREATE TABLE nswallet_fields (item_id TEXT, type TEXT, value BLOB, deleted INT);",
        )
    }

    fn assert_quick_error<T: std::fmt::Debug>(what: &str, f: impl FnOnce() -> Result<T>) {
        let started = std::time::Instant::now();
        let r = f();
        let took = started.elapsed();
        assert!(r.is_err(), "{what} must fail, got {r:?}");
        assert!(took < std::time::Duration::from_millis(500), "{what} took {took:?}");
    }

    #[test]
    fn a_backup_with_an_endless_view_fails_fast_everywhere() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = endless_view_backup(temp_dir.path());
        let base = temp_dir.path().join("tmp");

        assert_quick_error("inspect", || inspect_backup_in(&backup_path, &base));
        assert_quick_error("version", || get_backup_db_version_in(&backup_path, &base));
        assert_quick_error("compatible", || is_backup_compatible_in(&backup_path, "6", &base));
        assert_quick_error("password", || check_backup_password_in(&backup_path, "pw", &base));
        // Nothing extracted is left behind.
        assert_eq!(fs::read_dir(&base).unwrap().count(), 0);
    }

    #[test]
    fn a_backup_that_is_not_an_sqlite_database_is_refused() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = temp_dir.path().join("fake.zip");
        zip_with_db_entry(&backup_path, FAKE_DB.as_bytes());
        let base = temp_dir.path().join("tmp");

        assert!(matches!(inspect_backup_in(&backup_path, &base), Err(WalletError::BackupError(_))));
        assert!(get_backup_db_version_in(&backup_path, &base).is_err());
        assert!(check_backup_password_in(&backup_path, "pw", &base).is_err());
    }

    #[test]
    fn a_backup_password_check_needs_something_to_verify_against() {
        let temp_dir = TempDir::new().unwrap();
        // A pre-v5 schema that `Wallet::open` would have migrated in place.
        let backup_path = zip_of_db(
            temp_dir.path(),
            "old.zip",
            &format!("{MINIMAL_WALLET_SCHEMA} INSERT INTO nswallet_properties VALUES ('id', '3', '0');"),
        );
        let base = temp_dir.path().join("tmp");
        // No root and no data: the password cannot be verified.
        assert!(check_backup_password_in(&backup_path, "pw", &base).is_err());
    }

    /// A backup of a vault whose crypto record asks for more than a backup
    /// may is refused before the password is derived.
    #[test]
    fn a_backup_asking_for_a_costly_key_derivation_is_refused() {
        let temp_dir = TempDir::new().unwrap();
        let wallet_dir = temp_dir.path().join("w");
        let wallet = crate::Wallet::create(&wallet_dir, "pw", "en").unwrap();
        drop(wallet);
        let db = wallet_dir.join(DATABASE_FILENAME);
        let base = temp_dir.path().join("tmp");
        let backup_of = |name: &str| {
            let path = temp_dir.path().join(name);
            zip_with_db_entry(&path, &fs::read(&db).unwrap());
            path
        };
        assert!(check_backup_password_in(&backup_of("ok.zip"), "pw", &base).unwrap());

        let set = |sql: &str| rusqlite::Connection::open(&db).unwrap().execute_batch(sql).unwrap();
        for sql in [
            "UPDATE nswallet_crypto SET kdf_m_cost = 262145",
            "UPDATE nswallet_crypto SET kdf_m_cost = 65536, kdf_t_cost = 13",
            "UPDATE nswallet_crypto SET kdf_t_cost = 3, kdf_p_cost = 5",
        ] {
            set(sql);
            let err = check_backup_password_in(&backup_of("costly.zip"), "pw", &base).unwrap_err();
            assert!(matches!(&err, WalletError::BackupError(m) if m.contains("for a backup")), "{sql}: {err:?}");
        }
    }

    /// A backup whose schema would run code in the live vault is refused,
    /// and the previous database stays as it was.
    #[test]
    fn a_backup_with_code_in_its_schema_is_not_restored() {
        for (what, sql) in [
            ("trigger", "CREATE TRIGGER t AFTER INSERT ON nswallet_items BEGIN DELETE FROM nswallet_fields; END;"),
            ("view", "CREATE VIEW v AS SELECT 1;"),
            ("virtual table", "CREATE VIRTUAL TABLE v USING fts5(a);"),
            ("generated column", "CREATE TABLE g (a INT, b INT AS (a * 2));"),
            ("expression index", "CREATE INDEX i ON nswallet_items (length(item_id));"),
            ("partial index", "CREATE INDEX i ON nswallet_items (item_id) WHERE deleted = 0;"),
        ] {
            let temp_dir = TempDir::new().unwrap();
            let backup_path = zip_of_db(temp_dir.path(), "b.zip", &format!("{MINIMAL_WALLET_SCHEMA} {sql}"));
            let db_path = old_database_with_sidecars(temp_dir.path());
            let err = restore_backup(&backup_path, &db_path).unwrap_err();
            assert!(matches!(err, WalletError::BackupError(_)), "{what}: {err:?}");
            assert_old_database_intact(temp_dir.path(), &db_path);
        }
    }

    #[test]
    fn a_backup_that_fails_inspection_is_not_restored() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = endless_view_backup(temp_dir.path());
        let db_path = old_database_with_sidecars(temp_dir.path());
        assert!(restore_backup(&backup_path, &db_path).is_err());
        assert_old_database_intact(temp_dir.path(), &db_path);

        let fake = temp_dir.path().join("fake.zip");
        zip_with_db_entry(&fake, FAKE_DB.as_bytes());
        assert!(restore_backup(&fake, &db_path).is_err());
        assert_old_database_intact(temp_dir.path(), &db_path);
    }

    /// Plain indexes, the labels view of older vaults and the schema iwcore
    /// writes restore.
    #[test]
    fn a_backup_with_the_usual_schema_restores() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = zip_of_db(
            temp_dir.path(),
            "b.zip",
            &format!(
                "{MINIMAL_WALLET_SCHEMA}
                 CREATE TABLE nswallet_labels (field_type, label_name, value_type, icon, system, change_timestamp, deleted);
                 {};
                 CREATE INDEX i ON nswallet_items (item_id);
                 CREATE UNIQUE INDEX j ON nswallet_fields (item_id, type);",
                crate::database::schema::CREATE_LABELS_VIEW
            ),
        );
        let db_path = temp_dir.path().join("w").join(DATABASE_FILENAME);
        restore_backup(&backup_path, &db_path).unwrap();
        assert!(db_path.exists());
    }

    /// The fuzz seeds for backups stay valid wallet databases.
    #[test]
    fn the_restore_fuzz_seeds_pass_inspection() {
        let seeds = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/restore");
        // The published crate leaves out the fuzz folder.
        if !seeds.exists() {
            return;
        }
        for name in ["wallet_v6", "wallet_legacy"] {
            let bytes = fs::read(seeds.join(name)).unwrap();
            let temp_dir = TempDir::new().unwrap();
            let backup_path = temp_dir.path().join("iwb-20260101-120000-manual.zip");
            zip_with_db_entry(&backup_path, &bytes[1..]);
            let base = temp_dir.path().join("tmp");
            inspect_backup_in(&backup_path, &base).unwrap();
            assert!(!check_backup_password_in(&backup_path, "Sun001!", &base).unwrap(), "{name}");
        }
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
