//! Database connection management

use std::path::{Path, PathBuf};
use rusqlite::Connection;
use crate::error::{WalletError, Result};
use super::schema;

/// Database connection wrapper
pub struct Database {
    /// Path to the database file
    path: PathBuf,
    /// SQLite connection
    conn: Option<Connection>,
}

impl Database {
    /// How long SQLite waits on a locked database before returning
    /// SQLITE_BUSY. Without this the default is 0: any leftover lock (e.g.
    /// stale sidecar files copied in by the legacy upgrade, or a second
    /// connection during a slow first-unlock migration) fails instantly
    /// instead of riding out a short contention window.
    const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Open a database at the specified path
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Self::BUSY_TIMEOUT)?;
        Ok(Self {
            path: path.to_path_buf(),
            conn: Some(conn),
        })
    }

    /// Create a new database with all tables
    pub fn create(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Self::BUSY_TIMEOUT)?;

        // Create all tables
        for sql in schema::CREATE_ALL_TABLES {
            conn.execute(sql, [])?;
        }

        Ok(Self {
            path: path.to_path_buf(),
            conn: Some(conn),
        })
    }

    /// Get a reference to the connection
    pub fn connection(&self) -> Result<&Connection> {
        self.conn.as_ref().ok_or_else(|| {
            WalletError::DatabaseError("Database not open".to_string())
        })
    }

    /// Get a mutable reference to the connection
    pub fn connection_mut(&mut self) -> Result<&mut Connection> {
        self.conn.as_mut().ok_or_else(|| {
            WalletError::DatabaseError("Database not open".to_string())
        })
    }

    /// Get the database path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Close the database connection
    pub fn close(&mut self) {
        self.conn = None;
    }

    /// Check if database is open
    pub fn is_open(&self) -> bool {
        self.conn.is_some()
    }

    /// Begin a transaction
    ///
    /// If the connection is already inside a transaction (a previous operation
    /// died mid-flight, e.g. a panicked unlock whose mutex guard was recovered),
    /// roll that stale transaction back and retry once, so one failed attempt
    /// cannot wedge every subsequent one.
    pub fn begin_transaction(&mut self) -> Result<()> {
        let conn = self.connection()?;
        if conn.execute("BEGIN TRANSACTION", []).is_err() {
            let _ = conn.execute("ROLLBACK", []);
            conn.execute("BEGIN TRANSACTION", [])?;
        }
        Ok(())
    }

    /// Commit a transaction
    pub fn commit_transaction(&mut self) -> Result<()> {
        self.connection()?.execute("COMMIT", [])?;
        Ok(())
    }

    /// Rollback a transaction
    pub fn rollback_transaction(&mut self) -> Result<()> {
        self.connection()?.execute("ROLLBACK", [])?;
        Ok(())
    }

    /// Force a WAL checkpoint to write all data to the main database file
    ///
    /// Uses TRUNCATE mode which checkpoints all frames and truncates the WAL file.
    /// This should be called after write operations to ensure data is persisted.
    pub fn checkpoint(&self) -> Result<()> {
        self.connection()?.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_checkpoint_no_error() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let db = Database::create(&db_path).unwrap();

        // Checkpoint should succeed even on fresh database
        db.checkpoint().unwrap();
    }

    #[test]
    fn test_begin_transaction_recovers_from_stale_transaction() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let mut db = Database::create(&db_path).unwrap();

        // Simulate a previous operation that died mid-transaction without
        // rolling back (e.g. a panicked unlock).
        db.begin_transaction().unwrap();

        // A fresh begin must not fail: it rolls the stale transaction back
        // and starts a new one.
        db.begin_transaction().unwrap();
        db.commit_transaction().unwrap();
    }

    #[test]
    fn test_checkpoint_after_write() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let db = Database::create(&db_path).unwrap();

        // Insert some data
        db.connection().unwrap().execute(
            "INSERT INTO nswallet_properties (database_id, lang, version, email, sync_timestamp, update_timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            rusqlite::params!["test-id", "en", "4", "0", "2024-01-01 00:00:00", "2024-01-01 00:00:00"]
        ).unwrap();

        // Checkpoint should succeed after write
        db.checkpoint().unwrap();
    }

    #[test]
    fn test_checkpoint_clears_wal() {
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let wal_path = temp_dir.path().join("test.db-wal");

        let db = Database::create(&db_path).unwrap();

        // Enable WAL mode explicitly
        db.connection().unwrap().execute_batch("PRAGMA journal_mode=WAL").unwrap();

        // Insert data to create WAL entries
        db.connection().unwrap().execute(
            "INSERT INTO nswallet_properties (database_id, lang, version, email, sync_timestamp, update_timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            rusqlite::params!["test-id", "en", "4", "0", "2024-01-01 00:00:00", "2024-01-01 00:00:00"]
        ).unwrap();

        // WAL file might exist with data
        let wal_size_before = fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);

        // Checkpoint with TRUNCATE should clear WAL
        db.checkpoint().unwrap();

        // After checkpoint, WAL should be empty or very small
        let wal_size_after = fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);

        // WAL should be truncated (0 bytes or gone)
        assert!(wal_size_after == 0 || !wal_path.exists() || wal_size_after < wal_size_before,
            "WAL should be truncated after checkpoint");
    }
}
