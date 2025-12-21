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
    /// Open a database at the specified path
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            conn: Some(conn),
        })
    }

    /// Create a new database with all tables
    pub fn create(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;

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
    pub fn begin_transaction(&mut self) -> Result<()> {
        self.connection()?.execute("BEGIN TRANSACTION", [])?;
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
}

impl Drop for Database {
    fn drop(&mut self) {
        self.close();
    }
}
