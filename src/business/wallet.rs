//! Main Wallet API
//!
//! This module provides the primary interface for interacting with
//! an IntelliWallet database.

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use crate::error::{WalletError, Result};
use crate::database::{Database, IWItem, IWField, IWLabel, IWProperties};
use crate::database::queries::{self, parse_timestamp};
use crate::crypto;
use crate::utils::generate_database_id;
use crate::{DATABASE_FILENAME, ROOT_ID, ROOT_PARENT_ID, DB_VERSION, ENCRYPTION_COUNT_DEFAULT};

/// Main wallet interface
pub struct Wallet {
    /// Path to the wallet folder
    pub(crate) folder: PathBuf,
    /// Database connection
    pub(crate) db: Option<Database>,
    /// Current password (when unlocked)
    pub(crate) password: Option<String>,
    /// Encryption iteration count
    pub(crate) encryption_count: u32,
    /// Cached items (decrypted)
    pub(crate) items_cache: Option<Vec<IWItem>>,
    /// Cached fields (decrypted)
    pub(crate) fields_cache: Option<Vec<IWField>>,
    /// Cached labels
    pub(crate) labels_cache: Option<HashMap<String, IWLabel>>,
}

impl Wallet {
    /// Open a wallet from a folder
    ///
    /// The folder should contain a `nswallet.dat` file.
    pub fn open(folder: &Path) -> Result<Self> {
        let db_path = folder.join(DATABASE_FILENAME);

        if !db_path.exists() {
            return Err(WalletError::DatabaseNotFound(
                db_path.to_string_lossy().to_string()
            ));
        }

        let db = Database::open(&db_path)?;

        Ok(Self {
            folder: folder.to_path_buf(),
            db: Some(db),
            password: None,
            encryption_count: ENCRYPTION_COUNT_DEFAULT,
            items_cache: None,
            fields_cache: None,
            labels_cache: None,
        })
    }

    /// Create a new wallet in the specified folder
    pub fn create(folder: &Path, password: &str, lang: &str) -> Result<Self> {
        std::fs::create_dir_all(folder)?;

        let db_path = folder.join(DATABASE_FILENAME);
        let db = Database::create(&db_path)?;

        let mut wallet = Self {
            folder: folder.to_path_buf(),
            db: Some(db),
            password: Some(password.to_string()),
            encryption_count: 0, // New databases use 0
            items_cache: None,
            fields_cache: None,
            labels_cache: None,
        };

        // Initialize the database with required data
        wallet.init_new_database(password, lang)?;

        Ok(wallet)
    }

    /// Initialize a new database with properties and root item
    fn init_new_database(&mut self, password: &str, lang: &str) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        // Create properties
        let db_id = generate_database_id();
        queries::set_properties(conn, &db_id, lang, DB_VERSION, 0)?;

        // Create root item with encrypted random string
        let root_data = crate::utils::generate_id(32);
        let encrypted = crypto::encrypt(&root_data, password, 0, None)
            .map_err(|e| WalletError::EncryptionError(e))?;
        queries::create_item(conn, ROOT_ID, ROOT_PARENT_ID, &encrypted, "", true)?;

        // Add system labels
        self.add_system_labels()?;

        Ok(())
    }

    /// Unlock the wallet with a password
    pub fn unlock(&mut self, password: &str) -> Result<bool> {
        // Try to decrypt the root item to verify password
        let db = self.db.as_ref().ok_or(WalletError::DatabaseError(
            "Database not open".to_string()
        ))?;

        let conn = db.connection()?;

        // Get root item's encrypted name
        let root_name = queries::get_root_item_raw(conn)?;

        let Some(encrypted_name) = root_name else {
            return Err(WalletError::DatabaseError("Root item not found".to_string()));
        };

        // Get encryption count from properties
        if let Some(props) = queries::get_properties(conn)? {
            self.encryption_count = props.email.parse().unwrap_or(ENCRYPTION_COUNT_DEFAULT);
        }

        // Try to decrypt
        match crypto::decrypt(&encrypted_name, password, self.encryption_count, None) {
            Ok(_) => {
                self.password = Some(password.to_string());
                self.clear_caches();
                Ok(true)
            }
            Err(_) => Ok(false)
        }
    }

    /// Lock the wallet
    pub fn lock(&mut self) {
        self.password = None;
        self.clear_caches();
    }

    /// Check if the wallet is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.password.is_some()
    }

    /// Close the wallet
    pub fn close(&mut self) {
        self.lock();
        if let Some(mut db) = self.db.take() {
            db.close();
        }
    }

    /// Clear all caches
    pub(crate) fn clear_caches(&mut self) {
        self.items_cache = None;
        self.fields_cache = None;
        self.labels_cache = None;
    }

    /// Get the wallet folder path
    pub fn folder(&self) -> &Path {
        &self.folder
    }

    /// Check password without unlocking
    pub fn check_password(&self, password: &str) -> Result<bool> {
        let db = self.db.as_ref().ok_or(WalletError::DatabaseError(
            "Database not open".to_string()
        ))?;

        let conn = db.connection()?;

        let root_name = queries::get_root_item_raw(conn)?;

        let Some(encrypted_name) = root_name else {
            return Err(WalletError::DatabaseError("Root item not found".to_string()));
        };

        match crypto::decrypt(&encrypted_name, password, self.encryption_count, None) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false)
        }
    }

    /// Get database properties
    pub fn get_properties(&self) -> Result<IWProperties> {
        let db = self.db.as_ref().ok_or(WalletError::DatabaseError(
            "Database not open".to_string()
        ))?;

        let conn = db.connection()?;

        let raw_props = queries::get_properties(conn)?
            .ok_or_else(|| WalletError::DatabaseError("Properties not found".to_string()))?;

        Ok(IWProperties {
            database_id: raw_props.database_id,
            lang: raw_props.lang,
            version: raw_props.version,
            encryption_count: raw_props.email.parse().unwrap_or(ENCRYPTION_COUNT_DEFAULT),
            sync_timestamp: raw_props.sync_timestamp.as_ref().and_then(|s| parse_timestamp(s)),
            update_timestamp: raw_props.update_timestamp.as_ref().and_then(|s| parse_timestamp(s)),
        })
    }

    /// Change the wallet password (re-encrypts all data)
    pub fn change_password(&mut self, new_password: &str) -> Result<bool> {
        self.ensure_unlocked()?;

        let old_password = self.password.as_ref().unwrap().clone();

        // Load all data first
        self.load_items_if_needed()?;
        self.load_fields_if_needed()?;

        let items = self.items_cache.take().unwrap();
        let fields = self.fields_cache.take().unwrap();
        let encryption_count = self.encryption_count;

        let db = self.db.as_mut()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?;

        db.begin_transaction()?;

        let result = (|| -> Result<()> {
            let conn = db.connection()?;

            // Re-encrypt all items
            for item in &items {
                let new_encrypted = crypto::encrypt(&item.name, new_password, encryption_count, None)
                    .map_err(|e| WalletError::EncryptionError(e))?;
                queries::update_item_name_only(conn, &item.item_id, &new_encrypted)?;
            }

            // Re-encrypt all fields
            for field in &fields {
                let new_encrypted = crypto::encrypt(&field.value, new_password, encryption_count, None)
                    .map_err(|e| WalletError::EncryptionError(e))?;
                queries::update_field_value_only(conn, &field.item_id, &field.field_id, &new_encrypted)?;
            }

            Ok(())
        })();

        match result {
            Ok(()) => {
                db.commit_transaction()?;
                self.password = Some(new_password.to_string());
                self.clear_caches();
                Ok(true)
            }
            Err(e) => {
                db.rollback_transaction()?;
                self.password = Some(old_password);
                self.items_cache = Some(items);
                self.fields_cache = Some(fields);
                Err(e)
            }
        }
    }

    /// Ensure wallet is unlocked
    pub(crate) fn ensure_unlocked(&self) -> Result<()> {
        if self.password.is_none() {
            return Err(WalletError::Locked);
        }
        Ok(())
    }

    /// Get the database path
    pub fn database_path(&self) -> PathBuf {
        self.folder.join(DATABASE_FILENAME)
    }

    /// Get a reference to the database for backup operations
    pub fn database(&self) -> Result<&Database> {
        self.db.as_ref().ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::DB_VERSION;

    pub fn create_test_wallet() -> (Wallet, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let wallet = Wallet::create(temp_dir.path(), "TestPassword123", "en").unwrap();
        (wallet, temp_dir)
    }

    #[test]
    fn test_create_and_unlock() {
        let (mut wallet, _temp) = create_test_wallet();
        wallet.lock();
        assert!(!wallet.is_unlocked());
        assert!(wallet.unlock("TestPassword123").unwrap());
        assert!(wallet.is_unlocked());
    }

    #[test]
    fn test_wrong_password() {
        let (mut wallet, _temp) = create_test_wallet();
        wallet.lock();
        assert!(!wallet.unlock("WrongPassword").unwrap());
        assert!(!wallet.is_unlocked());
    }

    #[test]
    fn test_properties() {
        let (wallet, _temp) = create_test_wallet();
        let props = wallet.get_properties().unwrap();
        assert_eq!(props.lang, "en");
        assert_eq!(props.version, DB_VERSION);
        assert_eq!(props.encryption_count, 0);
        assert_eq!(props.database_id.len(), 32);
    }

    #[test]
    fn test_change_password() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        wallet.add_field(&item_id, "PASS", "secret123", None).unwrap();

        assert!(wallet.change_password("NewPassword456").unwrap());

        wallet.lock();
        assert!(!wallet.unlock("TestPassword123").unwrap());
        assert!(wallet.unlock("NewPassword456").unwrap());

        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields[0].value, "secret123");
    }

    #[test]
    fn test_wallet_folder() {
        let (wallet, temp) = create_test_wallet();
        assert_eq!(wallet.folder(), temp.path());
    }

    #[test]
    fn test_database_path() {
        let (wallet, temp) = create_test_wallet();
        assert_eq!(wallet.database_path(), temp.path().join("nswallet.dat"));
    }

    #[test]
    fn test_open_nonexistent() {
        let result = Wallet::open(std::path::Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn test_check_password() {
        let (mut wallet, _temp) = create_test_wallet();
        wallet.lock();
        assert!(wallet.check_password("TestPassword123").unwrap());
        assert!(!wallet.check_password("WrongPassword").unwrap());
    }
}
