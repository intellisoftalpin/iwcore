//! Main Wallet API
//!
//! This module provides the primary interface for interacting with
//! an IntelliWallet database.

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use crate::error::{WalletError, Result};
use crate::database::{Database, IWItem, IWField, IWLabel, IWProperties};
use crate::database::queries::{self, parse_timestamp, CryptoRecord};
use crate::database::migrations;
use crate::crypto;
use crate::crypto::dek::DEK_LEN;
use crate::utils::generate_database_id;
use crate::{DATABASE_FILENAME, ROOT_ID, ROOT_PARENT_ID, DB_VERSION, ENCRYPTION_COUNT_DEFAULT};
use rand::Rng;
use zeroize::Zeroizing;

/// Filename of the pre-migration snapshot kept (permanently) next to the
/// database when a v5 vault is upgraded to v6. See `iwcore-hardening.md`.
pub const PRE_V6_BACKUP_FILENAME: &str = "nswallet.pre-v6.bak";

/// Scheme id stored in the crypto record (1 = XChaCha20-Poly1305 / Argon2id).
const CRYPTO_SCHEME_V6: i64 = 1;

/// KDF salt length in bytes.
const KDF_SALT_LEN: usize = 16;

/// In-memory state of an unlocked wallet. Holds the per-vault Data Encryption
/// Key; zeroized on drop / lock.
pub(crate) struct Unlocked {
    dek: Zeroizing<[u8; DEK_LEN]>,
}

/// Draw `n` cryptographically random bytes from the OS CSPRNG.
fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::rng().fill_bytes(&mut v);
    v
}

/// Turn the legacy `email` column (which actually stores the AES
/// re-encryption iteration count) into the count used for legacy decrypt.
///
/// Mirrors the original C# `Convert.ToInt32(nswProps.email)`, which returns
/// `0` for a `null` value. Many real legacy databases have this column as SQL
/// `NULL` — it was added to the schema without a backfill/default (see
/// `CHAR(200)` in `database::schema`, a column-width declaration, not a
/// default value) — so a missing/empty/unparseable count MUST fall back to
/// `0`, exactly like the old app did, not to `ENCRYPTION_COUNT_DEFAULT`
/// (200): that constant is only a generic placeholder for
/// `IWProperties::default()` and was never a valid fallback here. Using it
/// as the fallback silently derived the wrong AES key for every vault with a
/// NULL `email` column, making a correct password look "wrong" on import.
fn legacy_encryption_count(email: Option<&str>) -> u32 {
    email.and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Main wallet interface
pub struct Wallet {
    /// Path to the wallet folder
    pub(crate) folder: PathBuf,
    /// Database connection
    pub(crate) db: Option<Database>,
    /// Unlocked state (holds the per-vault DEK) when unlocked, else None.
    pub(crate) unlocked: Option<Unlocked>,
    /// Legacy encryption iteration count. Used only to read pre-v6 data during
    /// the one-time migration; ignored once the vault is v6.
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
    /// The folder should contain a `nswallet.dat` file. Runs any pending
    /// schema migrations as part of opening so that databases coming from
    /// older app versions (whether on disk from an older install or freshly
    /// imported via restore) get their schema and version field brought
    /// up to `DB_VERSION` before any other code touches them.
    pub fn open(folder: &Path) -> Result<Self> {
        let db_path = folder.join(DATABASE_FILENAME);

        if !db_path.exists() {
            return Err(WalletError::DatabaseNotFound(
                db_path.to_string_lossy().to_string()
            ));
        }

        let db = Database::open(&db_path)?;

        // Apply pending migrations. Idempotent on already-current DBs.
        // Migrations operate on plaintext schema and label rows, so they
        // don't need the master password — safe to run pre-unlock.
        {
            let conn = db.connection()?;
            let current = migrations::get_database_version(conn)?;
            migrations::upgrade_database(conn, &current)?;
        }

        Ok(Self {
            folder: folder.to_path_buf(),
            db: Some(db),
            unlocked: None,
            encryption_count: ENCRYPTION_COUNT_DEFAULT,
            items_cache: None,
            fields_cache: None,
            labels_cache: None,
        })
    }

    /// Create a new wallet in the specified folder. New wallets are born at the
    /// current (v6) scheme; legacy crypto is never written.
    pub fn create(folder: &Path, password: &str, lang: &str) -> Result<Self> {
        std::fs::create_dir_all(folder)?;

        let db_path = folder.join(DATABASE_FILENAME);
        let db = Database::create(&db_path)?;

        let mut wallet = Self {
            folder: folder.to_path_buf(),
            db: Some(db),
            unlocked: None,
            encryption_count: 0,
            items_cache: None,
            fields_cache: None,
            labels_cache: None,
        };

        wallet.init_new_database(password, lang)?;

        Ok(wallet)
    }

    /// Initialize a new (v6) database: properties, crypto record, root item,
    /// system labels.
    fn init_new_database(&mut self, password: &str, lang: &str) -> Result<()> {
        // Generate fresh key material and wrap the DEK under the password.
        let dek = crypto::dek::generate_dek();
        let params = crypto::kdf::KdfParams::current();
        let salt = random_bytes(KDF_SALT_LEN);
        let kek = crypto::kdf::derive_kek(password.as_bytes(), &salt, params)
            .map_err(WalletError::EncryptionError)?;
        let dek_wrapped = crypto::dek::wrap_dek(&kek, &dek)
            .map_err(WalletError::EncryptionError)?;

        // Hold the DEK so the root item can be encrypted under it.
        self.unlocked = Some(Unlocked { dek: Zeroizing::new(dek) });

        let db_id = generate_database_id();
        let root_data = crate::utils::generate_id(32);
        let encrypted_root = self.enc_value(&root_data)?;

        {
            let conn = self.db.as_ref()
                .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
                .connection()?;

            queries::set_properties(conn, &db_id, lang, DB_VERSION, 0)?;
            queries::set_crypto_record(conn, &CryptoRecord {
                scheme: CRYPTO_SCHEME_V6,
                kdf: "argon2id".to_string(),
                m_cost_kib: params.m_cost_kib,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
                salt,
                dek_wrapped,
            })?;
            queries::create_item(conn, ROOT_ID, ROOT_PARENT_ID, &encrypted_root, "", true)?;
        }

        self.add_system_labels()?;

        Ok(())
    }

    /// Unlock the wallet with a password.
    ///
    /// For a v6 vault: derive the KEK with the stored Argon2id params and unwrap
    /// the DEK (the AEAD tag is the password verifier). For a not-yet-migrated
    /// v5 vault: verify the password against the legacy root item, then perform
    /// the one-time v5->v6 migration before returning.
    pub fn unlock(&mut self, password: &str) -> Result<bool> {
        // Read all metadata up front into owned values so the immutable
        // connection borrow is fully released before any mutation/migration.
        let (props, crypto_rec, root_blob) = {
            let conn = self.db.as_ref()
                .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
                .connection()?;
            (
                queries::get_properties(conn)?,
                queries::get_crypto_record(conn)?,
                queries::get_root_item_raw(conn)?,
            )
        };

        self.encryption_count = legacy_encryption_count(props.as_ref().and_then(|p| p.email.as_deref()));

        if let Some(rec) = crypto_rec {
            // v6 vault: derive KEK from the stored params and unwrap the DEK.
            match self.unwrap_with_password(&rec, password) {
                Some(dek) => {
                    self.unlocked = Some(Unlocked { dek: Zeroizing::new(dek) });
                    self.clear_caches();
                    self.add_system_labels()?;
                    Ok(true)
                }
                None => Ok(false),
            }
        } else {
            // Legacy v5 vault: verify against the root item, then migrate.
            let Some(encrypted_name) = root_blob else {
                return Err(WalletError::DatabaseError("Root item not found".to_string()));
            };
            if crypto::legacy::decrypt(&encrypted_name, password, self.encryption_count, None).is_err() {
                return Ok(false);
            }
            // Password verified. Perform the one-time migration (sets the DEK).
            self.migrate_v5_to_v6(password)?;
            self.clear_caches();
            self.add_system_labels()?;
            Ok(true)
        }
    }

    /// Derive the KEK from `password` using the record's stored params and try
    /// to unwrap the DEK. Returns the DEK on success, `None` on wrong password.
    fn unwrap_with_password(&self, rec: &CryptoRecord, password: &str) -> Option<[u8; DEK_LEN]> {
        let params = crypto::kdf::KdfParams {
            m_cost_kib: rec.m_cost_kib,
            t_cost: rec.t_cost,
            p_cost: rec.p_cost,
        };
        let kek = crypto::kdf::derive_kek(password.as_bytes(), &rec.salt, params).ok()?;
        crypto::dek::unwrap_dek(&kek, &rec.dek_wrapped).ok()
    }

    /// Lock the wallet (zeroizes the in-memory DEK).
    pub fn lock(&mut self) {
        self.unlocked = None;
        self.clear_caches();
    }

    /// Check if the wallet is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    /// Borrow the in-memory DEK, or error if locked.
    fn dek(&self) -> Result<&[u8; DEK_LEN]> {
        self.unlocked.as_ref().map(|u| &*u.dek).ok_or(WalletError::Locked)
    }

    /// AEAD-encrypt a plaintext value (item name / field value) under the DEK.
    pub(crate) fn enc_value(&self, plaintext: &str) -> Result<Vec<u8>> {
        crypto::aead::seal(self.dek()?, plaintext.as_bytes())
            .map_err(WalletError::EncryptionError)
    }

    /// AEAD-decrypt a stored v6 blob under the DEK.
    pub(crate) fn dec_value(&self, blob: &[u8]) -> Result<String> {
        let pt = crypto::aead::open(self.dek()?, blob).map_err(WalletError::DecryptionError)?;
        String::from_utf8(pt)
            .map_err(|e| WalletError::DecryptionError(format!("invalid UTF-8: {e}")))
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

    /// Check a password without unlocking or migrating. Works on both v6 vaults
    /// (verify via DEK unwrap) and not-yet-migrated v5 vaults (verify via the
    /// legacy root item). Read-only: never mutates the database.
    pub fn check_password(&self, password: &str) -> Result<bool> {
        let (props, crypto_rec, root_blob) = {
            let conn = self.db.as_ref()
                .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
                .connection()?;
            (
                queries::get_properties(conn)?,
                queries::get_crypto_record(conn)?,
                queries::get_root_item_raw(conn)?,
            )
        };

        if let Some(rec) = crypto_rec {
            Ok(self.unwrap_with_password(&rec, password).is_some())
        } else {
            let Some(encrypted_name) = root_blob else {
                return Err(WalletError::DatabaseError("Root item not found".to_string()));
            };
            let encryption_count = legacy_encryption_count(props.as_ref().and_then(|p| p.email.as_deref()));
            Ok(crypto::legacy::decrypt(&encrypted_name, password, encryption_count, None).is_ok())
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
            encryption_count: legacy_encryption_count(raw_props.email.as_deref()),
            sync_timestamp: raw_props.sync_timestamp.as_ref().and_then(|s| parse_timestamp(s)),
            update_timestamp: raw_props.update_timestamp.as_ref().and_then(|s| parse_timestamp(s)),
        })
    }

    /// Change the wallet password.
    ///
    /// Under the v6 scheme this only re-wraps the DEK: a fresh salt + KEK are
    /// derived from `new_password` and the same DEK is re-wrapped. The encrypted
    /// item names and field values are NOT touched (they are under the DEK, not
    /// the password), so this is fast and leaves all data blobs byte-identical.
    pub fn change_password(&mut self, new_password: &str) -> Result<bool> {
        self.ensure_unlocked()?;

        let dek = *self.dek()?;
        let params = crypto::kdf::KdfParams::current();
        let salt = random_bytes(KDF_SALT_LEN);
        let kek = crypto::kdf::derive_kek(new_password.as_bytes(), &salt, params)
            .map_err(WalletError::EncryptionError)?;
        let dek_wrapped = crypto::dek::wrap_dek(&kek, &dek)
            .map_err(WalletError::EncryptionError)?;

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;
        queries::set_crypto_record(conn, &CryptoRecord {
            scheme: CRYPTO_SCHEME_V6,
            kdf: "argon2id".to_string(),
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            salt,
            dek_wrapped,
        })?;

        Ok(true)
    }

    /// Ensure wallet is unlocked
    pub(crate) fn ensure_unlocked(&self) -> Result<()> {
        if self.unlocked.is_none() {
            return Err(WalletError::Locked);
        }
        Ok(())
    }

    /// Write a consistent pre-migration snapshot of the database to
    /// `<folder>/nswallet.pre-v6.bak` using SQLite `VACUUM INTO`. Kept
    /// permanently as a recovery anchor. Overwrites any stale snapshot (safe:
    /// only called while the live DB is still an intact v5).
    fn create_pre_v6_backup(&self) -> Result<()> {
        let dst = self.folder.join(PRE_V6_BACKUP_FILENAME);
        if dst.exists() {
            std::fs::remove_file(&dst).map_err(|e| {
                WalletError::BackupError(format!("Failed to remove stale pre-v6 backup: {e}"))
            })?;
        }
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;
        conn.execute("VACUUM INTO ?", [dst.to_string_lossy().to_string()])
            .map_err(|e| WalletError::BackupError(format!("Pre-v6 snapshot (VACUUM INTO) failed: {e}")))?;
        Ok(())
    }

    /// One-time v5->v6 crypto migration. Precondition: the password has already
    /// been verified against the legacy root item.
    ///
    /// Sequence (see `iwcore-hardening.md`): checkpoint, write a kept pre-v6
    /// snapshot, then in a single transaction generate fresh key material,
    /// re-encrypt every item name and field value (active, deleted, and root)
    /// from the legacy scheme to the DEK AEAD scheme, write the crypto record,
    /// and bump the version to 6. Any undecryptable blob aborts the whole
    /// migration (rollback to intact v5). On success the DEK is held in memory.
    fn migrate_v5_to_v6(&mut self, password: &str) -> Result<()> {
        let enc_count = self.encryption_count;

        // 1. Flush WAL so the live file is self-contained, then snapshot it.
        self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .checkpoint()?;
        self.create_pre_v6_backup()?;

        // 2. Fresh key material; wrap the DEK under the password.
        let dek = crypto::dek::generate_dek();
        let params = crypto::kdf::KdfParams::current();
        let salt = random_bytes(KDF_SALT_LEN);
        let kek = crypto::kdf::derive_kek(password.as_bytes(), &salt, params)
            .map_err(WalletError::EncryptionError)?;
        let dek_wrapped = crypto::dek::wrap_dek(&kek, &dek)
            .map_err(WalletError::EncryptionError)?;

        // 3. Read every blob up front (owned), releasing the conn borrow.
        let (item_blobs, field_blobs) = {
            let conn = self.db.as_ref()
                .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
                .connection()?;
            (queries::get_all_item_blobs(conn)?, queries::get_all_field_blobs(conn)?)
        };

        // 4. Re-encrypt everything inside a single transaction.
        let db = self.db.as_mut()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?;
        db.begin_transaction()?;

        let result = (|| -> Result<()> {
            let conn = db.connection()?;
            queries::ensure_crypto_table(conn)?;

            for (item_id, blob, deleted) in &item_blobs {
                match crypto::legacy::decrypt(blob, password, enc_count, None) {
                    Ok(plaintext) => {
                        let new_blob = crypto::aead::seal(&dek, plaintext.as_bytes())
                            .map_err(WalletError::EncryptionError)?;
                        queries::update_item_name_only(conn, item_id, &new_blob)?;
                    }
                    Err(e) => {
                        // An undecryptable ACTIVE record is real corruption: abort
                        // and roll back to intact v5. An undecryptable SOFT-DELETED
                        // record is pre-existing dead history that is unreadable
                        // under the master password (the app never surfaced it), so
                        // there is nothing to preserve: purge the row.
                        if *deleted {
                            queries::hard_delete_item(conn, item_id)?;
                        } else {
                            return Err(WalletError::DecryptionError(
                                format!("active item {item_id}: {e}"),
                            ));
                        }
                    }
                }
            }

            for (item_id, field_id, blob, deleted) in &field_blobs {
                match crypto::legacy::decrypt(blob, password, enc_count, None) {
                    Ok(plaintext) => {
                        let new_blob = crypto::aead::seal(&dek, plaintext.as_bytes())
                            .map_err(WalletError::EncryptionError)?;
                        queries::update_field_value_only(conn, item_id, field_id, &new_blob)?;
                    }
                    Err(e) => {
                        if *deleted {
                            queries::hard_delete_field(conn, item_id, field_id)?;
                        } else {
                            return Err(WalletError::DecryptionError(
                                format!("active field {item_id}/{field_id}: {e}"),
                            ));
                        }
                    }
                }
            }

            queries::set_crypto_record(conn, &CryptoRecord {
                scheme: CRYPTO_SCHEME_V6,
                kdf: "argon2id".to_string(),
                m_cost_kib: params.m_cost_kib,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
                salt: salt.clone(),
                dek_wrapped: dek_wrapped.clone(),
            })?;
            queries::set_db_version_no_checkpoint(conn, DB_VERSION)?;
            Ok(())
        })();

        match result {
            Ok(()) => db.commit_transaction()?,
            Err(e) => {
                db.rollback_transaction()?;
                return Err(e);
            }
        }

        // 5. Best-effort checkpoint so the on-disk file fully reflects the
        // migrated state. The commit above is already durable (in the WAL), so a
        // checkpoint failure must NOT fail the migration: SQLite will checkpoint
        // automatically later. Making this fatal would surface a spurious error
        // on an otherwise-successful, already-committed v6 migration.
        let _ = self.db.as_ref().unwrap().checkpoint();

        // 6. Hold the DEK: the vault is now unlocked under v6.
        self.unlocked = Some(Unlocked { dek: Zeroizing::new(dek) });
        Ok(())
    }

    /// Get the database path
    pub fn database_path(&self) -> PathBuf {
        self.folder.join(DATABASE_FILENAME)
    }

    /// Permanently purge all soft-deleted records and orphaned fields.
    /// Returns (purged_items_count, purged_fields_count).
    pub fn compact(&mut self) -> Result<(u32, u32)> {
        self.ensure_unlocked()?;

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        let result = queries::purge_deleted(conn)?;

        self.clear_caches();
        Ok(result)
    }

    /// Get database statistics (counts of items, fields, labels, deleted records, file size)
    pub fn get_database_stats(&self) -> Result<queries::DatabaseStats> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        let mut stats = queries::get_database_stats(conn)?;

        // Set file size from filesystem metadata
        let db_path = self.database_path();
        if let Ok(metadata) = std::fs::metadata(&db_path) {
            stats.file_size_bytes = metadata.len();
        }

        Ok(stats)
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
    fn test_open_migrates_old_database() {
        // Simulate the "imported v4 backup" scenario: drop an old-version
        // database file into a folder, then call Wallet::open() and confirm
        // the schema-migration version is bumped without ever calling unlock().
        // open() only runs the password-free schema migrations (ceiling = 5);
        // the crypto bump to v6 happens later in unlock().
        use rusqlite::Connection;
        let temp_dir = TempDir::new().unwrap();
        let wallet = Wallet::create(temp_dir.path(), "TestPassword123", "en").unwrap();
        let folder = temp_dir.path().to_path_buf();
        drop(wallet);

        // Force the version field back to "4" to simulate an older DB.
        let db_path = folder.join(crate::DATABASE_FILENAME);
        let conn = Connection::open(&db_path).unwrap();
        conn.execute("UPDATE nswallet_properties SET version = ?", ["4"]).unwrap();
        drop(conn);

        // Re-open the wallet — schema migrations should run and bump to 5.
        let _ = Wallet::open(&folder).unwrap();

        let conn = Connection::open(&db_path).unwrap();
        let v: String = conn
            .query_row(
                "SELECT version FROM nswallet_properties LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v, migrations::CURRENT_VERSION); // "5": schema-migrated, not yet crypto-migrated

        // SEED label (added by the v4→v5 migration) must now be present.
        let seed_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM nswallet_labels WHERE field_type = 'SEED'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(seed_count, 1);
    }

    #[test]
    fn test_open_no_op_on_current_database() {
        // Open a fresh DB twice; the second open shouldn't change anything
        // version-wise.
        let temp_dir = TempDir::new().unwrap();
        let wallet = Wallet::create(temp_dir.path(), "TestPassword123", "en").unwrap();
        let folder = temp_dir.path().to_path_buf();
        drop(wallet);

        // Re-open — should be a no-op for migration purposes.
        let _ = Wallet::open(&folder).unwrap();

        use rusqlite::Connection;
        let db_path = folder.join(crate::DATABASE_FILENAME);
        let conn = Connection::open(&db_path).unwrap();
        let v: String = conn
            .query_row(
                "SELECT version FROM nswallet_properties LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v, DB_VERSION);
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

    /// Fabricates a genuine legacy (v5) vault encrypted with the given
    /// encryption_count, so the legacy `check_password` path can be exercised.
    /// Creates a fresh v6 wallet, recovers the root plaintext via its live DEK,
    /// re-encrypts the root with the legacy scheme, drops the crypto record, and
    /// marks the DB as version 5.
    fn create_wallet_with_encryption_count(encryption_count: u32) -> (TempDir, std::path::PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();
        let password = "TestPassword123";

        let wallet = Wallet::create(&path, password, "en").unwrap();

        let conn = wallet.db.as_ref().unwrap().connection().unwrap();

        // Recover the root plaintext from its v6 blob using the live DEK.
        let root_raw = queries::get_root_item_raw(conn).unwrap().unwrap();
        let plaintext = wallet.dec_value(&root_raw).unwrap();

        // Re-encrypt root with the legacy scheme at the target encryption_count.
        let legacy_root = crypto::legacy::encrypt(&plaintext, password, encryption_count, None).unwrap();
        conn.execute(
            "UPDATE nswallet_items SET name = ? WHERE item_id = '__ROOT__'",
            rusqlite::params![legacy_root],
        ).unwrap();

        // Turn it into a real v5 vault: no crypto record, version 5, stored count.
        conn.execute("DROP TABLE nswallet_crypto", []).unwrap();
        conn.execute(
            "UPDATE nswallet_properties SET version = '5', email = ?",
            rusqlite::params![encryption_count.to_string()],
        ).unwrap();

        drop(wallet);
        (temp_dir, path)
    }

    #[test]
    fn test_check_password_after_reopen_enc0() {
        let (_temp, path) = create_wallet_with_encryption_count(0);
        let wallet = Wallet::open(&path).unwrap();
        assert!(wallet.check_password("TestPassword123").unwrap());
        assert!(!wallet.check_password("WrongPassword").unwrap());
    }

    #[test]
    fn test_check_password_after_reopen_enc33() {
        let (_temp, path) = create_wallet_with_encryption_count(33);
        let wallet = Wallet::open(&path).unwrap();
        assert!(wallet.check_password("TestPassword123").unwrap());
        assert!(!wallet.check_password("WrongPassword").unwrap());
    }

    #[test]
    fn test_check_password_after_reopen_enc200() {
        let (_temp, path) = create_wallet_with_encryption_count(200);
        let wallet = Wallet::open(&path).unwrap();
        assert!(wallet.check_password("TestPassword123").unwrap());
        assert!(!wallet.check_password("WrongPassword").unwrap());
    }

    #[test]
    fn test_check_password_after_reopen_enc500() {
        let (_temp, path) = create_wallet_with_encryption_count(500);
        let wallet = Wallet::open(&path).unwrap();
        assert!(wallet.check_password("TestPassword123").unwrap());
        assert!(!wallet.check_password("WrongPassword").unwrap());
    }

    /// Same fabrication as [`create_wallet_with_encryption_count`], but the
    /// `email` column is left as SQL `NULL` instead of a numeric string -
    /// simulating a real legacy database whose column was never backfilled.
    /// The root is encrypted with `encryption_count = 0`, matching what the
    /// original C# app actually used in this situation (`Convert.ToInt32(null)
    /// == 0`).
    fn create_wallet_with_null_email() -> (TempDir, std::path::PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();
        let password = "TestPassword123";

        let wallet = Wallet::create(&path, password, "en").unwrap();

        let conn = wallet.db.as_ref().unwrap().connection().unwrap();

        let root_raw = queries::get_root_item_raw(conn).unwrap().unwrap();
        let plaintext = wallet.dec_value(&root_raw).unwrap();

        // Legacy scheme, encryption_count = 0 - what the C# app used when its
        // own `EncryptionCount` property read back as NULL.
        let legacy_root = crypto::legacy::encrypt(&plaintext, password, 0, None).unwrap();
        conn.execute(
            "UPDATE nswallet_items SET name = ? WHERE item_id = '__ROOT__'",
            rusqlite::params![legacy_root],
        ).unwrap();

        conn.execute("DROP TABLE nswallet_crypto", []).unwrap();
        conn.execute(
            "UPDATE nswallet_properties SET version = '5', email = NULL",
            [],
        ).unwrap();

        drop(wallet);
        (temp_dir, path)
    }

    /// Regression test for the reported customer bug: a genuine legacy vault
    /// whose `email` column is SQL `NULL` (not `"0"`). Before the fix,
    /// `get_properties()` silently mapped the NULL-decode error to
    /// `Ok(None)`, so `encryption_count` fell back to
    /// `ENCRYPTION_COUNT_DEFAULT` (200) instead of the `0` the C# app
    /// actually used - deriving the wrong AES key and reporting the correct
    /// password as wrong. `check_password` must succeed with the real
    /// password and still reject a wrong one.
    #[test]
    fn test_check_password_after_reopen_null_email() {
        let (_temp, path) = create_wallet_with_null_email();
        let wallet = Wallet::open(&path).unwrap();
        assert!(wallet.check_password("TestPassword123").unwrap());
        assert!(!wallet.check_password("WrongPassword").unwrap());
    }

    /// Same NULL-`email` scenario, but through the real end-user path:
    /// `unlock()`, which verifies the password against the legacy root item
    /// and then performs the one-time v5->v6 migration. Confirms a wrong
    /// password is rejected without mutating anything, and the correct
    /// password unlocks *and* the vault ends up on the v6 crypto scheme with
    /// the root item still decryptable afterwards.
    #[test]
    fn test_unlock_and_migrate_with_null_email() {
        let (_temp, path) = create_wallet_with_null_email();

        // Wrong password: rejected, vault stays on the legacy scheme.
        let mut wallet = Wallet::open(&path).unwrap();
        assert!(!wallet.unlock("WrongPassword").unwrap());
        assert!(!wallet.is_unlocked());

        // Correct password: unlocks and migrates to v6.
        assert!(wallet.unlock("TestPassword123").unwrap());
        assert!(wallet.is_unlocked());

        let props = wallet.get_properties().unwrap();
        assert_eq!(props.version, DB_VERSION);

        // Root item must still be readable post-migration.
        let conn = wallet.db.as_ref().unwrap().connection().unwrap();
        assert!(queries::get_crypto_record(conn).unwrap().is_some());
    }

    #[test]
    fn test_compact_items() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("To Purge", "document", false, None).unwrap();
        wallet.delete_item(&item_id).unwrap();

        wallet.compact().unwrap();

        let deleted = wallet.get_deleted_items().unwrap();
        assert!(deleted.is_empty());
    }

    #[test]
    fn test_compact_fields() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "MAIL", "purge@test.com", None).unwrap();
        wallet.delete_field(&item_id, &field_id).unwrap();

        wallet.compact().unwrap();

        let deleted = wallet.get_deleted_fields().unwrap();
        assert!(deleted.is_empty());
    }

    #[test]
    fn test_compact_cascaded_fields() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        wallet.add_field(&item_id, "MAIL", "orphan@test.com", None).unwrap();
        wallet.add_field(&item_id, "PASS", "secret", None).unwrap();

        // Delete item (fields are cascade soft-deleted)
        wallet.delete_item(&item_id).unwrap();

        wallet.compact().unwrap();

        // Cascade-deleted fields should also be purged
        let deleted_fields = wallet.get_deleted_fields().unwrap();
        assert!(deleted_fields.is_empty());
        let deleted_items = wallet.get_deleted_items().unwrap();
        assert!(deleted_items.is_empty());
    }

    #[test]
    fn test_compact_returns_counts() {
        let (mut wallet, _temp) = create_test_wallet();
        let item1_id = wallet.add_item("Item 1", "document", false, None).unwrap();
        let item2_id = wallet.add_item("Item 2", "document", false, None).unwrap();
        let _field_id = wallet.add_field(&item1_id, "MAIL", "test@test.com", None).unwrap();

        // delete_item cascades to fields now, so field is already deleted=1
        wallet.delete_item(&item1_id).unwrap();
        wallet.delete_item(&item2_id).unwrap();

        let (items_count, fields_count) = wallet.compact().unwrap();
        assert_eq!(items_count, 2);
        assert_eq!(fields_count, 1); // cascade-deleted field
    }

    #[test]
    fn test_compact_empty() {
        let (mut wallet, _temp) = create_test_wallet();
        let (items, fields) = wallet.compact().unwrap();
        assert_eq!(items, 0);
        assert_eq!(fields, 0);
    }

    #[test]
    fn test_compact_preserves_active_records() {
        let (mut wallet, _temp) = create_test_wallet();
        let item1 = wallet.add_item("Keep This", "document", false, None).unwrap();
        wallet.add_field(&item1, "MAIL", "keep@test.com", None).unwrap();
        let item2 = wallet.add_item("Delete This", "document", false, None).unwrap();
        wallet.add_field(&item2, "PASS", "gone", None).unwrap();

        wallet.delete_item(&item2).unwrap();
        wallet.compact().unwrap();

        // Active records untouched
        let item = wallet.get_item(&item1).unwrap().unwrap();
        assert_eq!(item.name, "Keep This");
        let fields = wallet.get_fields_by_item(&item1).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value, "keep@test.com");
    }

    #[test]
    fn test_compact_double_call_idempotent() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Delete Me", "document", false, None).unwrap();
        wallet.delete_item(&item_id).unwrap();

        let (i1, _f1) = wallet.compact().unwrap();
        assert_eq!(i1, 1);

        // Second compact: nothing left to purge
        let (i2, f2) = wallet.compact().unwrap();
        assert_eq!(i2, 0);
        assert_eq!(f2, 0);
    }

    #[test]
    fn test_compact_after_cascade_delete() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder = wallet.add_item("Folder", "folder", true, None).unwrap();
        let child1 = wallet.add_item("Child 1", "document", false, Some(&folder)).unwrap();
        let child2 = wallet.add_item("Child 2", "document", false, Some(&folder)).unwrap();
        wallet.add_field(&child1, "MAIL", "c1@test.com", None).unwrap();
        wallet.add_field(&child2, "PASS", "secret", None).unwrap();

        wallet.delete_item(&folder).unwrap();

        let (items_count, fields_count) = wallet.compact().unwrap();
        assert_eq!(items_count, 3); // folder + 2 children
        assert_eq!(fields_count, 2); // cascade-deleted fields

        // Everything gone
        assert!(wallet.get_deleted_items().unwrap().is_empty());
        assert!(wallet.get_deleted_fields().unwrap().is_empty());
    }

    #[test]
    fn test_compact_mixed_deleted_and_cascaded_fields() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let f1 = wallet.add_field(&item_id, "MAIL", "test@test.com", None).unwrap();
        wallet.add_field(&item_id, "PASS", "secret", None).unwrap();

        // Explicitly delete one field, then delete the item (cascade-deletes the other)
        wallet.delete_field(&item_id, &f1).unwrap();
        wallet.delete_item(&item_id).unwrap();

        let (items_count, fields_count) = wallet.compact().unwrap();
        assert_eq!(items_count, 1);
        // Both fields purged: f1 was explicitly soft-deleted, PASS was cascade-deleted
        assert_eq!(fields_count, 2);
    }

    #[test]
    fn test_compact_with_active_and_deleted_fields_same_item() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let f_del = wallet.add_field(&item_id, "MAIL", "delete@me.com", None).unwrap();
        wallet.add_field(&item_id, "PASS", "keep_me", None).unwrap();

        wallet.delete_field(&item_id, &f_del).unwrap();
        wallet.compact().unwrap();

        // Deleted field gone
        assert!(wallet.get_deleted_fields().unwrap().is_empty());
        // Active field still there
        let active = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].value, "keep_me");
    }

    #[test]
    fn test_database_stats() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder = wallet.add_item("Folder", "folder", true, None).unwrap();
        let item1 = wallet.add_item("Item 1", "document", false, None).unwrap();
        let item2 = wallet.add_item("Item 2", "document", false, Some(&folder)).unwrap();
        wallet.add_field(&item1, "MAIL", "a@a.com", None).unwrap();
        wallet.add_field(&item1, "PASS", "secret", None).unwrap();
        wallet.add_field(&item2, "NOTE", "note", None).unwrap();

        // Delete one item (cascades to its fields)
        wallet.delete_item(&item2).unwrap();

        let stats = wallet.get_database_stats().unwrap();
        assert_eq!(stats.total_items, 1);    // item1 (item2 deleted)
        assert_eq!(stats.total_folders, 1);  // folder
        assert_eq!(stats.total_fields, 2);   // item1's 2 fields (item2's field cascade-deleted)
        assert_eq!(stats.deleted_items, 1);  // item2
        assert_eq!(stats.deleted_fields, 1); // item2's cascade-deleted field
        assert!(stats.total_labels >= 19);   // system labels
        assert!(stats.file_size_bytes > 0);
    }

    #[test]
    fn test_change_password_reencrypts_deleted_items() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Deleted Item", "document", false, None).unwrap();
        wallet.delete_item(&item_id).unwrap();

        // Change password
        assert!(wallet.change_password("NewPassword456").unwrap());

        // Deleted item should still be accessible after password change
        let deleted = wallet.get_deleted_items().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].name, "Deleted Item");

        // Verify new password works after reopen
        wallet.lock();
        assert!(wallet.unlock("NewPassword456").unwrap());
        let deleted2 = wallet.get_deleted_items().unwrap();
        assert_eq!(deleted2.len(), 1);
        assert_eq!(deleted2[0].name, "Deleted Item");
    }

    #[test]
    fn test_change_password_reencrypts_deleted_fields() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "PASS", "my_secret", None).unwrap();
        wallet.delete_field(&item_id, &field_id).unwrap();

        // Change password
        assert!(wallet.change_password("NewPassword456").unwrap());

        // Deleted field should still be accessible after password change
        let deleted = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].value, "my_secret");

        // Verify new password works after reopen
        wallet.lock();
        assert!(wallet.unlock("NewPassword456").unwrap());
        let deleted2 = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted2.len(), 1);
        assert_eq!(deleted2[0].value, "my_secret");
    }

    #[test]
    fn test_change_password_reencrypts_cascade_deleted_fields() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        wallet.add_field(&item_id, "MAIL", "cascade@test.com", None).unwrap();
        wallet.add_field(&item_id, "PASS", "cascade_secret", None).unwrap();

        // Delete item — fields become cascade-deleted (deleted=1)
        wallet.delete_item(&item_id).unwrap();

        // Verify cascade-deleted fields are in deleted list
        let deleted_before = wallet.get_deleted_fields().unwrap();
        let our_fields: Vec<_> = deleted_before.iter().filter(|f| f.item_id == item_id).collect();
        assert_eq!(our_fields.len(), 2);

        // Change password
        assert!(wallet.change_password("NewPassword456").unwrap());

        // Cascade-deleted fields should still be accessible after password change
        let deleted_after = wallet.get_deleted_fields().unwrap();
        let our_fields_after: Vec<_> = deleted_after.iter().filter(|f| f.item_id == item_id).collect();
        assert_eq!(our_fields_after.len(), 2);
        let values: Vec<&str> = our_fields_after.iter().map(|f| f.value.as_str()).collect();
        assert!(values.contains(&"cascade@test.com"));
        assert!(values.contains(&"cascade_secret"));

        // Verify after lock/unlock with new password
        wallet.lock();
        assert!(wallet.unlock("NewPassword456").unwrap());
        let deleted_reopen = wallet.get_deleted_fields().unwrap();
        let our_fields_reopen: Vec<_> = deleted_reopen.iter().filter(|f| f.item_id == item_id).collect();
        assert_eq!(our_fields_reopen.len(), 2);
    }

    #[test]
    fn test_change_password_mixed_active_and_deleted() {
        let (mut wallet, _temp) = create_test_wallet();
        let active_item = wallet.add_item("Active Item", "document", false, None).unwrap();
        wallet.add_field(&active_item, "MAIL", "active@test.com", None).unwrap();

        let del_item = wallet.add_item("Deleted Item", "document", false, None).unwrap();
        let del_field = wallet.add_field(&del_item, "PASS", "deleted_secret", None).unwrap();
        wallet.delete_item(&del_item).unwrap();
        wallet.delete_field(&del_item, &del_field).unwrap();

        assert!(wallet.change_password("NewPassword456").unwrap());

        // Active records still work
        let item = wallet.get_item(&active_item).unwrap().unwrap();
        assert_eq!(item.name, "Active Item");
        let fields = wallet.get_fields_by_item(&active_item).unwrap();
        assert_eq!(fields[0].value, "active@test.com");

        // Deleted records also still work
        let deleted_items = wallet.get_deleted_items().unwrap();
        assert_eq!(deleted_items.len(), 1);
        assert_eq!(deleted_items[0].name, "Deleted Item");

        let deleted_fields = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted_fields.len(), 1);
        assert_eq!(deleted_fields[0].value, "deleted_secret");
    }
}
