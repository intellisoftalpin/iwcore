//! Main Wallet API
//!
//! This module provides the primary interface for interacting with
//! an IntelliWallet database.

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use chrono::Utc;
use crate::error::{WalletError, Result};
use crate::database::{Database, IWItem, IWField, IWLabel, IWProperties, SearchResult, SearchMatchType};
use crate::database::queries::{self, parse_timestamp};
use crate::crypto;
use crate::utils::{generate_item_id, generate_field_id, generate_label_id, generate_database_id};
use crate::{DATABASE_FILENAME, ROOT_ID, ROOT_PARENT_ID, DB_VERSION, ENCRYPTION_COUNT_DEFAULT};

/// Main wallet interface
pub struct Wallet {
    /// Path to the wallet folder
    folder: PathBuf,
    /// Database connection
    db: Option<Database>,
    /// Current password (when unlocked)
    password: Option<String>,
    /// Encryption iteration count
    encryption_count: u32,
    /// Cached items (decrypted)
    items_cache: Option<Vec<IWItem>>,
    /// Cached fields (decrypted)
    fields_cache: Option<Vec<IWField>>,
    /// Cached labels
    labels_cache: Option<HashMap<String, IWLabel>>,
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

    /// Add system labels to the database
    pub fn add_system_labels(&mut self) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        // System labels with their properties
        let system_labels = [
            ("MAIL", "Email", "mail", "mail"),
            ("PASS", "Password", "pass", "pass"),
            ("NOTE", "Note", "text", "note"),
            ("LINK", "Link", "link", "link"),
            ("ACNT", "Account", "text", "account"),
            ("CARD", "Card", "text", "card"),
            ("NAME", "Name", "text", "name"),
            ("PHON", "Phone", "phon", "phone"),
            ("PINC", "PIN", "pass", "pin"),
            ("USER", "Username", "text", "user"),
            ("OLDP", "Old Password", "pass", "oldpass"),
            ("DATE", "Date", "date", "date"),
            ("TIME", "Time", "time", "time"),
            ("EXPD", "Expiry Date", "date", "expiry"),
            ("SNUM", "Serial Number", "text", "serial"),
            ("ADDR", "Address", "text", "address"),
            ("SQUE", "Secret Question", "text", "question"),
            ("SANS", "Secret Answer", "pass", "answer"),
            ("2FAC", "2FA", "pass", "2fa"),
        ];

        for (field_type, name, value_type, icon) in system_labels {
            queries::create_label(conn, field_type, name, value_type, icon, true)?;
        }

        self.labels_cache = None;
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
    fn clear_caches(&mut self) {
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

    /// Get all items (decrypted)
    pub fn get_items(&mut self) -> Result<&[IWItem]> {
        self.ensure_unlocked()?;
        self.load_items_if_needed()?;
        Ok(self.items_cache.as_ref().unwrap())
    }

    /// Get an item by ID
    pub fn get_item(&mut self, item_id: &str) -> Result<Option<IWItem>> {
        let items = self.get_items()?;
        Ok(items.iter().find(|i| i.item_id == item_id).cloned())
    }

    /// Get items by parent ID
    pub fn get_items_by_parent(&mut self, parent_id: &str) -> Result<Vec<IWItem>> {
        let items = self.get_items()?;
        let mut result: Vec<IWItem> = items
            .iter()
            .filter(|i| i.parent_id.as_deref() == Some(parent_id))
            .cloned()
            .collect();

        // Sort: folders first, then by name
        result.sort_by(|a, b| {
            match (a.folder, b.folder) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            }
        });

        Ok(result)
    }

    /// Load items from database if not cached
    fn load_items_if_needed(&mut self) -> Result<()> {
        if self.items_cache.is_some() {
            return Ok(());
        }

        let password = self.password.as_ref()
            .ok_or(WalletError::Locked)?
            .clone();

        let db = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?;

        let conn = db.connection()?;
        let raw_items = queries::get_all_items_raw(conn)?;

        let mut items = Vec::with_capacity(raw_items.len());

        for raw in raw_items {
            let name = crypto::decrypt(&raw.name_encrypted, &password, self.encryption_count, None)
                .map_err(|e| WalletError::DecryptionError(e))?;

            items.push(IWItem {
                item_id: raw.item_id,
                parent_id: raw.parent_id,
                name,
                icon: raw.icon,
                folder: raw.folder,
                create_timestamp: raw.create_timestamp
                    .as_ref()
                    .and_then(|s| parse_timestamp(s))
                    .unwrap_or_else(Utc::now),
                change_timestamp: raw.change_timestamp
                    .as_ref()
                    .and_then(|s| parse_timestamp(s))
                    .unwrap_or_else(Utc::now),
                deleted: raw.deleted,
            });
        }

        self.items_cache = Some(items);
        Ok(())
    }

    /// Create a new item
    pub fn add_item(&mut self, name: &str, icon: &str, folder: bool, parent_id: Option<&str>) -> Result<String> {
        self.ensure_unlocked()?;

        let password = self.password.as_ref().unwrap().clone();
        let item_id = generate_item_id();
        let parent = parent_id.unwrap_or(ROOT_ID);

        let encrypted_name = crypto::encrypt(name, &password, self.encryption_count, None)
            .map_err(|e| WalletError::EncryptionError(e))?;

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::create_item(conn, &item_id, parent, &encrypted_name, icon, folder)?;

        self.items_cache = None;
        Ok(item_id)
    }

    /// Update item name
    pub fn update_item_name(&mut self, item_id: &str, name: &str) -> Result<()> {
        self.ensure_unlocked()?;

        let password = self.password.as_ref().unwrap().clone();

        let encrypted_name = crypto::encrypt(name, &password, self.encryption_count, None)
            .map_err(|e| WalletError::EncryptionError(e))?;

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::update_item_name(conn, item_id, &encrypted_name)?;

        self.items_cache = None;
        Ok(())
    }

    /// Update item icon
    pub fn update_item_icon(&mut self, item_id: &str, icon: &str) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::update_item_icon(conn, item_id, icon)?;

        self.items_cache = None;
        Ok(())
    }

    /// Move item to a new parent
    pub fn move_item(&mut self, item_id: &str, new_parent_id: &str) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::update_item_parent(conn, item_id, new_parent_id)?;

        self.items_cache = None;
        Ok(())
    }

    /// Delete an item (soft delete)
    pub fn delete_item(&mut self, item_id: &str) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::delete_item(conn, item_id)?;

        self.items_cache = None;
        self.fields_cache = None;
        Ok(())
    }

    /// Copy an item (and optionally its fields)
    pub fn copy_item(&mut self, source_item_id: &str) -> Result<String> {
        self.ensure_unlocked()?;

        let source_item = self.get_item(source_item_id)?
            .ok_or_else(|| WalletError::InvalidOperation("Item not found".to_string()))?;

        let copy_prefix = "Copy of ";
        let new_name = format!("{}{}", copy_prefix, source_item.name);

        let new_item_id = self.add_item(&new_name, &source_item.icon, source_item.folder, source_item.parent_id.as_deref())?;

        // Copy fields if it's not a folder
        if !source_item.folder {
            let fields = self.get_fields_by_item(source_item_id)?;
            for field in fields {
                self.add_field(&new_item_id, &field.field_type, &field.value, Some(field.sort_weight))?;
            }
        }

        Ok(new_item_id)
    }

    // =========================================================================
    // Fields operations
    // =========================================================================

    /// Get all fields (decrypted)
    pub fn get_fields(&mut self) -> Result<&[IWField]> {
        self.ensure_unlocked()?;
        self.load_fields_if_needed()?;
        Ok(self.fields_cache.as_ref().unwrap())
    }

    /// Get fields for a specific item
    pub fn get_fields_by_item(&mut self, item_id: &str) -> Result<Vec<IWField>> {
        let fields = self.get_fields()?;
        let mut result: Vec<IWField> = fields
            .iter()
            .filter(|f| f.item_id == item_id)
            .cloned()
            .collect();

        // Sort by weight
        result.sort_by_key(|f| f.sort_weight);

        Ok(result)
    }

    /// Load fields from database if not cached
    fn load_fields_if_needed(&mut self) -> Result<()> {
        if self.fields_cache.is_some() {
            return Ok(());
        }

        // Ensure labels are loaded first
        self.load_labels_if_needed()?;

        let password = self.password.as_ref()
            .ok_or(WalletError::Locked)?
            .clone();

        let db = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?;

        let conn = db.connection()?;
        let raw_fields = queries::get_all_fields_raw(conn)?;

        let labels = self.labels_cache.as_ref().unwrap();
        let mut fields = Vec::with_capacity(raw_fields.len());

        for raw in raw_fields {
            let value = crypto::decrypt(&raw.value_encrypted, &password, self.encryption_count, None)
                .map_err(|e| WalletError::DecryptionError(e))?;

            let label = labels.get(&raw.field_type);
            let (label_name, icon, value_type) = match label {
                Some(l) => (l.name.clone(), l.icon.clone(), l.value_type.clone()),
                None => ("Unknown".to_string(), "unknown".to_string(), "text".to_string()),
            };

            // Check expiry for date fields
            let (expired, expiring) = if raw.field_type == "EXPD" {
                check_expiry(&value)
            } else {
                (false, false)
            };

            fields.push(IWField {
                item_id: raw.item_id,
                field_id: raw.field_id,
                field_type: raw.field_type,
                value,
                label: label_name,
                icon,
                value_type,
                sort_weight: raw.sort_weight.unwrap_or(0),
                change_timestamp: raw.change_timestamp
                    .as_ref()
                    .and_then(|s| parse_timestamp(s))
                    .unwrap_or_else(Utc::now),
                deleted: raw.deleted,
                expired,
                expiring,
            });
        }

        self.fields_cache = Some(fields);
        Ok(())
    }

    /// Add a new field to an item
    pub fn add_field(&mut self, item_id: &str, field_type: &str, value: &str, sort_weight: Option<i32>) -> Result<String> {
        self.ensure_unlocked()?;

        let password = self.password.as_ref().unwrap().clone();
        let field_id = generate_field_id();

        let encrypted_value = crypto::encrypt(value, &password, self.encryption_count, None)
            .map_err(|e| WalletError::EncryptionError(e))?;

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        // Get weight if not specified
        let weight = match sort_weight {
            Some(w) => w,
            None => queries::get_max_field_weight(conn, item_id)? + 100,
        };

        queries::create_field(conn, item_id, &field_id, field_type, &encrypted_value, weight)?;

        self.fields_cache = None;
        Ok(field_id)
    }

    /// Update a field's value
    pub fn update_field(&mut self, field_id: &str, value: &str, sort_weight: Option<i32>) -> Result<()> {
        self.ensure_unlocked()?;

        let password = self.password.as_ref().unwrap().clone();

        let encrypted_value = crypto::encrypt(value, &password, self.encryption_count, None)
            .map_err(|e| WalletError::EncryptionError(e))?;

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        // Handle old password preservation
        // If updating a PASS field and OLDP field exists, save old password to OLDP
        if let Some(fields) = &self.fields_cache {
            if let Some(field) = fields.iter().find(|f| f.field_id == field_id) {
                if field.field_type == "PASS" {
                    if let Some(oldp_field) = fields.iter().find(|f| f.item_id == field.item_id && f.field_type == "OLDP") {
                        let old_encrypted = crypto::encrypt(&field.value, &password, self.encryption_count, None)
                            .map_err(|e| WalletError::EncryptionError(e))?;
                        queries::update_field(conn, &oldp_field.field_id, &old_encrypted, None)?;
                    }
                }
            }
        }

        queries::update_field(conn, field_id, &encrypted_value, sort_weight)?;

        self.fields_cache = None;
        Ok(())
    }

    /// Delete a field
    pub fn delete_field(&mut self, item_id: &str, field_id: &str) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::delete_field(conn, item_id, field_id)?;

        self.fields_cache = None;
        Ok(())
    }

    /// Copy a field to another item
    pub fn copy_field(&mut self, source_item_id: &str, field_id: &str, target_item_id: &str) -> Result<String> {
        let fields = self.get_fields_by_item(source_item_id)?;
        let field = fields.iter().find(|f| f.field_id == field_id)
            .ok_or_else(|| WalletError::InvalidOperation("Field not found".to_string()))?;

        self.add_field(target_item_id, &field.field_type, &field.value, None)
    }

    /// Move a field to another item
    pub fn move_field(&mut self, source_item_id: &str, field_id: &str, target_item_id: &str) -> Result<()> {
        self.copy_field(source_item_id, field_id, target_item_id)?;
        self.delete_field(source_item_id, field_id)?;
        Ok(())
    }

    // =========================================================================
    // Labels operations
    // =========================================================================

    /// Get all labels
    pub fn get_labels(&mut self) -> Result<Vec<IWLabel>> {
        self.load_labels_if_needed()?;
        let labels = self.labels_cache.as_ref().unwrap();
        let mut result: Vec<IWLabel> = labels.values().cloned().collect();

        // Sort: system first, then by name
        result.sort_by(|a, b| {
            match (a.system, b.system) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            }
        });

        Ok(result)
    }

    /// Load labels from database if not cached
    fn load_labels_if_needed(&mut self) -> Result<()> {
        if self.labels_cache.is_some() {
            return Ok(());
        }

        let db = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?;

        let conn = db.connection()?;
        let raw_labels = queries::get_all_labels(conn)?;

        let mut labels = HashMap::with_capacity(raw_labels.len());

        for raw in raw_labels {
            labels.insert(raw.field_type.clone(), IWLabel {
                field_type: raw.field_type,
                name: raw.label_name,
                value_type: raw.value_type,
                icon: raw.icon,
                system: raw.system,
                change_timestamp: raw.change_timestamp
                    .as_ref()
                    .and_then(|s| parse_timestamp(s))
                    .unwrap_or_else(Utc::now),
                deleted: raw.deleted,
                usage: raw.usage as u32,
            });
        }

        self.labels_cache = Some(labels);
        Ok(())
    }

    /// Add a new label
    pub fn add_label(&mut self, name: &str, icon: &str, value_type: &str) -> Result<String> {
        let label_id = generate_label_id();

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        let created = queries::create_label(conn, &label_id, name, value_type, icon, false)?;

        if !created {
            return Err(WalletError::InvalidOperation("Failed to create label".to_string()));
        }

        self.labels_cache = None;
        Ok(label_id)
    }

    /// Update label name
    pub fn update_label_name(&mut self, field_type: &str, name: &str) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::update_label_name(conn, field_type, name)?;

        self.labels_cache = None;
        Ok(())
    }

    /// Update label icon
    pub fn update_label_icon(&mut self, field_type: &str, icon: &str) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::update_label_icon(conn, field_type, icon)?;

        self.labels_cache = None;
        Ok(())
    }

    /// Delete a label (returns usage count, only deletes if 0)
    pub fn delete_label(&mut self, field_type: &str) -> Result<i32> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        let count = queries::delete_label(conn, field_type)?;

        self.labels_cache = None;
        Ok(count)
    }

    // =========================================================================
    // Search operations
    // =========================================================================

    /// Search items and fields
    ///
    /// Matches the original C# implementation:
    /// - Requires minimum search phrase length (SEARCH_MIN_LENGTH = 3)
    /// - Name matches exclude folders (only items are matched by name)
    /// - Field value matches include all items
    /// - Returns distinct results
    pub fn search(&mut self, query: &str) -> Result<Vec<SearchResult>> {
        use super::search::is_valid_search_phrase;

        self.ensure_unlocked()?;

        // Check minimum phrase length (matching C# SM.CheckPhraseLength)
        if !is_valid_search_phrase(query) {
            return Ok(Vec::new());
        }

        let query_lower = query.to_lowercase();
        let items = self.get_items()?.to_vec();
        let fields = self.get_fields()?.to_vec();

        let mut results = Vec::new();

        for item in items.iter() {
            if item.item_id == ROOT_ID {
                continue;
            }

            // Name match: only for non-folders (matching original C# behavior: !x.Folder)
            let name_match = !item.folder && item.name.to_lowercase().contains(&query_lower);

            // Field match: search in field values
            let matching_fields: Vec<IWField> = fields.iter()
                .filter(|f| f.item_id == item.item_id && f.value.to_lowercase().contains(&query_lower))
                .cloned()
                .collect();

            let field_match = !matching_fields.is_empty();

            if name_match || field_match {
                let match_type = match (name_match, field_match) {
                    (true, true) => SearchMatchType::Both,
                    (true, false) => SearchMatchType::Name,
                    (false, true) => SearchMatchType::Field,
                    (false, false) => unreachable!(),
                };

                results.push(SearchResult {
                    item: item.clone(),
                    matching_fields,
                    match_type,
                });
            }
        }

        Ok(results)
    }

    // =========================================================================
    // Password operations
    // =========================================================================

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
    fn ensure_unlocked(&self) -> Result<()> {
        if self.password.is_none() {
            return Err(WalletError::Locked);
        }
        Ok(())
    }

    /// Get the database path
    pub fn database_path(&self) -> PathBuf {
        self.folder.join(DATABASE_FILENAME)
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.close();
    }
}

/// Check if a date field is expired or expiring soon
fn check_expiry(date_str: &str) -> (bool, bool) {
    // Try to parse date in format YYYY-MM-DD
    if let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        let today = Utc::now().date_naive();
        let days_until = (date - today).num_days();

        let expired = days_until < 0;
        let expiring = days_until >= 0 && days_until <= 30;

        return (expired, expiring);
    }
    (false, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_wallet() -> (Wallet, TempDir) {
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
    fn test_create_item() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let item = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item.name, "Test Item");
        assert_eq!(item.icon, "document");
        assert!(!item.folder);
    }

    #[test]
    fn test_create_field() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "MAIL", "test@example.com", None).unwrap();
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].field_id, field_id);
        assert_eq!(fields[0].value, "test@example.com");
    }

    #[test]
    fn test_labels() {
        let (mut wallet, _temp) = create_test_wallet();
        let labels = wallet.get_labels().unwrap();
        assert_eq!(labels.len(), 19); // System labels count
    }

    #[test]
    fn test_search() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("My Email Account", "document", false, None).unwrap();
        wallet.add_field(&item_id, "MAIL", "john@example.com", None).unwrap();

        let results = wallet.search("email").unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].item.name, "My Email Account");
    }

    #[test]
    fn test_search_minimum_length() {
        let (mut wallet, _temp) = create_test_wallet();
        wallet.add_item("AB", "document", false, None).unwrap();

        // Search with phrase shorter than minimum length should return empty
        let results = wallet.search("ab").unwrap();
        assert!(results.is_empty());

        // Search with phrase at minimum length should work
        let results = wallet.search("abc").unwrap();
        assert!(results.is_empty()); // No match, but search executed
    }

    #[test]
    fn test_search_excludes_folders() {
        let (mut wallet, _temp) = create_test_wallet();
        wallet.add_item("Banking Folder", "folder", true, None).unwrap();
        let item_id = wallet.add_item("Banking Card", "document", false, None).unwrap();

        let results = wallet.search("Banking").unwrap();
        // Should find the item but not the folder
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].item.name, "Banking Card");
        assert!(!results[0].item.folder);
    }

    #[test]
    fn test_search_field_values() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("My Account", "document", false, None).unwrap();
        wallet.add_field(&item_id, "MAIL", "user@example.com", None).unwrap();

        let results = wallet.search("example.com").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_type, SearchMatchType::Field);
        assert_eq!(results[0].matching_fields.len(), 1);
    }

    #[test]
    fn test_search_case_insensitive() {
        let (mut wallet, _temp) = create_test_wallet();
        wallet.add_item("MyEmailAccount", "document", false, None).unwrap();

        let results = wallet.search("MYEMAIL").unwrap();
        assert_eq!(results.len(), 1);

        let results = wallet.search("myemail").unwrap();
        assert_eq!(results.len(), 1);

        let results = wallet.search("MyEmail").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_match_type_both() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        wallet.add_field(&item_id, "NOTE", "This is a test note", None).unwrap();

        let results = wallet.search("test").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_type, SearchMatchType::Both);
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
    fn test_delete_item() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("To Delete", "document", false, None).unwrap();
        wallet.delete_item(&item_id).unwrap();
        let item = wallet.get_item(&item_id).unwrap();
        assert!(item.is_none());
    }

    #[test]
    fn test_copy_item() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Original", "document", false, None).unwrap();
        wallet.add_field(&item_id, "MAIL", "test@test.com", None).unwrap();

        let copy_id = wallet.copy_item(&item_id).unwrap();
        let copy = wallet.get_item(&copy_id).unwrap().unwrap();
        assert_eq!(copy.name, "Copy of Original");

        let copy_fields = wallet.get_fields_by_item(&copy_id).unwrap();
        assert_eq!(copy_fields.len(), 1);
        assert_eq!(copy_fields[0].value, "test@test.com");
    }

    /// Test: CreateDeleteLabel from C# BusinessFixture
    #[test]
    fn test_create_delete_label() {
        let (mut wallet, _temp) = create_test_wallet();

        // Create custom label
        let label_id = wallet.add_label("Test Label 789", "labelcalendar", "date").unwrap();

        // Verify it exists
        let labels = wallet.get_labels().unwrap();
        let created = labels.iter().find(|l| l.field_type == label_id);
        assert!(created.is_some());
        let label = created.unwrap();
        assert_eq!(label.name, "Test Label 789");
        assert_eq!(label.value_type, "date");
        assert!(!label.system);

        // Delete it
        wallet.delete_label(&label_id).unwrap();

        // Verify it's gone
        let labels_after = wallet.get_labels().unwrap();
        let deleted = labels_after.iter().find(|l| l.field_type == label_id);
        assert!(deleted.is_none());
    }

    /// Test: DeleteField from C# BusinessFixture
    #[test]
    fn test_delete_field() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "PASS", "secretpassword", None).unwrap();

        // Verify field exists
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields.len(), 1);

        // Delete field
        wallet.delete_field(&item_id, &field_id).unwrap();

        // Verify it's gone
        let fields_after = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields_after.len(), 0);
    }

    /// Test: ChangeItem from C# BusinessFixture
    #[test]
    fn test_update_item_name() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Original Name", "document", false, None).unwrap();

        // Update name
        wallet.update_item_name(&item_id, "New Name").unwrap();

        // Verify change
        let item = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item.name, "New Name");
    }

    /// Test: ChangeIcon from C# BusinessFixture
    #[test]
    fn test_update_item_icon() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();

        // Update icon
        wallet.update_item_icon(&item_id, "maestro").unwrap();

        // Verify change
        let item = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item.icon, "maestro");
    }

    /// Test: ChangeField from C# BusinessFixture
    #[test]
    fn test_update_field() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "LINK", "http://old.com", None).unwrap();

        // Update value
        wallet.update_field(&field_id, "http://new.com", None).unwrap();

        // Verify change
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        let field = fields.iter().find(|f| f.field_id == field_id).unwrap();
        assert_eq!(field.value, "http://new.com");
    }

    /// Test: CopyFolder from C# BusinessFixture
    #[test]
    fn test_copy_folder() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Original Folder", "folder", true, None).unwrap();

        let copy_id = wallet.copy_item(&folder_id).unwrap();
        let copy = wallet.get_item(&copy_id).unwrap().unwrap();
        assert_eq!(copy.name, "Copy of Original Folder");
        assert!(copy.folder);
    }

    /// Test: CopyField from C# BusinessFixture
    #[test]
    fn test_copy_field() {
        let (mut wallet, _temp) = create_test_wallet();
        let item1_id = wallet.add_item("Item 1", "document", false, None).unwrap();
        let item2_id = wallet.add_item("Item 2", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item1_id, "MAIL", "test@example.com", None).unwrap();

        // Copy field to item2
        let new_field_id = wallet.copy_field(&item1_id, &field_id, &item2_id).unwrap();

        // Verify original still exists
        let fields1 = wallet.get_fields_by_item(&item1_id).unwrap();
        assert_eq!(fields1.len(), 1);

        // Verify copy exists in item2
        let fields2 = wallet.get_fields_by_item(&item2_id).unwrap();
        assert_eq!(fields2.len(), 1);
        assert_eq!(fields2[0].field_id, new_field_id);
        assert_eq!(fields2[0].value, "test@example.com");
        assert_eq!(fields2[0].field_type, "MAIL");
    }

    /// Test: MoveField from C# BusinessFixture
    #[test]
    fn test_move_field() {
        let (mut wallet, _temp) = create_test_wallet();
        let item1_id = wallet.add_item("Item 1", "document", false, None).unwrap();
        let item2_id = wallet.add_item("Item 2", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item1_id, "MAIL", "move@example.com", None).unwrap();

        // Move field to item2
        wallet.move_field(&item1_id, &field_id, &item2_id).unwrap();

        // Verify field is gone from item1
        let fields1 = wallet.get_fields_by_item(&item1_id).unwrap();
        assert_eq!(fields1.len(), 0);

        // Verify field is in item2
        let fields2 = wallet.get_fields_by_item(&item2_id).unwrap();
        assert_eq!(fields2.len(), 1);
        assert_eq!(fields2[0].value, "move@example.com");
    }

    /// Test: MoveItem from C# BusinessFixture
    #[test]
    fn test_move_item() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Target Folder", "folder", true, None).unwrap();
        let item_id = wallet.add_item("Item to Move", "document", false, None).unwrap();

        // Item should be at root
        let item_before = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item_before.parent_id.as_deref(), Some(ROOT_ID));

        // Move to folder
        wallet.move_item(&item_id, &folder_id).unwrap();

        // Verify new parent
        let item_after = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item_after.parent_id.as_deref(), Some(folder_id.as_str()));
    }

    /// Test: UpdateLabelName
    #[test]
    fn test_update_label_name() {
        let (mut wallet, _temp) = create_test_wallet();
        let label_id = wallet.add_label("Original Label", "labelcalendar", "text").unwrap();

        wallet.update_label_name(&label_id, "Renamed Label").unwrap();

        let labels = wallet.get_labels().unwrap();
        let label = labels.iter().find(|l| l.field_type == label_id).unwrap();
        assert_eq!(label.name, "Renamed Label");
    }

    /// Test: UpdateLabelIcon
    #[test]
    fn test_update_label_icon() {
        let (mut wallet, _temp) = create_test_wallet();
        let label_id = wallet.add_label("Test Label", "labelcalendar", "text").unwrap();

        wallet.update_label_icon(&label_id, "labellink").unwrap();

        let labels = wallet.get_labels().unwrap();
        let label = labels.iter().find(|l| l.field_type == label_id).unwrap();
        assert_eq!(label.icon, "labellink");
    }

    /// Test with special characters (Cyrillic) - from C# BusinessFixture.DeleteItem
    #[test]
    fn test_cyrillic_item_name() {
        let (mut wallet, _temp) = create_test_wallet();
        let cyrillic_name = "аиыфьиафывр78ыфвафы23 !@#$%'\"";
        let item_id = wallet.add_item(cyrillic_name, "document", false, None).unwrap();

        let item = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item.name, cyrillic_name);
    }

    /// Test with special characters in field value
    #[test]
    fn test_special_chars_in_field() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let special_value = "Test Field 456 !@#$%'\"<>&";
        wallet.add_field(&item_id, "NOTE", special_value, None).unwrap();

        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields[0].value, special_value);
    }

    #[test]
    fn test_check_expiry_expired() {
        let yesterday = (Utc::now() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
        let (expired, expiring) = check_expiry(&yesterday);
        assert!(expired);
        assert!(!expiring);
    }

    #[test]
    fn test_check_expiry_expiring_soon() {
        let in_15_days = (Utc::now() + chrono::Duration::days(15)).format("%Y-%m-%d").to_string();
        let (expired, expiring) = check_expiry(&in_15_days);
        assert!(!expired);
        assert!(expiring);
    }

    #[test]
    fn test_check_expiry_future() {
        let in_60_days = (Utc::now() + chrono::Duration::days(60)).format("%Y-%m-%d").to_string();
        let (expired, expiring) = check_expiry(&in_60_days);
        assert!(!expired);
        assert!(!expiring);
    }

    #[test]
    fn test_check_expiry_invalid() {
        let (expired, expiring) = check_expiry("invalid");
        assert!(!expired);
        assert!(!expiring);
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

    #[test]
    fn test_create_folder() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Test Folder", "folder", true, None).unwrap();
        let folder = wallet.get_item(&folder_id).unwrap().unwrap();
        assert!(folder.folder);
        assert_eq!(folder.name, "Test Folder");
    }

    #[test]
    fn test_nested_items() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Parent Folder", "folder", true, None).unwrap();
        let item_id = wallet.add_item("Child Item", "document", false, Some(&folder_id)).unwrap();

        let children = wallet.get_items_by_parent(&folder_id).unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].item_id, item_id);
    }
}
