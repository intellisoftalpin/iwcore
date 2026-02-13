//! Field operations
//!
//! This module provides field management operations for the Wallet.

use chrono::Utc;
use crate::error::{WalletError, Result};
use crate::database::{IWField, queries};
use crate::database::queries::parse_timestamp;
use crate::crypto;
use crate::utils::generate_field_id;
use super::wallet::Wallet;

impl Wallet {
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
    pub(crate) fn load_fields_if_needed(&mut self) -> Result<()> {
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

    /// Update a field's value. Soft-deletes the old field (preserving its value in the deleted pool)
    /// and creates a new field with the updated value. Returns the new field_id.
    pub fn update_field(&mut self, field_id: &str, value: &str, sort_weight: Option<i32>) -> Result<String> {
        self.ensure_unlocked()?;

        let password = self.password.as_ref().unwrap().clone();

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        // Fetch old field from DB
        let old_field = queries::get_field_raw_by_id(conn, field_id)?
            .ok_or_else(|| WalletError::FieldNotFound(field_id.to_string()))?;

        // If PASS type: copy old encrypted bytes directly to OLDP (no decrypt/re-encrypt needed)
        if old_field.field_type == "PASS" {
            if let Some(oldp_field_id) = queries::get_oldp_field_id(conn, &old_field.item_id)? {
                queries::update_field_value_only(conn, &old_field.item_id, &oldp_field_id, &old_field.value_encrypted)?;
            }
        }

        // Encrypt new value
        let encrypted_value = crypto::encrypt(value, &password, self.encryption_count, None)
            .map_err(|e| WalletError::EncryptionError(e))?;

        // Generate new field_id
        let new_field_id = generate_field_id();

        // Determine sort_weight: use explicit param if provided, else preserve old
        let weight = sort_weight.unwrap_or(old_field.sort_weight.unwrap_or(0));

        // Soft-delete old field
        queries::delete_field(conn, &old_field.item_id, field_id)?;

        // Create new field
        queries::create_field(conn, &old_field.item_id, &new_field_id, &old_field.field_type, &encrypted_value, weight)?;

        self.fields_cache = None;
        Ok(new_field_id)
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

    /// Get all soft-deleted fields (decrypted)
    pub fn get_deleted_fields(&mut self) -> Result<Vec<IWField>> {
        self.ensure_unlocked()?;

        // Ensure labels are loaded
        self.load_labels_if_needed()?;

        let password = self.password.as_ref()
            .ok_or(WalletError::Locked)?
            .clone();

        let db = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?;

        let conn = db.connection()?;
        let raw_fields = queries::get_deleted_fields_raw(conn)?;

        let labels = self.labels_cache.as_ref().unwrap();
        let mut fields = Vec::with_capacity(raw_fields.len());

        for raw in raw_fields {
            let value = match crypto::decrypt(&raw.value_encrypted, &password, self.encryption_count, None) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let label = labels.get(&raw.field_type);
            let (label_name, icon, value_type) = match label {
                Some(l) => (l.name.clone(), l.icon.clone(), l.value_type.clone()),
                None => ("Unknown".to_string(), "unknown".to_string(), "text".to_string()),
            };

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

        Ok(fields)
    }

    /// Restore a soft-deleted field
    pub fn undelete_field(&mut self, item_id: &str, field_id: &str) -> Result<()> {
        self.ensure_unlocked()?;

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::undelete_field(conn, item_id, field_id)?;

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
}

/// Check if a date field is expired or expiring soon
pub(crate) fn check_expiry(date_str: &str) -> (bool, bool) {
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
    use crate::business::wallet::tests::create_test_wallet;

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

    /// Test: ChangeField from C# BusinessFixture
    #[test]
    fn test_update_field() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "LINK", "http://old.com", Some(200)).unwrap();

        // Update value — returns new field_id
        let new_field_id = wallet.update_field(&field_id, "http://new.com", None).unwrap();

        // New field_id should differ from original
        assert_ne!(new_field_id, field_id);

        // Verify new field has updated value
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields.len(), 1);
        let field = fields.iter().find(|f| f.field_id == new_field_id).unwrap();
        assert_eq!(field.value, "http://new.com");
        assert_eq!(field.field_type, "LINK");
        assert_eq!(field.sort_weight, 200);

        // Old value should be in deleted pool
        let deleted = wallet.get_deleted_fields().unwrap();
        let old = deleted.iter().find(|f| f.field_id == field_id).unwrap();
        assert_eq!(old.value, "http://old.com");
        assert_eq!(old.field_type, "LINK");
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
    fn test_get_deleted_fields() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let field1_id = wallet.add_field(&item_id, "MAIL", "deleted@test.com", None).unwrap();
        let field2_id = wallet.add_field(&item_id, "PASS", "secret123", None).unwrap();
        wallet.add_field(&item_id, "NOTE", "keep this", None).unwrap();

        wallet.delete_field(&item_id, &field1_id).unwrap();
        wallet.delete_field(&item_id, &field2_id).unwrap();

        let deleted = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted.len(), 2);
        let values: Vec<&str> = deleted.iter().map(|f| f.value.as_str()).collect();
        assert!(values.contains(&"deleted@test.com"));
        assert!(values.contains(&"secret123"));
    }

    #[test]
    fn test_undelete_field() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "MAIL", "recover@test.com", None).unwrap();

        wallet.delete_field(&item_id, &field_id).unwrap();
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields.len(), 0);

        wallet.undelete_field(&item_id, &field_id).unwrap();
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value, "recover@test.com");
    }

    #[test]
    fn test_undelete_field_not_found() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let result = wallet.undelete_field(&item_id, "XXXX");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_deleted_fields_empty() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        wallet.add_field(&item_id, "MAIL", "active@test.com", None).unwrap();

        let deleted = wallet.get_deleted_fields().unwrap();
        assert!(deleted.is_empty());
    }

    #[test]
    fn test_get_deleted_fields_excludes_active() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let del_id = wallet.add_field(&item_id, "MAIL", "deleted@test.com", None).unwrap();
        wallet.add_field(&item_id, "NOTE", "active note", None).unwrap();

        wallet.delete_field(&item_id, &del_id).unwrap();

        let deleted = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].value, "deleted@test.com");

        let active = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].value, "active note");
    }

    #[test]
    fn test_get_deleted_fields_preserves_label_info() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "MAIL", "test@test.com", None).unwrap();

        wallet.delete_field(&item_id, &field_id).unwrap();

        let deleted = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].field_type, "MAIL");
        assert!(!deleted[0].label.is_empty());
        assert_ne!(deleted[0].label, "Unknown");
    }

    #[test]
    fn test_undelete_field_preserves_value_and_type() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "PASS", "MySecret123!", Some(500)).unwrap();

        wallet.delete_field(&item_id, &field_id).unwrap();
        wallet.undelete_field(&item_id, &field_id).unwrap();

        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value, "MySecret123!");
        assert_eq!(fields[0].field_type, "PASS");
        assert_eq!(fields[0].sort_weight, 500);
        assert!(!fields[0].deleted);
    }

    #[test]
    fn test_undelete_already_active_field_errors() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "MAIL", "test@test.com", None).unwrap();

        // Field is not deleted, undelete should fail
        let result = wallet.undelete_field(&item_id, &field_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_and_undelete_multiple_fields() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        let f1 = wallet.add_field(&item_id, "MAIL", "a@test.com", None).unwrap();
        let f2 = wallet.add_field(&item_id, "PASS", "pass1", None).unwrap();
        let f3 = wallet.add_field(&item_id, "NOTE", "note1", None).unwrap();

        // Delete all three
        wallet.delete_field(&item_id, &f1).unwrap();
        wallet.delete_field(&item_id, &f2).unwrap();
        wallet.delete_field(&item_id, &f3).unwrap();

        assert_eq!(wallet.get_deleted_fields().unwrap().len(), 3);
        assert_eq!(wallet.get_fields_by_item(&item_id).unwrap().len(), 0);

        // Undelete only two
        wallet.undelete_field(&item_id, &f1).unwrap();
        wallet.undelete_field(&item_id, &f3).unwrap();

        assert_eq!(wallet.get_deleted_fields().unwrap().len(), 1);
        let active = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(active.len(), 2);
        let active_values: Vec<&str> = active.iter().map(|f| f.value.as_str()).collect();
        assert!(active_values.contains(&"a@test.com"));
        assert!(active_values.contains(&"note1"));
    }

    #[test]
    fn test_get_deleted_fields_from_multiple_items() {
        let (mut wallet, _temp) = create_test_wallet();
        let item1 = wallet.add_item("Item 1", "document", false, None).unwrap();
        let item2 = wallet.add_item("Item 2", "document", false, None).unwrap();
        let f1 = wallet.add_field(&item1, "MAIL", "a@a.com", None).unwrap();
        let f2 = wallet.add_field(&item2, "MAIL", "b@b.com", None).unwrap();

        wallet.delete_field(&item1, &f1).unwrap();
        wallet.delete_field(&item2, &f2).unwrap();

        let deleted = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted.len(), 2);
        let item_ids: Vec<&str> = deleted.iter().map(|f| f.item_id.as_str()).collect();
        assert!(item_ids.contains(&item1.as_str()));
        assert!(item_ids.contains(&item2.as_str()));
    }

    #[test]
    fn test_get_deleted_fields_skips_undecryptable() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let f1 = wallet.add_field(&item_id, "MAIL", "good@test.com", None).unwrap();
        let f2 = wallet.add_field(&item_id, "PASS", "will_corrupt", None).unwrap();

        wallet.delete_field(&item_id, &f1).unwrap();
        wallet.delete_field(&item_id, &f2).unwrap();

        // Corrupt f2's encrypted value directly in the database
        let conn = wallet.db.as_ref().unwrap().connection().unwrap();
        conn.execute(
            "UPDATE nswallet_fields SET value = ? WHERE field_id = ?",
            rusqlite::params![vec![0u8; 32], f2],
        ).unwrap();

        // Should return only the decryptable field, not abort
        let deleted = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].value, "good@test.com");
    }

    #[test]
    fn test_get_deleted_fields_all_undecryptable_returns_empty() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let f1 = wallet.add_field(&item_id, "MAIL", "will_corrupt", None).unwrap();

        wallet.delete_field(&item_id, &f1).unwrap();

        // Corrupt the encrypted value
        let conn = wallet.db.as_ref().unwrap().connection().unwrap();
        conn.execute(
            "UPDATE nswallet_fields SET value = ? WHERE field_id = ?",
            rusqlite::params![vec![0u8; 32], f1],
        ).unwrap();

        // Should return empty, not error
        let deleted = wallet.get_deleted_fields().unwrap();
        assert!(deleted.is_empty());
    }

    #[test]
    fn test_update_field_creates_deleted_history() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "NOTE", "original value", None).unwrap();

        wallet.update_field(&field_id, "new value", None).unwrap();

        let deleted = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].value, "original value");
        assert_eq!(deleted[0].field_type, "NOTE");
    }

    #[test]
    fn test_update_field_multiple_history() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let fid = wallet.add_field(&item_id, "NOTE", "v1", None).unwrap();

        let fid2 = wallet.update_field(&fid, "v2", None).unwrap();
        let fid3 = wallet.update_field(&fid2, "v3", None).unwrap();
        wallet.update_field(&fid3, "v4", None).unwrap();

        // 3 old values in deleted pool
        let deleted = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted.len(), 3);
        let values: Vec<&str> = deleted.iter().map(|f| f.value.as_str()).collect();
        assert!(values.contains(&"v1"));
        assert!(values.contains(&"v2"));
        assert!(values.contains(&"v3"));

        // Active field has latest value
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value, "v4");
    }

    #[test]
    fn test_update_pass_field_updates_oldp_and_creates_history() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        wallet.add_field(&item_id, "PASS", "password1", None).unwrap();
        let oldp_id = wallet.add_field(&item_id, "OLDP", "", None).unwrap();

        // Load fields so we can get the PASS field_id
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        let pass_field_id = fields.iter().find(|f| f.field_type == "PASS").unwrap().field_id.clone();

        // Update PASS
        wallet.update_field(&pass_field_id, "password2", None).unwrap();

        // OLDP should have old password
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        let oldp = fields.iter().find(|f| f.field_id == oldp_id).unwrap();
        assert_eq!(oldp.value, "password1");

        // Old PASS should be in deleted pool
        let deleted = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].value, "password1");
        assert_eq!(deleted[0].field_type, "PASS");
    }

    #[test]
    fn test_update_pass_without_oldp() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let pass_id = wallet.add_field(&item_id, "PASS", "password1", None).unwrap();

        // No OLDP field — should not error
        let new_id = wallet.update_field(&pass_id, "password2", None).unwrap();
        assert_ne!(new_id, pass_id);

        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value, "password2");
    }

    #[test]
    fn test_update_field_does_not_affect_others() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let f1 = wallet.add_field(&item_id, "MAIL", "email@test.com", None).unwrap();
        let f2 = wallet.add_field(&item_id, "NOTE", "some note", None).unwrap();

        // Update only f1
        wallet.update_field(&f1, "new@test.com", None).unwrap();

        // f2 should be unchanged
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        let note = fields.iter().find(|f| f.field_id == f2).unwrap();
        assert_eq!(note.value, "some note");

        // Only 1 deleted entry (old f1)
        let deleted = wallet.get_deleted_fields().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].value, "email@test.com");
    }

    #[test]
    fn test_update_field_preserves_sort_weight() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let field_id = wallet.add_field(&item_id, "NOTE", "old", Some(500)).unwrap();

        let new_id = wallet.update_field(&field_id, "new", None).unwrap();

        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        let field = fields.iter().find(|f| f.field_id == new_id).unwrap();
        assert_eq!(field.sort_weight, 500);
    }
}
