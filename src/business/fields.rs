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
        let field_id = wallet.add_field(&item_id, "LINK", "http://old.com", None).unwrap();

        // Update value
        wallet.update_field(&field_id, "http://new.com", None).unwrap();

        // Verify change
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        let field = fields.iter().find(|f| f.field_id == field_id).unwrap();
        assert_eq!(field.value, "http://new.com");
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
}
