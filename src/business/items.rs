//! Item operations
//!
//! This module provides item management operations for the Wallet.

use chrono::Utc;
use crate::error::{WalletError, Result};
use crate::database::{IWItem, queries};
use crate::database::queries::parse_timestamp;
use crate::crypto;
use crate::utils::generate_item_id;
use crate::ROOT_ID;
use super::wallet::Wallet;

impl Wallet {
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
    pub(crate) fn load_items_if_needed(&mut self) -> Result<()> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::business::wallet::tests::create_test_wallet;

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

    /// Test with special characters (Cyrillic) - from C# BusinessFixture.DeleteItem
    #[test]
    fn test_cyrillic_item_name() {
        let (mut wallet, _temp) = create_test_wallet();
        let cyrillic_name = "аиыфьиафывр78ыфвафы23 !@#$%'\"";
        let item_id = wallet.add_item(cyrillic_name, "document", false, None).unwrap();

        let item = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item.name, cyrillic_name);
    }
}
