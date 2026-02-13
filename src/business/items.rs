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

    /// Delete an item (soft delete). If the item is a folder, cascades to all descendants.
    pub fn delete_item(&mut self, item_id: &str) -> Result<()> {
        self.ensure_unlocked()?;

        // Check if item is a folder and cascade if needed
        let is_folder = self.get_item(item_id)?
            .map(|i| i.folder)
            .unwrap_or(false);

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        if is_folder {
            queries::delete_item_descendants(conn, item_id)?;
        }

        queries::delete_item(conn, item_id)?;

        self.items_cache = None;
        self.fields_cache = None;
        Ok(())
    }

    /// Get all soft-deleted items (decrypted)
    pub fn get_deleted_items(&mut self) -> Result<Vec<IWItem>> {
        self.ensure_unlocked()?;

        let password = self.password.as_ref()
            .ok_or(WalletError::Locked)?
            .clone();

        let db = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?;

        let conn = db.connection()?;
        let raw_items = queries::get_deleted_items_raw(conn)?;

        let mut items = Vec::with_capacity(raw_items.len());

        for raw in raw_items {
            let name = match crypto::decrypt(&raw.name_encrypted, &password, self.encryption_count, None) {
                Ok(v) => v,
                Err(_) => continue,
            };

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

        Ok(items)
    }

    /// Restore a soft-deleted item
    pub fn undelete_item(&mut self, item_id: &str) -> Result<()> {
        self.ensure_unlocked()?;

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::undelete_item(conn, item_id)?;

        self.items_cache = None;
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

    #[test]
    fn test_delete_folder_cascades() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Folder", "folder", true, None).unwrap();
        let item1_id = wallet.add_item("Item 1", "document", false, Some(&folder_id)).unwrap();
        let item2_id = wallet.add_item("Item 2", "document", false, Some(&folder_id)).unwrap();

        wallet.delete_item(&folder_id).unwrap();

        // All descendants should be gone from get_items()
        assert!(wallet.get_item(&folder_id).unwrap().is_none());
        assert!(wallet.get_item(&item1_id).unwrap().is_none());
        assert!(wallet.get_item(&item2_id).unwrap().is_none());
    }

    #[test]
    fn test_delete_folder_nested_cascades() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Top Folder", "folder", true, None).unwrap();
        let subfolder_id = wallet.add_item("Sub Folder", "folder", true, Some(&folder_id)).unwrap();
        let item_id = wallet.add_item("Deep Item", "document", false, Some(&subfolder_id)).unwrap();

        wallet.delete_item(&folder_id).unwrap();

        assert!(wallet.get_item(&folder_id).unwrap().is_none());
        assert!(wallet.get_item(&subfolder_id).unwrap().is_none());
        assert!(wallet.get_item(&item_id).unwrap().is_none());
    }

    #[test]
    fn test_get_deleted_items() {
        let (mut wallet, _temp) = create_test_wallet();
        let item1_id = wallet.add_item("Item A", "document", false, None).unwrap();
        let item2_id = wallet.add_item("Item B", "document", false, None).unwrap();
        wallet.add_item("Item C", "document", false, None).unwrap();

        wallet.delete_item(&item1_id).unwrap();
        wallet.delete_item(&item2_id).unwrap();

        let deleted = wallet.get_deleted_items().unwrap();
        assert_eq!(deleted.len(), 2);
        let names: Vec<&str> = deleted.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"Item A"));
        assert!(names.contains(&"Item B"));
    }

    #[test]
    fn test_undelete_item() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Recoverable", "document", false, None).unwrap();

        wallet.delete_item(&item_id).unwrap();
        assert!(wallet.get_item(&item_id).unwrap().is_none());

        wallet.undelete_item(&item_id).unwrap();
        let item = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item.name, "Recoverable");
    }

    #[test]
    fn test_undelete_item_not_found() {
        let (mut wallet, _temp) = create_test_wallet();
        let result = wallet.undelete_item("NONEXIST");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_deleted_items_empty() {
        let (mut wallet, _temp) = create_test_wallet();
        wallet.add_item("Alive Item", "document", false, None).unwrap();
        let deleted = wallet.get_deleted_items().unwrap();
        assert!(deleted.is_empty());
    }

    #[test]
    fn test_get_deleted_items_excludes_active() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("To Delete", "document", false, None).unwrap();
        wallet.add_item("Keep Alive", "document", false, None).unwrap();
        wallet.delete_item(&item_id).unwrap();

        let deleted = wallet.get_deleted_items().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].name, "To Delete");

        // Active items still accessible
        let active = wallet.get_items().unwrap();
        let active_names: Vec<&str> = active.iter().map(|i| i.name.as_str()).collect();
        assert!(active_names.contains(&"Keep Alive"));
        assert!(!active_names.contains(&"To Delete"));
    }

    #[test]
    fn test_get_deleted_items_includes_folders() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Deleted Folder", "folder", true, None).unwrap();
        wallet.delete_item(&folder_id).unwrap();

        let deleted = wallet.get_deleted_items().unwrap();
        assert!(deleted.iter().any(|i| i.name == "Deleted Folder" && i.folder));
    }

    #[test]
    fn test_delete_folder_cascades_appear_in_deleted() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Folder", "folder", true, None).unwrap();
        let child_id = wallet.add_item("Child", "document", false, Some(&folder_id)).unwrap();

        wallet.delete_item(&folder_id).unwrap();

        let deleted = wallet.get_deleted_items().unwrap();
        let deleted_ids: Vec<&str> = deleted.iter().map(|i| i.item_id.as_str()).collect();
        assert!(deleted_ids.contains(&folder_id.as_str()));
        assert!(deleted_ids.contains(&child_id.as_str()));
    }

    #[test]
    fn test_delete_empty_folder() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Empty Folder", "folder", true, None).unwrap();

        wallet.delete_item(&folder_id).unwrap();

        assert!(wallet.get_item(&folder_id).unwrap().is_none());
        let deleted = wallet.get_deleted_items().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].name, "Empty Folder");
    }

    #[test]
    fn test_delete_folder_deep_nesting_4_levels() {
        let (mut wallet, _temp) = create_test_wallet();
        let l1 = wallet.add_item("Level 1", "folder", true, None).unwrap();
        let l2 = wallet.add_item("Level 2", "folder", true, Some(&l1)).unwrap();
        let l3 = wallet.add_item("Level 3", "folder", true, Some(&l2)).unwrap();
        let l4 = wallet.add_item("Level 4 Item", "document", false, Some(&l3)).unwrap();

        wallet.delete_item(&l1).unwrap();

        assert!(wallet.get_item(&l1).unwrap().is_none());
        assert!(wallet.get_item(&l2).unwrap().is_none());
        assert!(wallet.get_item(&l3).unwrap().is_none());
        assert!(wallet.get_item(&l4).unwrap().is_none());

        let deleted = wallet.get_deleted_items().unwrap();
        assert_eq!(deleted.len(), 4);
    }

    #[test]
    fn test_delete_folder_mixed_content() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Mixed Folder", "folder", true, None).unwrap();
        let sub_folder = wallet.add_item("Sub Folder", "folder", true, Some(&folder_id)).unwrap();
        let item1 = wallet.add_item("Item in root", "document", false, Some(&folder_id)).unwrap();
        let item2 = wallet.add_item("Item in sub", "document", false, Some(&sub_folder)).unwrap();

        // Keep one item outside
        let outside = wallet.add_item("Outside", "document", false, None).unwrap();

        wallet.delete_item(&folder_id).unwrap();

        // All inside items gone
        assert!(wallet.get_item(&folder_id).unwrap().is_none());
        assert!(wallet.get_item(&sub_folder).unwrap().is_none());
        assert!(wallet.get_item(&item1).unwrap().is_none());
        assert!(wallet.get_item(&item2).unwrap().is_none());

        // Outside item untouched
        assert!(wallet.get_item(&outside).unwrap().is_some());
    }

    #[test]
    fn test_undelete_cascade_child_individually() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Folder", "folder", true, None).unwrap();
        let child_id = wallet.add_item("Child", "document", false, Some(&folder_id)).unwrap();

        wallet.delete_item(&folder_id).unwrap();

        // Undelete just the child
        wallet.undelete_item(&child_id).unwrap();

        let child = wallet.get_item(&child_id).unwrap().unwrap();
        assert_eq!(child.name, "Child");
        // Parent still deleted
        assert!(wallet.get_item(&folder_id).unwrap().is_none());
    }

    #[test]
    fn test_undelete_item_restores_to_root() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Parent Folder", "folder", true, None).unwrap();
        let item_id = wallet.add_item("Child Item", "document", false, Some(&folder_id)).unwrap();

        wallet.delete_item(&item_id).unwrap();
        wallet.undelete_item(&item_id).unwrap();

        let item = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item.parent_id.as_deref(), Some("__ROOT__"));
    }

    #[test]
    fn test_undelete_item_preserves_properties() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("My Item", "maestro", false, None).unwrap();

        wallet.delete_item(&item_id).unwrap();
        wallet.undelete_item(&item_id).unwrap();

        let item = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item.name, "My Item");
        assert_eq!(item.icon, "maestro");
        assert!(!item.folder);
        assert!(!item.deleted);
    }

    #[test]
    fn test_undelete_already_active_item_errors() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Active", "document", false, None).unwrap();
        // Item is not deleted, undelete should fail
        let result = wallet.undelete_item(&item_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_item_cascades_to_fields() {
        // Fields are cascade soft-deleted when their parent item is deleted.
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        wallet.add_field(&item_id, "MAIL", "test@test.com", None).unwrap();
        wallet.add_field(&item_id, "PASS", "secret", None).unwrap();

        wallet.delete_item(&item_id).unwrap();

        // Fields are now soft-deleted (not returned by get_fields_by_item)
        let fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(fields.len(), 0);

        // But the item itself is gone from active items
        assert!(wallet.get_item(&item_id).unwrap().is_none());

        // Fields appear in deleted fields list
        let deleted_fields = wallet.get_deleted_fields().unwrap();
        let item_deleted_fields: Vec<_> = deleted_fields.iter().filter(|f| f.item_id == item_id).collect();
        assert_eq!(item_deleted_fields.len(), 2);

        // compact() cleans them up
        wallet.compact().unwrap();
        let deleted_after = wallet.get_deleted_fields().unwrap();
        assert!(deleted_after.iter().all(|f| f.item_id != item_id));
    }

    #[test]
    fn test_delete_folder_cascades_to_child_fields() {
        // Cascade-deleted items also cascade-delete their fields
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Folder", "folder", true, None).unwrap();
        let child_id = wallet.add_item("Child", "document", false, Some(&folder_id)).unwrap();
        wallet.add_field(&child_id, "MAIL", "child@test.com", None).unwrap();

        wallet.delete_item(&folder_id).unwrap();

        // Fields are now soft-deleted
        let fields = wallet.get_fields_by_item(&child_id).unwrap();
        assert_eq!(fields.len(), 0);

        // Fields appear in deleted list
        let deleted_fields = wallet.get_deleted_fields().unwrap();
        assert!(deleted_fields.iter().any(|f| f.item_id == child_id));

        // compact() cleans them up
        wallet.compact().unwrap();
        let deleted_after = wallet.get_deleted_fields().unwrap();
        assert!(deleted_after.iter().all(|f| f.item_id != child_id));
    }

    #[test]
    fn test_delete_item_then_undelete_single_field() {
        // Delete item with 3 fields, undelete item + 1 field, assert only 1 field active
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let f1 = wallet.add_field(&item_id, "MAIL", "a@test.com", None).unwrap();
        wallet.add_field(&item_id, "PASS", "secret", None).unwrap();
        wallet.add_field(&item_id, "NOTE", "note text", None).unwrap();

        // Delete item (cascades to all 3 fields)
        wallet.delete_item(&item_id).unwrap();
        assert_eq!(wallet.get_fields_by_item(&item_id).unwrap().len(), 0);

        // Undelete the item
        wallet.undelete_item(&item_id).unwrap();
        // Fields stay deleted after item undelete
        assert_eq!(wallet.get_fields_by_item(&item_id).unwrap().len(), 0);

        // Undelete only one field
        wallet.undelete_field(&item_id, &f1).unwrap();

        let active_fields = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(active_fields.len(), 1);
        assert_eq!(active_fields[0].value, "a@test.com");

        // Other 2 fields still in deleted
        let deleted_fields = wallet.get_deleted_fields().unwrap();
        let still_deleted: Vec<_> = deleted_fields.iter().filter(|f| f.item_id == item_id).collect();
        assert_eq!(still_deleted.len(), 2);
    }

    #[test]
    fn test_delete_folder_deep_nesting_cascades_fields_at_all_levels() {
        // Fields at every nesting level should be cascade-deleted
        let (mut wallet, _temp) = create_test_wallet();
        let l1 = wallet.add_item("Level 1", "folder", true, None).unwrap();
        let l2 = wallet.add_item("Level 2", "folder", true, Some(&l1)).unwrap();
        let l3 = wallet.add_item("Level 3", "folder", true, Some(&l2)).unwrap();
        let item_l2 = wallet.add_item("Item in L2", "document", false, Some(&l2)).unwrap();
        let item_l3 = wallet.add_item("Item in L3", "document", false, Some(&l3)).unwrap();

        wallet.add_field(&item_l2, "MAIL", "l2@test.com", None).unwrap();
        wallet.add_field(&item_l2, "PASS", "l2secret", None).unwrap();
        wallet.add_field(&item_l3, "NOTE", "l3note", None).unwrap();

        // Delete top-level folder
        wallet.delete_item(&l1).unwrap();

        // All items gone from active
        assert!(wallet.get_item(&l1).unwrap().is_none());
        assert!(wallet.get_item(&item_l2).unwrap().is_none());
        assert!(wallet.get_item(&item_l3).unwrap().is_none());

        // Fields at level 2 are cascade-deleted
        let fields_l2 = wallet.get_fields_by_item(&item_l2).unwrap();
        assert_eq!(fields_l2.len(), 0);

        // Fields at level 3 are cascade-deleted
        let fields_l3 = wallet.get_fields_by_item(&item_l3).unwrap();
        assert_eq!(fields_l3.len(), 0);

        // All 3 fields appear in deleted list
        let deleted = wallet.get_deleted_fields().unwrap();
        let our_deleted: Vec<_> = deleted.iter()
            .filter(|f| f.item_id == item_l2 || f.item_id == item_l3)
            .collect();
        assert_eq!(our_deleted.len(), 3);
    }

    #[test]
    fn test_explicit_field_delete_then_item_delete_intermediate_state() {
        // Verify intermediate state: explicitly-deleted field stays deleted,
        // remaining active field becomes cascade-deleted
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Item", "document", false, None).unwrap();
        let f1 = wallet.add_field(&item_id, "MAIL", "explicit@test.com", None).unwrap();
        let f2 = wallet.add_field(&item_id, "PASS", "cascade_me", None).unwrap();

        // Explicitly delete f1
        wallet.delete_field(&item_id, &f1).unwrap();

        // f1 is deleted, f2 is still active
        let active = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].field_id, f2);

        let deleted_before = wallet.get_deleted_fields().unwrap();
        let our_deleted: Vec<_> = deleted_before.iter().filter(|f| f.item_id == item_id).collect();
        assert_eq!(our_deleted.len(), 1);
        assert_eq!(our_deleted[0].field_id, f1);

        // Now delete the item — f2 should become cascade-deleted, f1 stays deleted
        wallet.delete_item(&item_id).unwrap();

        let active_after = wallet.get_fields_by_item(&item_id).unwrap();
        assert_eq!(active_after.len(), 0);

        let deleted_after = wallet.get_deleted_fields().unwrap();
        let our_deleted_after: Vec<_> = deleted_after.iter().filter(|f| f.item_id == item_id).collect();
        assert_eq!(our_deleted_after.len(), 2);

        let deleted_ids: Vec<&str> = our_deleted_after.iter().map(|f| f.field_id.as_str()).collect();
        assert!(deleted_ids.contains(&f1.as_str()));
        assert!(deleted_ids.contains(&f2.as_str()));
    }

    #[test]
    fn test_get_deleted_items_skips_undecryptable() {
        let (mut wallet, _temp) = create_test_wallet();
        let item1 = wallet.add_item("Good Item", "document", false, None).unwrap();
        let item2 = wallet.add_item("Corrupt Item", "document", false, None).unwrap();

        wallet.delete_item(&item1).unwrap();
        wallet.delete_item(&item2).unwrap();

        // Corrupt item2's encrypted name directly in the database
        let conn = wallet.db.as_ref().unwrap().connection().unwrap();
        conn.execute(
            "UPDATE nswallet_items SET name = ? WHERE item_id = ?",
            rusqlite::params![vec![0u8; 32], item2],
        ).unwrap();

        // Should return only the decryptable item, not abort
        let deleted = wallet.get_deleted_items().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].name, "Good Item");
    }

    #[test]
    fn test_get_deleted_items_all_undecryptable_returns_empty() {
        let (mut wallet, _temp) = create_test_wallet();
        let item1 = wallet.add_item("Corrupt Item", "document", false, None).unwrap();

        wallet.delete_item(&item1).unwrap();

        // Corrupt the encrypted name
        let conn = wallet.db.as_ref().unwrap().connection().unwrap();
        conn.execute(
            "UPDATE nswallet_items SET name = ? WHERE item_id = ?",
            rusqlite::params![vec![0u8; 32], item1],
        ).unwrap();

        // Should return empty, not error
        let deleted = wallet.get_deleted_items().unwrap();
        assert!(deleted.is_empty());
    }

    #[test]
    fn test_undelete_item_with_purged_parent() {
        let (mut wallet, _temp) = create_test_wallet();
        let folder_id = wallet.add_item("Folder", "folder", true, None).unwrap();
        let item_id = wallet.add_item("Item", "document", false, Some(&folder_id)).unwrap();

        // Delete folder (cascades to item)
        wallet.delete_item(&folder_id).unwrap();

        // Simulate: folder was purged but item remains in deleted state
        // (e.g., folder purged in older version, item retained)
        let conn = wallet.db.as_ref().unwrap().connection().unwrap();
        conn.execute(
            "DELETE FROM nswallet_items WHERE item_id = ?",
            rusqlite::params![folder_id],
        ).unwrap();

        // Undelete the item — parent is gone, item restores to root
        wallet.undelete_item(&item_id).unwrap();

        let item = wallet.get_item(&item_id).unwrap().unwrap();
        assert_eq!(item.parent_id.as_deref(), Some("__ROOT__"));
        assert!(!item.deleted);
    }

    #[test]
    fn test_undelete_item_from_deep_nesting() {
        let (mut wallet, _temp) = create_test_wallet();
        let l1 = wallet.add_item("Level 1", "folder", true, None).unwrap();
        let l2 = wallet.add_item("Level 2", "folder", true, Some(&l1)).unwrap();
        let l3 = wallet.add_item("Level 3", "folder", true, Some(&l2)).unwrap();
        let leaf = wallet.add_item("Leaf Item", "document", false, Some(&l3)).unwrap();

        // Delete top-level folder (cascades all)
        wallet.delete_item(&l1).unwrap();

        // Undelete only the leaf item
        wallet.undelete_item(&leaf).unwrap();

        let item = wallet.get_item(&leaf).unwrap().unwrap();
        assert_eq!(item.parent_id.as_deref(), Some("__ROOT__"));
        assert!(!item.deleted);
    }

    #[test]
    fn test_undelete_folder_restores_to_root() {
        let (mut wallet, _temp) = create_test_wallet();
        let parent = wallet.add_item("Parent", "folder", true, None).unwrap();
        let child_folder = wallet.add_item("Child Folder", "folder", true, Some(&parent)).unwrap();

        // Delete parent (cascades to child folder)
        wallet.delete_item(&parent).unwrap();

        // Undelete child folder
        wallet.undelete_item(&child_folder).unwrap();

        let item = wallet.get_item(&child_folder).unwrap().unwrap();
        assert_eq!(item.parent_id.as_deref(), Some("__ROOT__"));
        assert!(item.folder);
        assert!(!item.deleted);
    }
}
