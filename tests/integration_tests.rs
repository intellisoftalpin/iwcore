//! Integration tests for iwcore
//!
//! These tests use the obfuscated test database in testdata/nswallet.dat

use std::path::PathBuf;
use std::fs;
use iwcore::{Wallet, BackupManager};
use tempfile::TempDir;

/// Hardcoded password for the test database
const TEST_PASSWORD: &str = "KuiperBelt30au";

/// Get the path to the test database
fn get_test_db_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("nswallet.dat")
}

/// Copy test database to temp directory and return wallet
fn setup_test_wallet() -> (Wallet, TempDir) {
    let source_db = get_test_db_path();
    assert!(source_db.exists(), "Test database not found: {:?}", source_db);

    let temp_dir = TempDir::new().unwrap();
    let dest_db = temp_dir.path().join("nswallet.dat");
    fs::copy(&source_db, &dest_db).expect("Failed to copy test database");

    let wallet = Wallet::open(temp_dir.path()).expect("Failed to open wallet");
    (wallet, temp_dir)
}

#[test]
fn test_open_and_unlock() {
    let (mut wallet, _temp_dir) = setup_test_wallet();

    // Verify unlock works with correct password
    let unlock_result = wallet.unlock(TEST_PASSWORD).unwrap();
    assert!(unlock_result, "Failed to unlock with correct password");
    assert!(wallet.is_unlocked());

    wallet.close();
}

#[test]
fn test_wrong_password() {
    let (mut wallet, _temp_dir) = setup_test_wallet();

    // Wrong password should fail
    let unlock_result = wallet.unlock("WrongPassword123!").unwrap();
    assert!(!unlock_result, "Should not unlock with wrong password");
    assert!(!wallet.is_unlocked());

    wallet.close();
}

#[test]
fn test_read_items() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Get all items
    let items = wallet.get_items().unwrap();
    println!("Found {} items", items.len());

    // There should be items (including root)
    assert!(!items.is_empty(), "Database should contain items");

    // Count folders and items
    let folder_count = items.iter().filter(|i| i.folder && i.item_id != "__ROOT__").count();
    let item_count = items.iter().filter(|i| !i.folder).count();
    println!("  Folders: {}, Items: {}", folder_count, item_count);

    wallet.close();
}

#[test]
fn test_read_fields() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Get all fields
    let fields = wallet.get_fields().unwrap();
    println!("Found {} fields", fields.len());

    // Should have fields
    assert!(!fields.is_empty(), "Database should contain fields");

    // Count by type
    let mut type_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for field in fields {
        *type_counts.entry(field.field_type.clone()).or_default() += 1;
    }

    for (field_type, count) in &type_counts {
        println!("  {}: {}", field_type, count);
    }

    wallet.close();
}

#[test]
fn test_properties() {
    let (wallet, _temp_dir) = setup_test_wallet();

    // Get properties (doesn't require unlock)
    let props = wallet.get_properties().unwrap();

    println!("Database properties:");
    println!("  Version: {}", props.version);
    println!("  Language: {}", props.lang);
    println!("  Encryption count: {}", props.encryption_count);

    // Verify version is valid
    let version: u32 = props.version.parse().unwrap_or(0);
    assert!(version > 0 && version <= 4, "Version should be between 1 and 4");
}

#[test]
fn test_labels() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Get all labels
    let labels = wallet.get_labels().unwrap();
    println!("Found {} labels", labels.len());

    // Should have at least system labels
    assert!(labels.len() >= 19, "Should have at least 19 system labels");

    // Count system vs custom
    let system_count = labels.iter().filter(|l| l.system).count();
    let custom_count = labels.iter().filter(|l| !l.system).count();
    println!("  System: {}, Custom: {}", system_count, custom_count);

    wallet.close();
}

#[test]
fn test_search() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Search for common pattern (items are named "Item 001", "Folder 001", etc.)
    let results = wallet.search("Item").unwrap();
    println!("Search for 'Item' found {} results", results.len());

    assert!(!results.is_empty(), "Search should find items");

    wallet.close();
}

#[test]
fn test_get_items_by_parent() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Get root items
    let root_items = wallet.get_items_by_parent("__ROOT__").unwrap();
    println!("Found {} items at root level", root_items.len());

    assert!(!root_items.is_empty(), "Should have items at root level");

    wallet.close();
}

#[test]
fn test_get_fields_by_item() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Find first non-folder item
    let items = wallet.get_items().unwrap().to_vec();
    let first_item = items.iter().find(|i| !i.folder);

    if let Some(item) = first_item {
        let fields = wallet.get_fields_by_item(&item.item_id).unwrap();
        println!("Item '{}' has {} fields", item.name, fields.len());
    }

    wallet.close();
}

#[test]
fn test_full_backup_restore_cycle() {
    // Create a new wallet
    let temp_dir = TempDir::new().unwrap();
    let wallet_dir = temp_dir.path().join("wallet");
    let backup_dir = temp_dir.path().join("backups");

    let mut wallet = Wallet::create(&wallet_dir, "TestPassword123!", "en").unwrap();

    // Add some items
    let folder_id = wallet.add_item("Test Folder", "folder", true, None).unwrap();
    let item_id = wallet.add_item("Test Item", "document", false, Some(&folder_id)).unwrap();
    wallet.add_field(&item_id, "MAIL", "test@example.com", None).unwrap();
    wallet.add_field(&item_id, "PASS", "secretpassword", None).unwrap();

    // Create backup
    let backup_mgr = BackupManager::new(&backup_dir);
    let backup_path = backup_mgr.create_backup(wallet.database().unwrap(), true).unwrap();

    // Close wallet
    wallet.close();

    // Restore to new location
    let restore_dir = temp_dir.path().join("restored");
    backup_mgr.extract_backup(&backup_path, &restore_dir).unwrap();

    // Open restored wallet
    let mut restored = Wallet::open(&restore_dir).unwrap();
    assert!(restored.unlock("TestPassword123!").unwrap());

    // Get items and clone to avoid borrow issues
    let items = restored.get_items().unwrap().to_vec();
    let folder = items.iter().find(|i| i.name == "Test Folder").unwrap();
    assert!(folder.folder);

    let item = items.iter().find(|i| i.name == "Test Item").unwrap();
    assert!(!item.folder);

    // Get item_id before getting fields
    let item_id = item.item_id.clone();

    // Verify fields
    let fields = restored.get_fields_by_item(&item_id).unwrap();
    assert_eq!(fields.len(), 2);

    let email_field = fields.iter().find(|f| f.field_type == "MAIL").unwrap();
    assert_eq!(email_field.value, "test@example.com");

    let pass_field = fields.iter().find(|f| f.field_type == "PASS").unwrap();
    assert_eq!(pass_field.value, "secretpassword");

    restored.close();
}

#[test]
fn test_modify_and_verify() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Add a new item
    let new_item_id = wallet.add_item("New Test Item", "document", false, None).unwrap();

    // Add fields to it
    wallet.add_field(&new_item_id, "USER", "testuser", None).unwrap();
    wallet.add_field(&new_item_id, "PASS", "testpass", None).unwrap();

    // Verify it exists
    let items = wallet.get_items().unwrap();
    let new_item = items.iter().find(|i| i.item_id == new_item_id);
    assert!(new_item.is_some(), "New item should exist");
    assert_eq!(new_item.unwrap().name, "New Test Item");

    // Verify fields
    let fields = wallet.get_fields_by_item(&new_item_id).unwrap();
    assert_eq!(fields.len(), 2);

    // Delete the item
    wallet.delete_item(&new_item_id).unwrap();

    // Verify it's gone (soft deleted, won't appear in get_items)
    let items_after = wallet.get_items().unwrap();
    let deleted_item = items_after.iter().find(|i| i.item_id == new_item_id);
    assert!(deleted_item.is_none(), "Deleted item should not appear");

    wallet.close();
}

#[test]
fn test_change_password() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Get initial item count
    let items_before = wallet.get_items().unwrap().to_vec();
    let fields_before = wallet.get_fields().unwrap().to_vec();

    // Change password
    let new_password = "NewSecurePassword123!";
    assert!(wallet.change_password(new_password).unwrap());

    // Lock and try old password
    wallet.lock();
    assert!(!wallet.unlock(TEST_PASSWORD).unwrap(), "Old password should not work");

    // Unlock with new password
    assert!(wallet.unlock(new_password).unwrap(), "New password should work");

    // Verify all data is still accessible
    let items_after = wallet.get_items().unwrap().len();
    let fields_after = wallet.get_fields().unwrap().len();
    assert_eq!(items_before.len(), items_after, "Item count should match");
    assert_eq!(fields_before.len(), fields_after, "Field count should match");

    wallet.close();
}

#[test]
fn test_update_item_name() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item
    let item_id = wallet.add_item("Original Name", "document", false, None).unwrap();

    // Update name
    wallet.update_item_name(&item_id, "Updated Name").unwrap();

    // Verify
    let item = wallet.get_item(&item_id).unwrap().unwrap();
    assert_eq!(item.name, "Updated Name");

    wallet.close();
}

#[test]
fn test_update_item_icon() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item
    let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();

    // Update icon
    wallet.update_item_icon(&item_id, "folder").unwrap();

    // Verify
    let item = wallet.get_item(&item_id).unwrap().unwrap();
    assert_eq!(item.icon, "folder");

    wallet.close();
}

#[test]
fn test_update_field_value() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item with field
    let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
    let field_id = wallet.add_field(&item_id, "NOTE", "Original value", None).unwrap();

    // Update field
    wallet.update_field(&field_id, "Updated value", None).unwrap();

    // Verify
    let fields = wallet.get_fields_by_item(&item_id).unwrap();
    assert_eq!(fields[0].value, "Updated value");

    wallet.close();
}

#[test]
fn test_delete_field() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item with field
    let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
    let field_id = wallet.add_field(&item_id, "PASS", "secret", None).unwrap();

    // Verify field exists
    let fields = wallet.get_fields_by_item(&item_id).unwrap();
    assert_eq!(fields.len(), 1);

    // Delete field
    wallet.delete_field(&item_id, &field_id).unwrap();

    // Verify deleted
    let fields_after = wallet.get_fields_by_item(&item_id).unwrap();
    assert_eq!(fields_after.len(), 0);

    wallet.close();
}

#[test]
fn test_copy_item() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item with fields
    let item_id = wallet.add_item("Original Item", "document", false, None).unwrap();
    wallet.add_field(&item_id, "MAIL", "test@example.com", None).unwrap();
    wallet.add_field(&item_id, "PASS", "password123", None).unwrap();

    // Copy item
    let copy_id = wallet.copy_item(&item_id).unwrap();

    // Verify copy
    let copy = wallet.get_item(&copy_id).unwrap().unwrap();
    assert_eq!(copy.name, "Copy of Original Item");

    // Verify fields copied
    let copy_fields = wallet.get_fields_by_item(&copy_id).unwrap();
    assert_eq!(copy_fields.len(), 2);

    wallet.close();
}

#[test]
fn test_copy_folder() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create folder
    let folder_id = wallet.add_item("Original Folder", "folder", true, None).unwrap();

    // Copy folder
    let copy_id = wallet.copy_item(&folder_id).unwrap();

    // Verify
    let copy = wallet.get_item(&copy_id).unwrap().unwrap();
    assert_eq!(copy.name, "Copy of Original Folder");
    assert!(copy.folder);

    wallet.close();
}

#[test]
fn test_move_item() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create folder and item
    let folder_id = wallet.add_item("Target Folder", "folder", true, None).unwrap();
    let item_id = wallet.add_item("Item to Move", "document", false, None).unwrap();

    // Move item to folder
    wallet.move_item(&item_id, &folder_id).unwrap();

    // Verify
    let item = wallet.get_item(&item_id).unwrap().unwrap();
    assert_eq!(item.parent_id.as_deref(), Some(folder_id.as_str()));

    wallet.close();
}

#[test]
fn test_copy_field() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create two items
    let item1_id = wallet.add_item("Item 1", "document", false, None).unwrap();
    let item2_id = wallet.add_item("Item 2", "document", false, None).unwrap();
    let field_id = wallet.add_field(&item1_id, "MAIL", "copy@test.com", None).unwrap();

    // Copy field to item2
    wallet.copy_field(&item1_id, &field_id, &item2_id).unwrap();

    // Verify original still exists
    let fields1 = wallet.get_fields_by_item(&item1_id).unwrap();
    assert_eq!(fields1.len(), 1);

    // Verify copy exists
    let fields2 = wallet.get_fields_by_item(&item2_id).unwrap();
    assert_eq!(fields2.len(), 1);
    assert_eq!(fields2[0].value, "copy@test.com");

    wallet.close();
}

#[test]
fn test_move_field() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create two items
    let item1_id = wallet.add_item("Item 1", "document", false, None).unwrap();
    let item2_id = wallet.add_item("Item 2", "document", false, None).unwrap();
    let field_id = wallet.add_field(&item1_id, "MAIL", "move@test.com", None).unwrap();

    // Move field to item2
    wallet.move_field(&item1_id, &field_id, &item2_id).unwrap();

    // Verify gone from item1
    let fields1 = wallet.get_fields_by_item(&item1_id).unwrap();
    assert_eq!(fields1.len(), 0);

    // Verify in item2
    let fields2 = wallet.get_fields_by_item(&item2_id).unwrap();
    assert_eq!(fields2.len(), 1);
    assert_eq!(fields2[0].value, "move@test.com");

    wallet.close();
}

#[test]
fn test_create_delete_label() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let initial_count = wallet.get_labels().unwrap().len();

    // Create custom label
    let label_id = wallet.add_label("Custom Label", "labelcalendar", "date").unwrap();

    // Verify created
    let labels = wallet.get_labels().unwrap();
    assert_eq!(labels.len(), initial_count + 1);
    let label = labels.iter().find(|l| l.field_type == label_id).unwrap();
    assert_eq!(label.name, "Custom Label");
    assert!(!label.system);

    // Delete label
    wallet.delete_label(&label_id).unwrap();

    // Verify deleted
    let labels_after = wallet.get_labels().unwrap();
    assert_eq!(labels_after.len(), initial_count);

    wallet.close();
}

#[test]
fn test_update_label() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create label
    let label_id = wallet.add_label("Original Label", "labelcalendar", "text").unwrap();

    // Update name
    wallet.update_label_name(&label_id, "Renamed Label").unwrap();

    // Update icon
    wallet.update_label_icon(&label_id, "labellink").unwrap();

    // Verify
    let labels = wallet.get_labels().unwrap();
    let label = labels.iter().find(|l| l.field_type == label_id).unwrap();
    assert_eq!(label.name, "Renamed Label");
    assert_eq!(label.icon, "labellink");

    wallet.close();
}

#[test]
fn test_cyrillic_data() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item with Cyrillic name
    let cyrillic_name = "Тестовый элемент 123";
    let item_id = wallet.add_item(cyrillic_name, "document", false, None).unwrap();

    // Add field with Cyrillic value
    let cyrillic_value = "Пароль: секретный!";
    wallet.add_field(&item_id, "NOTE", cyrillic_value, None).unwrap();

    // Verify
    let item = wallet.get_item(&item_id).unwrap().unwrap();
    assert_eq!(item.name, cyrillic_name);

    let fields = wallet.get_fields_by_item(&item_id).unwrap();
    assert_eq!(fields[0].value, cyrillic_value);

    wallet.close();
}

#[test]
fn test_special_characters() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item with special characters
    let special_name = "Test !@#$%^&*()_+-=[]{}|;':\",./<>?";
    let item_id = wallet.add_item(special_name, "document", false, None).unwrap();

    // Verify
    let item = wallet.get_item(&item_id).unwrap().unwrap();
    assert_eq!(item.name, special_name);

    wallet.close();
}

#[test]
fn test_reopen_after_modifications() {
    let (mut wallet, temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Add item
    let item_id = wallet.add_item("Persistent Item", "document", false, None).unwrap();
    wallet.add_field(&item_id, "MAIL", "persist@test.com", None).unwrap();

    // Close wallet
    wallet.close();

    // Reopen same database
    let mut wallet2 = iwcore::Wallet::open(temp_dir.path()).unwrap();
    wallet2.unlock(TEST_PASSWORD).unwrap();

    // Verify data persisted
    let item = wallet2.get_item(&item_id).unwrap().unwrap();
    assert_eq!(item.name, "Persistent Item");

    let fields = wallet2.get_fields_by_item(&item_id).unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].value, "persist@test.com");

    wallet2.close();
}

#[test]
fn test_search_by_item_name() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create items with searchable names
    wallet.add_item("Banking Account", "document", false, None).unwrap();
    wallet.add_item("Email Login", "document", false, None).unwrap();
    wallet.add_item("Social Media", "document", false, None).unwrap();

    // Search for "Bank"
    let results = wallet.search("Bank").unwrap();
    assert!(!results.is_empty(), "Should find 'Banking Account'");
    assert!(results.iter().any(|r| r.item.name.contains("Bank")));

    // Search for "Login"
    let results2 = wallet.search("Login").unwrap();
    assert!(!results2.is_empty(), "Should find 'Email Login'");

    wallet.close();
}

#[test]
fn test_search_by_field_value() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item with searchable field values
    let item_id = wallet.add_item("My Account", "document", false, None).unwrap();
    wallet.add_field(&item_id, "MAIL", "john.doe@example.com", None).unwrap();
    wallet.add_field(&item_id, "USER", "johndoe123", None).unwrap();

    // Search for email
    let results = wallet.search("john.doe").unwrap();
    assert!(!results.is_empty(), "Should find by email");

    // Search for username
    let results2 = wallet.search("johndoe").unwrap();
    assert!(!results2.is_empty(), "Should find by username");

    wallet.close();
}

#[test]
fn test_search_case_insensitive() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item
    let item_id = wallet.add_item("TestItem", "document", false, None).unwrap();
    wallet.add_field(&item_id, "NOTE", "SecretValue", None).unwrap();

    // Search with different cases
    let results_lower = wallet.search("testitem").unwrap();
    let results_upper = wallet.search("TESTITEM").unwrap();
    let results_mixed = wallet.search("TeStItEm").unwrap();

    assert!(!results_lower.is_empty(), "Should find with lowercase");
    assert!(!results_upper.is_empty(), "Should find with uppercase");
    assert!(!results_mixed.is_empty(), "Should find with mixed case");

    wallet.close();
}

#[test]
fn test_search_no_results() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Search for non-existent term
    let results = wallet.search("xyznonexistent123").unwrap();
    assert!(results.is_empty(), "Should return empty for non-existent term");

    wallet.close();
}

#[test]
fn test_search_cyrillic() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item with Cyrillic
    let item_id = wallet.add_item("Банковский счёт", "document", false, None).unwrap();
    wallet.add_field(&item_id, "NOTE", "Секретный пароль", None).unwrap();

    // Search Cyrillic
    let results = wallet.search("Банк").unwrap();
    assert!(!results.is_empty(), "Should find Cyrillic item name");

    let results2 = wallet.search("Секрет").unwrap();
    assert!(!results2.is_empty(), "Should find Cyrillic field value");

    wallet.close();
}

// =========================================================================
// Password Generator Tests
// =========================================================================

#[test]
fn test_password_generator_basic() {
    use iwcore::{generate_password, PasswordOptions};

    let options = PasswordOptions {
        lowercase: true,
        uppercase: true,
        digits: true,
        special: false,
        length: 16,
    };

    let password = generate_password(&options);
    assert_eq!(password.len(), 16);
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn test_password_generator_all_types() {
    use iwcore::{generate_password, PasswordOptions};

    let options = PasswordOptions {
        lowercase: true,
        uppercase: true,
        digits: true,
        special: true,
        length: 32,
    };

    let password = generate_password(&options);
    assert_eq!(password.len(), 32);
}

#[test]
fn test_password_generator_lowercase_only() {
    use iwcore::{generate_password, PasswordOptions};

    let options = PasswordOptions {
        lowercase: true,
        uppercase: false,
        digits: false,
        special: false,
        length: 20,
    };

    let password = generate_password(&options);
    assert_eq!(password.len(), 20);
    assert!(password.chars().all(|c| c.is_ascii_lowercase()));
}

#[test]
fn test_password_generator_digits_only() {
    use iwcore::{generate_password, PasswordOptions};

    let options = PasswordOptions {
        lowercase: false,
        uppercase: false,
        digits: true,
        special: false,
        length: 10,
    };

    let password = generate_password(&options);
    assert_eq!(password.len(), 10);
    assert!(password.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn test_password_generator_uniqueness() {
    use iwcore::{generate_password, PasswordOptions};

    let options = PasswordOptions::default();

    // Generate multiple passwords and ensure they're different
    let p1 = generate_password(&options);
    let p2 = generate_password(&options);
    let p3 = generate_password(&options);

    // With 16 chars from 62+ char pool, collision probability is negligible
    assert_ne!(p1, p2);
    assert_ne!(p2, p3);
    assert_ne!(p1, p3);
}

#[test]
fn test_clever_password_pattern() {
    use iwcore::generate_clever_password;

    // Pattern: uppercase + lowercase + digits
    let password = generate_clever_password("Aaaa0000");
    assert_eq!(password.len(), 8);

    let chars: Vec<char> = password.chars().collect();
    assert!(chars[0].is_ascii_uppercase());
    assert!(chars[1].is_ascii_lowercase());
    assert!(chars[2].is_ascii_lowercase());
    assert!(chars[3].is_ascii_lowercase());
    assert!(chars[4].is_ascii_digit());
    assert!(chars[5].is_ascii_digit());
    assert!(chars[6].is_ascii_digit());
    assert!(chars[7].is_ascii_digit());
}

#[test]
fn test_clever_password_mixed_pattern() {
    use iwcore::generate_clever_password;

    // More complex pattern
    let password = generate_clever_password("Aa0@Aa0@");
    assert_eq!(password.len(), 8);
}

// =========================================================================
// Export Types Tests
// =========================================================================

#[test]
fn test_export_item_type() {
    use iwcore::ExportItemType;

    assert_eq!(ExportItemType::Item.to_string(), "Item");
    assert_eq!(ExportItemType::Folder.to_string(), "Folder");
    assert_eq!(ExportItemType::Field.to_string(), "Field");
}

#[test]
fn test_pdf_item_model_creation() {
    use iwcore::{PDFItemModel, ExportItemType};

    let model = PDFItemModel::new("Test Item", "document", ExportItemType::Item, "/Banking/");
    assert_eq!(model.name, "Test Item");
    assert_eq!(model.image, "document");
    assert_eq!(model.item_type, ExportItemType::Item);
    assert_eq!(model.path, "/Banking/");
}

#[test]
fn test_pdf_item_model_helpers() {
    use iwcore::PDFItemModel;

    let item = PDFItemModel::item("My Item", "document", "/path/");
    assert!(item.is_item());
    assert!(!item.is_folder());
    assert!(!item.is_field());

    let folder = PDFItemModel::folder("My Folder", "folder", "/");
    assert!(!folder.is_item());
    assert!(folder.is_folder());
    assert!(!folder.is_field());

    let field = PDFItemModel::field("Email", "mail", "/Banking/Visa/");
    assert!(!field.is_item());
    assert!(!field.is_folder());
    assert!(field.is_field());
}

#[test]
fn test_pdf_item_model_serialization() {
    use iwcore::PDFItemModel;

    let model = PDFItemModel::item("Test", "icon", "/path/");
    let json = serde_json::to_string(&model).unwrap();

    assert!(json.contains("\"name\":\"Test\""));
    assert!(json.contains("\"image\":\"icon\""));
    assert!(json.contains("\"item_type\":\"Item\""));
    assert!(json.contains("\"path\":\"/path/\""));

    // Deserialize back
    let deserialized: PDFItemModel = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, "Test");
    assert!(deserialized.is_item());
}

// =========================================================================
// Search Edge Cases Tests
// =========================================================================

#[test]
fn test_search_minimum_length() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create item with short name
    wallet.add_item("AB", "document", false, None).unwrap();

    // Search with phrase shorter than minimum (3 chars) should return empty
    let results = wallet.search("AB").unwrap();
    assert!(results.is_empty(), "Search with <3 chars should return empty");

    // Search with exactly 3 chars should work
    let _results2 = wallet.search("ABC").unwrap();
    // May be empty if no match, but search executed

    wallet.close();
}

#[test]
fn test_search_excludes_folders_from_name_match() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create folder and item with same name pattern
    wallet.add_item("Banking Folder", "folder", true, None).unwrap();
    wallet.add_item("Banking Account", "document", false, None).unwrap();

    // Search should only match the item, not the folder
    let results = wallet.search("Banking").unwrap();

    // Count matches by type
    let folder_matches = results.iter().filter(|r| r.item.folder).count();
    let item_matches = results.iter().filter(|r| !r.item.folder).count();

    assert_eq!(folder_matches, 0, "Folders should not be matched by name");
    assert!(item_matches >= 1, "Items should be matched by name");

    wallet.close();
}
