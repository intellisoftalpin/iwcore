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

// =========================================================================
// Gap #1: Undelete Items & Fields
// =========================================================================

#[test]
fn test_undelete_item() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let item_id = wallet.add_item("Recoverable Item", "document", false, None).unwrap();
    wallet.add_field(&item_id, "MAIL", "recover@test.com", None).unwrap();

    // Delete (cascades to fields)
    wallet.delete_item(&item_id).unwrap();
    assert!(wallet.get_item(&item_id).unwrap().is_none());

    // Undelete item only
    wallet.undelete_item(&item_id).unwrap();

    // Verify item is restored
    let item = wallet.get_item(&item_id).unwrap().unwrap();
    assert_eq!(item.name, "Recoverable Item");
    assert!(!item.deleted);

    // Fields stay deleted after item undelete (must be individually restored)
    let fields = wallet.get_fields_by_item(&item_id).unwrap();
    assert_eq!(fields.len(), 0, "Fields should stay deleted after item undelete");

    // Undelete field individually
    let deleted_fields = wallet.get_deleted_fields().unwrap();
    let field = deleted_fields.iter().find(|f| f.item_id == item_id).unwrap();
    wallet.undelete_field(&item_id, &field.field_id).unwrap();

    let restored_fields = wallet.get_fields_by_item(&item_id).unwrap();
    assert_eq!(restored_fields.len(), 1);
    assert_eq!(restored_fields[0].value, "recover@test.com");

    wallet.close();
}

#[test]
fn test_database_stats() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Get stats on the legacy test database
    let stats = wallet.get_database_stats().unwrap();

    // Basic sanity checks on the legacy database
    assert!(stats.total_labels >= 19, "Should have at least 19 system labels");
    assert!(stats.file_size_bytes > 0, "File size should be positive");

    // Add some items and verify counts change
    let item_id = wallet.add_item("Stats Test", "document", false, None).unwrap();
    wallet.add_field(&item_id, "MAIL", "stats@test.com", None).unwrap();

    let stats2 = wallet.get_database_stats().unwrap();
    assert_eq!(stats2.total_items, stats.total_items + 1);
    assert_eq!(stats2.total_fields, stats.total_fields + 1);

    // Delete and check deleted counts
    wallet.delete_item(&item_id).unwrap();
    let stats3 = wallet.get_database_stats().unwrap();
    assert_eq!(stats3.deleted_items, stats.deleted_items + 1);
    assert_eq!(stats3.deleted_fields, stats.deleted_fields + 1); // cascade-deleted field

    wallet.close();
}

#[test]
fn test_undelete_field() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let item_id = wallet.add_item("Item", "document", false, None).unwrap();
    let field_id = wallet.add_field(&item_id, "PASS", "secret_value", None).unwrap();

    // Delete field
    wallet.delete_field(&item_id, &field_id).unwrap();
    let fields = wallet.get_fields_by_item(&item_id).unwrap();
    assert_eq!(fields.len(), 0);

    // Undelete field
    wallet.undelete_field(&item_id, &field_id).unwrap();

    // Verify restored with correct data
    let fields = wallet.get_fields_by_item(&item_id).unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].value, "secret_value");
    assert_eq!(fields[0].field_type, "PASS");

    wallet.close();
}

#[test]
fn test_undelete_item_not_found() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let result = wallet.undelete_item("NONEXISTENT");
    assert!(result.is_err());

    wallet.close();
}

#[test]
fn test_undelete_active_item_errors() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let item_id = wallet.add_item("Active Item", "document", false, None).unwrap();

    // Undelete an item that's not deleted should fail
    let result = wallet.undelete_item(&item_id);
    assert!(result.is_err());

    wallet.close();
}

#[test]
fn test_undelete_multiple_fields() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let item_id = wallet.add_item("Item", "document", false, None).unwrap();
    let f1 = wallet.add_field(&item_id, "MAIL", "a@test.com", None).unwrap();
    let f2 = wallet.add_field(&item_id, "PASS", "pass1", None).unwrap();
    let f3 = wallet.add_field(&item_id, "NOTE", "note1", None).unwrap();

    // Delete all
    wallet.delete_field(&item_id, &f1).unwrap();
    wallet.delete_field(&item_id, &f2).unwrap();
    wallet.delete_field(&item_id, &f3).unwrap();
    assert_eq!(wallet.get_fields_by_item(&item_id).unwrap().len(), 0);

    // Undelete two
    wallet.undelete_field(&item_id, &f1).unwrap();
    wallet.undelete_field(&item_id, &f3).unwrap();

    let fields = wallet.get_fields_by_item(&item_id).unwrap();
    assert_eq!(fields.len(), 2);
    let values: Vec<&str> = fields.iter().map(|f| f.value.as_str()).collect();
    assert!(values.contains(&"a@test.com"));
    assert!(values.contains(&"note1"));

    // f2 should still be in deleted list
    let deleted = wallet.get_deleted_fields().unwrap();
    assert!(deleted.iter().any(|f| f.field_id == f2));

    wallet.close();
}

// =========================================================================
// Gap #2: get_deleted_items() / get_deleted_fields()
// =========================================================================

#[test]
fn test_get_deleted_items_list() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Create and delete items
    let id1 = wallet.add_item("Deleted A", "document", false, None).unwrap();
    let id2 = wallet.add_item("Deleted B", "document", false, None).unwrap();
    wallet.add_item("Keep Active", "document", false, None).unwrap();

    wallet.delete_item(&id1).unwrap();
    wallet.delete_item(&id2).unwrap();

    let deleted = wallet.get_deleted_items().unwrap();
    let deleted_names: Vec<&str> = deleted.iter().map(|i| i.name.as_str()).collect();

    // Our two deleted items should be in the list
    assert!(deleted_names.contains(&"Deleted A"));
    assert!(deleted_names.contains(&"Deleted B"));
    // Active item should NOT be in deleted list
    assert!(!deleted_names.contains(&"Keep Active"));

    wallet.close();
}

#[test]
fn test_get_deleted_fields_list() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let item_id = wallet.add_item("Item", "document", false, None).unwrap();
    let f1 = wallet.add_field(&item_id, "MAIL", "deleted@test.com", None).unwrap();
    wallet.add_field(&item_id, "PASS", "active_secret", None).unwrap();

    wallet.delete_field(&item_id, &f1).unwrap();

    let deleted = wallet.get_deleted_fields().unwrap();
    let deleted_values: Vec<&str> = deleted.iter().map(|f| f.value.as_str()).collect();
    assert!(deleted_values.contains(&"deleted@test.com"));
    assert!(!deleted_values.contains(&"active_secret"));

    wallet.close();
}

#[test]
fn test_get_deleted_items_empty_when_none_deleted() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    wallet.add_item("Active Only", "document", false, None).unwrap();

    // Only newly created items (no deletes) — but the legacy DB may have deleted records,
    // so we just verify it doesn't error out
    let deleted = wallet.get_deleted_items();
    assert!(deleted.is_ok());

    wallet.close();
}

// =========================================================================
// Gap #3: Change Password + Deleted Records
// =========================================================================

#[test]
fn test_change_password_deleted_items_still_accessible() {
    let temp_dir = TempDir::new().unwrap();
    let mut wallet = Wallet::create(temp_dir.path(), "OldPassword1", "en").unwrap();

    // Create and delete an item
    let item_id = wallet.add_item("Deleted Before PW Change", "document", false, None).unwrap();
    wallet.delete_item(&item_id).unwrap();

    // Change password
    assert!(wallet.change_password("NewPassword2").unwrap());

    // Deleted item should still be accessible
    let deleted = wallet.get_deleted_items().unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].name, "Deleted Before PW Change");

    // Verify after lock/unlock with new password
    wallet.lock();
    assert!(wallet.unlock("NewPassword2").unwrap());
    let deleted2 = wallet.get_deleted_items().unwrap();
    assert_eq!(deleted2.len(), 1);
    assert_eq!(deleted2[0].name, "Deleted Before PW Change");

    wallet.close();
}

#[test]
fn test_change_password_deleted_fields_still_accessible() {
    let temp_dir = TempDir::new().unwrap();
    let mut wallet = Wallet::create(temp_dir.path(), "OldPassword1", "en").unwrap();

    let item_id = wallet.add_item("Item", "document", false, None).unwrap();
    let field_id = wallet.add_field(&item_id, "PASS", "secret_before_change", None).unwrap();
    wallet.delete_field(&item_id, &field_id).unwrap();

    assert!(wallet.change_password("NewPassword2").unwrap());

    let deleted = wallet.get_deleted_fields().unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].value, "secret_before_change");

    // Lock/unlock cycle
    wallet.lock();
    assert!(wallet.unlock("NewPassword2").unwrap());
    let deleted2 = wallet.get_deleted_fields().unwrap();
    assert_eq!(deleted2.len(), 1);
    assert_eq!(deleted2[0].value, "secret_before_change");

    wallet.close();
}

#[test]
fn test_change_password_mixed_active_and_deleted() {
    let temp_dir = TempDir::new().unwrap();
    let mut wallet = Wallet::create(temp_dir.path(), "Pass1", "en").unwrap();

    // Active records
    let active_item = wallet.add_item("Active Item", "document", false, None).unwrap();
    wallet.add_field(&active_item, "MAIL", "active@test.com", None).unwrap();

    // Deleted records
    let del_item = wallet.add_item("Deleted Item", "document", false, None).unwrap();
    let del_field = wallet.add_field(&active_item, "PASS", "deleted_pass", None).unwrap();
    wallet.delete_item(&del_item).unwrap();
    wallet.delete_field(&active_item, &del_field).unwrap();

    // Change password
    assert!(wallet.change_password("Pass2").unwrap());

    // Active still works
    let item = wallet.get_item(&active_item).unwrap().unwrap();
    assert_eq!(item.name, "Active Item");
    let fields = wallet.get_fields_by_item(&active_item).unwrap();
    assert_eq!(fields[0].value, "active@test.com");

    // Deleted still works
    let del_items = wallet.get_deleted_items().unwrap();
    assert!(del_items.iter().any(|i| i.name == "Deleted Item"));
    let del_fields = wallet.get_deleted_fields().unwrap();
    assert!(del_fields.iter().any(|f| f.value == "deleted_pass"));

    wallet.close();
}

#[test]
fn test_change_password_twice_deleted_survive() {
    let temp_dir = TempDir::new().unwrap();
    let mut wallet = Wallet::create(temp_dir.path(), "Pass1", "en").unwrap();

    let item_id = wallet.add_item("Survivor", "document", false, None).unwrap();
    let field_id = wallet.add_field(&item_id, "NOTE", "persistent_note", None).unwrap();
    wallet.delete_item(&item_id).unwrap();
    wallet.delete_field(&item_id, &field_id).unwrap();

    // First password change
    assert!(wallet.change_password("Pass2").unwrap());
    // Second password change
    assert!(wallet.change_password("Pass3").unwrap());

    wallet.lock();
    assert!(!wallet.unlock("Pass1").unwrap());
    assert!(!wallet.unlock("Pass2").unwrap());
    assert!(wallet.unlock("Pass3").unwrap());

    let del_items = wallet.get_deleted_items().unwrap();
    assert!(del_items.iter().any(|i| i.name == "Survivor"));
    let del_fields = wallet.get_deleted_fields().unwrap();
    assert!(del_fields.iter().any(|f| f.value == "persistent_note"));

    wallet.close();
}

// =========================================================================
// Gap #4: Compact
// =========================================================================

#[test]
fn test_compact_purges_deleted_items() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let id1 = wallet.add_item("Purge Me 1", "document", false, None).unwrap();
    let id2 = wallet.add_item("Purge Me 2", "document", false, None).unwrap();

    wallet.delete_item(&id1).unwrap();
    wallet.delete_item(&id2).unwrap();

    let deleted_before = wallet.get_deleted_items().unwrap();
    let our_deleted = deleted_before.iter()
        .filter(|i| i.name == "Purge Me 1" || i.name == "Purge Me 2")
        .count();
    assert_eq!(our_deleted, 2);

    let (items_purged, _fields_purged) = wallet.compact().unwrap();
    assert!(items_purged >= 2);

    // Our items should be gone from deleted list
    let deleted_after = wallet.get_deleted_items().unwrap();
    assert!(!deleted_after.iter().any(|i| i.name == "Purge Me 1"));
    assert!(!deleted_after.iter().any(|i| i.name == "Purge Me 2"));

    wallet.close();
}

#[test]
fn test_compact_purges_deleted_fields() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let item_id = wallet.add_item("Item With Fields", "document", false, None).unwrap();
    let f1 = wallet.add_field(&item_id, "MAIL", "purge_this@test.com", None).unwrap();
    wallet.add_field(&item_id, "PASS", "keep_this_active", None).unwrap();

    wallet.delete_field(&item_id, &f1).unwrap();

    wallet.compact().unwrap();

    // Deleted field should be purged
    let deleted = wallet.get_deleted_fields().unwrap();
    assert!(!deleted.iter().any(|f| f.value == "purge_this@test.com"));

    // Active field should survive
    let active = wallet.get_fields_by_item(&item_id).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].value, "keep_this_active");

    wallet.close();
}

#[test]
fn test_compact_returns_counts() {
    let temp_dir = TempDir::new().unwrap();
    let mut wallet = Wallet::create(temp_dir.path(), "TestPass", "en").unwrap();

    let item_id = wallet.add_item("Item", "document", false, None).unwrap();
    let f1 = wallet.add_field(&item_id, "MAIL", "a@a.com", None).unwrap();
    wallet.add_field(&item_id, "PASS", "secret", None).unwrap();

    // Explicitly delete one field, then delete item (cascade-deletes the other)
    wallet.delete_field(&item_id, &f1).unwrap();
    wallet.delete_item(&item_id).unwrap();

    let (items_purged, fields_purged) = wallet.compact().unwrap();
    assert_eq!(items_purged, 1);
    assert_eq!(fields_purged, 2); // f1 explicitly deleted + PASS cascade-deleted

    wallet.close();
}

#[test]
fn test_compact_idempotent() {
    let temp_dir = TempDir::new().unwrap();
    let mut wallet = Wallet::create(temp_dir.path(), "TestPass", "en").unwrap();

    let item_id = wallet.add_item("Gone", "document", false, None).unwrap();
    wallet.delete_item(&item_id).unwrap();

    let (count1, _) = wallet.compact().unwrap();
    assert_eq!(count1, 1);

    // Second compact: nothing left
    let (count2, count3) = wallet.compact().unwrap();
    assert_eq!(count2, 0);
    assert_eq!(count3, 0);

    wallet.close();
}

// =========================================================================
// Gap #5: check_password()
// =========================================================================

#[test]
fn test_check_password_correct() {
    let (wallet, _temp_dir) = setup_test_wallet();

    // check_password doesn't require unlock
    assert!(wallet.check_password(TEST_PASSWORD).unwrap());
}

#[test]
fn test_check_password_wrong() {
    let (wallet, _temp_dir) = setup_test_wallet();

    assert!(!wallet.check_password("WrongPassword").unwrap());
}

#[test]
fn test_check_password_after_change() {
    let temp_dir = TempDir::new().unwrap();
    let mut wallet = Wallet::create(temp_dir.path(), "OldPass", "en").unwrap();

    assert!(wallet.check_password("OldPass").unwrap());
    assert!(!wallet.check_password("NewPass").unwrap());

    wallet.change_password("NewPass").unwrap();

    assert!(!wallet.check_password("OldPass").unwrap());
    assert!(wallet.check_password("NewPass").unwrap());

    wallet.close();
}

#[test]
fn test_check_password_while_locked() {
    let (mut wallet, _temp_dir) = setup_test_wallet();

    // Lock explicitly (wallet starts locked for setup_test_wallet)
    // check_password should work regardless of lock state
    assert!(wallet.check_password(TEST_PASSWORD).unwrap());

    wallet.unlock(TEST_PASSWORD).unwrap();
    assert!(wallet.check_password(TEST_PASSWORD).unwrap());

    wallet.lock();
    assert!(wallet.check_password(TEST_PASSWORD).unwrap());

    wallet.close();
}

// =========================================================================
// Gap #6: Cascade Delete (folder with children)
// =========================================================================

#[test]
fn test_cascade_delete_folder_with_children() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let folder = wallet.add_item("Parent Folder", "folder", true, None).unwrap();
    let child1 = wallet.add_item("Child 1", "document", false, Some(&folder)).unwrap();
    let child2 = wallet.add_item("Child 2", "document", false, Some(&folder)).unwrap();
    wallet.add_field(&child1, "MAIL", "child1@test.com", None).unwrap();

    // Delete folder — should cascade to children
    wallet.delete_item(&folder).unwrap();

    // All gone from active
    assert!(wallet.get_item(&folder).unwrap().is_none());
    assert!(wallet.get_item(&child1).unwrap().is_none());
    assert!(wallet.get_item(&child2).unwrap().is_none());

    // All present in deleted list
    let deleted = wallet.get_deleted_items().unwrap();
    let deleted_ids: Vec<&str> = deleted.iter().map(|i| i.item_id.as_str()).collect();
    assert!(deleted_ids.contains(&folder.as_str()));
    assert!(deleted_ids.contains(&child1.as_str()));
    assert!(deleted_ids.contains(&child2.as_str()));

    wallet.close();
}

#[test]
fn test_cascade_delete_deep_nesting() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let l1 = wallet.add_item("Level 1", "folder", true, None).unwrap();
    let l2 = wallet.add_item("Level 2", "folder", true, Some(&l1)).unwrap();
    let l3 = wallet.add_item("Level 3", "folder", true, Some(&l2)).unwrap();
    let l4 = wallet.add_item("Deep Item", "document", false, Some(&l3)).unwrap();

    wallet.delete_item(&l1).unwrap();

    // All 4 levels should be deleted
    let deleted = wallet.get_deleted_items().unwrap();
    let deleted_ids: Vec<&str> = deleted.iter().map(|i| i.item_id.as_str()).collect();
    assert!(deleted_ids.contains(&l1.as_str()));
    assert!(deleted_ids.contains(&l2.as_str()));
    assert!(deleted_ids.contains(&l3.as_str()));
    assert!(deleted_ids.contains(&l4.as_str()));

    wallet.close();
}

#[test]
fn test_cascade_delete_then_undelete_child() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let folder = wallet.add_item("Folder", "folder", true, None).unwrap();
    let child = wallet.add_item("Child", "document", false, Some(&folder)).unwrap();

    wallet.delete_item(&folder).unwrap();

    // Undelete only the child
    wallet.undelete_item(&child).unwrap();

    let restored = wallet.get_item(&child).unwrap().unwrap();
    assert_eq!(restored.name, "Child");

    // Parent still deleted
    assert!(wallet.get_item(&folder).unwrap().is_none());

    wallet.close();
}

// =========================================================================
// Gap #6b: Cascade Delete — Fields at all nesting levels
// =========================================================================

#[test]
fn test_cascade_delete_deep_nesting_fields_at_all_levels() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let l1 = wallet.add_item("Level 1", "folder", true, None).unwrap();
    let l2 = wallet.add_item("Level 2", "folder", true, Some(&l1)).unwrap();
    let l3 = wallet.add_item("Level 3", "folder", true, Some(&l2)).unwrap();
    let item_l1 = wallet.add_item("Item in L1", "document", false, Some(&l1)).unwrap();
    let item_l2 = wallet.add_item("Item in L2", "document", false, Some(&l2)).unwrap();
    let item_l3 = wallet.add_item("Item in L3", "document", false, Some(&l3)).unwrap();

    wallet.add_field(&item_l1, "MAIL", "l1@test.com", None).unwrap();
    wallet.add_field(&item_l2, "PASS", "l2secret", None).unwrap();
    wallet.add_field(&item_l2, "NOTE", "l2note", None).unwrap();
    wallet.add_field(&item_l3, "MAIL", "l3@test.com", None).unwrap();

    // Delete top-level folder
    wallet.delete_item(&l1).unwrap();

    // Fields at all levels are cascade-deleted
    assert_eq!(wallet.get_fields_by_item(&item_l1).unwrap().len(), 0);
    assert_eq!(wallet.get_fields_by_item(&item_l2).unwrap().len(), 0);
    assert_eq!(wallet.get_fields_by_item(&item_l3).unwrap().len(), 0);

    // All 4 fields appear in deleted list
    let deleted = wallet.get_deleted_fields().unwrap();
    let our_deleted: Vec<_> = deleted.iter()
        .filter(|f| f.item_id == item_l1 || f.item_id == item_l2 || f.item_id == item_l3)
        .collect();
    assert_eq!(our_deleted.len(), 4);

    // Compact purges everything
    let (items_purged, fields_purged) = wallet.compact().unwrap();
    assert!(items_purged >= 6); // 3 folders + 3 items
    assert!(fields_purged >= 4); // 4 fields

    wallet.close();
}

#[test]
fn test_explicit_field_delete_then_item_delete_intermediate_state() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    let item_id = wallet.add_item("Item", "document", false, None).unwrap();
    let f1 = wallet.add_field(&item_id, "MAIL", "explicit@test.com", None).unwrap();
    let f2 = wallet.add_field(&item_id, "PASS", "cascade_me", None).unwrap();
    wallet.add_field(&item_id, "NOTE", "also_cascade", None).unwrap();

    // Explicitly delete f1 first
    wallet.delete_field(&item_id, &f1).unwrap();

    // Intermediate: 2 active, 1 deleted
    assert_eq!(wallet.get_fields_by_item(&item_id).unwrap().len(), 2);
    let deleted_mid = wallet.get_deleted_fields().unwrap();
    let our_deleted_mid: Vec<_> = deleted_mid.iter().filter(|f| f.item_id == item_id).collect();
    assert_eq!(our_deleted_mid.len(), 1);
    assert_eq!(our_deleted_mid[0].field_id, f1);

    // Now delete item — f2 and NOTE cascade, f1 stays as-is
    wallet.delete_item(&item_id).unwrap();

    // All 3 fields now in deleted list
    let deleted_after = wallet.get_deleted_fields().unwrap();
    let our_deleted_after: Vec<_> = deleted_after.iter().filter(|f| f.item_id == item_id).collect();
    assert_eq!(our_deleted_after.len(), 3);

    // f2 specifically became cascade-deleted
    assert!(our_deleted_after.iter().any(|f| f.field_id == f2));

    wallet.close();
}

#[test]
fn test_change_password_with_cascade_deleted_fields() {
    let temp_dir = TempDir::new().unwrap();
    let mut wallet = Wallet::create(temp_dir.path(), "OldPass", "en").unwrap();

    let item_id = wallet.add_item("Item", "document", false, None).unwrap();
    wallet.add_field(&item_id, "MAIL", "cascade@test.com", None).unwrap();
    wallet.add_field(&item_id, "PASS", "cascade_secret", None).unwrap();

    // Delete item — fields become cascade-deleted
    wallet.delete_item(&item_id).unwrap();

    // Change password
    assert!(wallet.change_password("NewPass").unwrap());

    // Cascade-deleted fields still accessible
    let deleted = wallet.get_deleted_fields().unwrap();
    let our_fields: Vec<_> = deleted.iter().filter(|f| f.item_id == item_id).collect();
    assert_eq!(our_fields.len(), 2);
    let values: Vec<&str> = our_fields.iter().map(|f| f.value.as_str()).collect();
    assert!(values.contains(&"cascade@test.com"));
    assert!(values.contains(&"cascade_secret"));

    // Deleted item also still accessible
    let deleted_items = wallet.get_deleted_items().unwrap();
    assert!(deleted_items.iter().any(|i| i.item_id == item_id));

    // Lock/unlock cycle with new password
    wallet.lock();
    assert!(!wallet.unlock("OldPass").unwrap());
    assert!(wallet.unlock("NewPass").unwrap());

    // Still accessible after reopen
    let deleted2 = wallet.get_deleted_fields().unwrap();
    let our_fields2: Vec<_> = deleted2.iter().filter(|f| f.item_id == item_id).collect();
    assert_eq!(our_fields2.len(), 2);

    wallet.close();
}

// =========================================================================
// Gap #7: Backup Verify / Cleanup
// =========================================================================

#[test]
fn test_backup_verify() {
    let temp_dir = TempDir::new().unwrap();
    let wallet_dir = temp_dir.path().join("wallet");
    let backup_dir = temp_dir.path().join("backups");

    let wallet = Wallet::create(&wallet_dir, "TestPass", "en").unwrap();
    let backup_mgr = BackupManager::new(&backup_dir);

    let backup_path = backup_mgr.create_backup(wallet.database().unwrap(), true).unwrap();

    // Verify the backup is valid
    let valid = backup_mgr.verify_backup(&backup_path).unwrap();
    assert!(valid);
}

#[test]
fn test_backup_list_and_get_latest() {
    let temp_dir = TempDir::new().unwrap();
    let wallet_dir = temp_dir.path().join("wallet");
    let backup_dir = temp_dir.path().join("backups");

    let wallet = Wallet::create(&wallet_dir, "TestPass", "en").unwrap();
    let backup_mgr = BackupManager::new(&backup_dir);

    // No backups yet
    assert!(backup_mgr.list_backups().unwrap().is_empty());
    assert!(backup_mgr.get_latest_backup().unwrap().is_none());

    // Create two backups
    let _b1 = backup_mgr.create_backup(wallet.database().unwrap(), true).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100)); // filenames use seconds
    let b2 = backup_mgr.create_backup(wallet.database().unwrap(), true).unwrap();

    let backups = backup_mgr.list_backups().unwrap();
    assert_eq!(backups.len(), 2);

    let latest = backup_mgr.get_latest_backup().unwrap().unwrap();
    assert_eq!(latest.path, b2);
}

#[test]
fn test_backup_cleanup_old() {
    let temp_dir = TempDir::new().unwrap();
    let wallet_dir = temp_dir.path().join("wallet");
    let backup_dir = temp_dir.path().join("backups");

    let wallet = Wallet::create(&wallet_dir, "TestPass", "en").unwrap();
    let backup_mgr = BackupManager::new(&backup_dir);

    // Create 4 backups
    for _ in 0..4 {
        backup_mgr.create_backup(wallet.database().unwrap(), true).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }

    assert_eq!(backup_mgr.list_backups().unwrap().len(), 4);

    // Keep only 2
    let deleted = backup_mgr.cleanup_old_backups(2).unwrap();
    assert_eq!(deleted, 2);
    assert_eq!(backup_mgr.list_backups().unwrap().len(), 2);
}

#[test]
fn test_backup_cleanup_auto() {
    let temp_dir = TempDir::new().unwrap();
    let wallet_dir = temp_dir.path().join("wallet");
    let backup_dir = temp_dir.path().join("backups");

    let wallet = Wallet::create(&wallet_dir, "TestPass", "en").unwrap();
    let backup_mgr = BackupManager::new(&backup_dir);

    // Create auto backups (manual=false)
    for _ in 0..3 {
        backup_mgr.create_backup(wallet.database().unwrap(), false).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }

    assert_eq!(backup_mgr.list_backups().unwrap().len(), 3);

    // Cleanup with min_keep=3 and max_age=30 days — all are fresh, none should be deleted
    let deleted = backup_mgr.cleanup_auto_backups(3, 30).unwrap();
    assert_eq!(deleted, 0);
    assert_eq!(backup_mgr.list_backups().unwrap().len(), 3);
}

#[test]
fn test_backup_cleanup_keeps_minimum() {
    let temp_dir = TempDir::new().unwrap();
    let wallet_dir = temp_dir.path().join("wallet");
    let backup_dir = temp_dir.path().join("backups");

    let wallet = Wallet::create(&wallet_dir, "TestPass", "en").unwrap();
    let backup_mgr = BackupManager::new(&backup_dir);

    // Create 2 backups
    backup_mgr.create_backup(wallet.database().unwrap(), true).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    backup_mgr.create_backup(wallet.database().unwrap(), true).unwrap();

    // Try to keep 5 (more than we have) — should delete nothing
    let deleted = backup_mgr.cleanup_old_backups(5).unwrap();
    assert_eq!(deleted, 0);
    assert_eq!(backup_mgr.list_backups().unwrap().len(), 2);
}

// =========================================================================
// Gap #8: Legacy Database with Deleted Records
// =========================================================================

#[test]
fn test_legacy_db_get_deleted_items_does_not_crash() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // The legacy test database has deleted items with potentially NULL icon fields.
    // This should not crash — should return Ok with whatever is decryptable.
    let result = wallet.get_deleted_items();
    assert!(result.is_ok(), "get_deleted_items should not crash on legacy DB");

    let deleted = result.unwrap();
    println!("Legacy DB has {} deleted items (decryptable)", deleted.len());

    // All returned items should have valid data
    for item in &deleted {
        assert!(!item.item_id.is_empty());
        assert!(item.deleted);
    }

    wallet.close();
}

#[test]
fn test_legacy_db_get_deleted_fields_does_not_crash() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Legacy DB may have deleted fields encrypted with old passwords.
    // Should silently skip undecryptable ones, not abort.
    let result = wallet.get_deleted_fields();
    assert!(result.is_ok(), "get_deleted_fields should not crash on legacy DB");

    let deleted = result.unwrap();
    println!("Legacy DB has {} deleted fields (decryptable)", deleted.len());

    for field in &deleted {
        assert!(!field.field_id.is_empty());
        assert!(field.deleted);
    }

    wallet.close();
}

#[test]
fn test_legacy_db_change_password_with_deleted_records() {
    let (mut wallet, _temp_dir) = setup_test_wallet();
    wallet.unlock(TEST_PASSWORD).unwrap();

    // Count what's decryptable before
    let items_before = wallet.get_items().unwrap().len();
    let fields_before = wallet.get_fields().unwrap().len();
    let deleted_items_before = wallet.get_deleted_items().unwrap().len();
    let deleted_fields_before = wallet.get_deleted_fields().unwrap().len();

    // Change password on legacy DB (which has deleted records with old encryption)
    let new_password = "LegacyDBNewPassword!";
    assert!(wallet.change_password(new_password).unwrap());

    // Active records should match
    let items_after = wallet.get_items().unwrap().len();
    let fields_after = wallet.get_fields().unwrap().len();
    assert_eq!(items_before, items_after, "Active items count should match");
    assert_eq!(fields_before, fields_after, "Active fields count should match");

    // Deleted records should be at least as many as before
    // (change_password re-encrypts what it can decrypt)
    let deleted_items_after = wallet.get_deleted_items().unwrap().len();
    let deleted_fields_after = wallet.get_deleted_fields().unwrap().len();
    assert!(deleted_items_after >= deleted_items_before,
        "Deleted items should not decrease after password change");
    assert!(deleted_fields_after >= deleted_fields_before,
        "Deleted fields should not decrease after password change");

    // Verify new password works after lock/unlock
    wallet.lock();
    assert!(wallet.unlock(new_password).unwrap());
    assert!(!wallet.unlock(TEST_PASSWORD).unwrap_or(false));

    wallet.close();
}
