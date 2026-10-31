//! Export functionality for IntelliWallet
//!
//! This module provides data structures and utilities for exporting
//! wallet data to various formats (PDF, CSV, JSON, XML).

mod csv;
mod json;
mod pdf;
mod xml;

pub use csv::generate_csv;
pub use json::generate_json;
pub use pdf::generate_pdf;
pub use xml::generate_xml;

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::database::models::IWItem;

/// Type of item being exported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportItemType {
    /// A regular item (entry)
    Item,
    /// A folder
    Folder,
    /// A field within an item
    Field,
}

impl std::fmt::Display for ExportItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportItemType::Item => write!(f, "Item"),
            ExportItemType::Folder => write!(f, "Folder"),
            ExportItemType::Field => write!(f, "Field"),
        }
    }
}

/// Model for PDF export items
///
/// Represents a single exportable item with its display information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDFItemModel {
    /// Display name of the item
    pub name: String,
    /// Icon identifier or path
    pub image: String,
    /// Type of the item (Item, Folder, or Field)
    pub item_type: ExportItemType,
    /// Path to the item in the hierarchy (e.g., "/Banking/Credit Cards/")
    pub path: String,
}

impl PDFItemModel {
    /// Create a new PDFItemModel
    pub fn new(name: &str, image: &str, item_type: ExportItemType, path: &str) -> Self {
        Self {
            name: name.to_string(),
            image: image.to_string(),
            item_type,
            path: path.to_string(),
        }
    }

    /// Create a new item entry
    pub fn item(name: &str, image: &str, path: &str) -> Self {
        Self::new(name, image, ExportItemType::Item, path)
    }

    /// Create a new folder entry
    pub fn folder(name: &str, image: &str, path: &str) -> Self {
        Self::new(name, image, ExportItemType::Folder, path)
    }

    /// Create a new field entry
    pub fn field(name: &str, image: &str, path: &str) -> Self {
        Self::new(name, image, ExportItemType::Field, path)
    }

    /// Check if this is a folder
    pub fn is_folder(&self) -> bool {
        self.item_type == ExportItemType::Folder
    }

    /// Check if this is an item
    pub fn is_item(&self) -> bool {
        self.item_type == ExportItemType::Item
    }

    /// Check if this is a field
    pub fn is_field(&self) -> bool {
        self.item_type == ExportItemType::Field
    }
}

/// Folder path of an item, `"Banking / Credit Cards"`, or `""` at the top level.
///
/// Stops at the root, at a missing parent, and at a parent chain that loops
/// back on itself: a corrupt or crafted vault must never hang an export.
pub(crate) fn compute_path(item: &IWItem, items_map: &HashMap<&str, &IWItem>) -> String {
    let mut path_parts = Vec::new();
    let mut current_id = item.parent_id.as_deref();
    let mut seen: HashSet<&str> = HashSet::from([item.item_id.as_str()]);

    while let Some(pid) = current_id {
        if pid == crate::ROOT_ID || !seen.insert(pid) {
            break;
        }
        if let Some(parent) = items_map.get(pid) {
            path_parts.push(parent.name.clone());
            current_id = parent.parent_id.as_deref();
        } else {
            break;
        }
    }

    path_parts.reverse();
    path_parts.join(" / ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::models::IWField;
    use chrono::Utc;

    fn make_item(id: &str, name: &str, parent_id: Option<&str>, folder: bool, deleted: bool) -> IWItem {
        IWItem {
            item_id: id.to_string(),
            parent_id: parent_id.map(|s| s.to_string()),
            name: name.to_string(),
            icon: "icon".to_string(),
            folder,
            create_timestamp: Utc::now(),
            change_timestamp: Utc::now(),
            deleted,
        }
    }

    fn make_field(item_id: &str, field_id: &str, label: &str, value: &str, sort_weight: i32, deleted: bool) -> IWField {
        IWField {
            item_id: item_id.to_string(),
            field_id: field_id.to_string(),
            field_type: "TEXT".to_string(),
            value: value.to_string(),
            label: label.to_string(),
            icon: "icon".to_string(),
            value_type: "text".to_string(),
            sort_weight,
            change_timestamp: Utc::now(),
            deleted,
            expired: false,
            expiring: false,
        }
    }

    #[test]
    fn test_generate_pdf_empty() {
        let result = generate_pdf(&[], &[]);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
        // PDF files start with %PDF
        assert!(bytes.starts_with(b"%PDF"));
    }

    #[test]
    fn test_generate_pdf_single_item_no_fields() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("item1", "My Entry", Some("__ROOT__"), false, false),
        ];
        let result = generate_pdf(&items, &[]);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert!(bytes.starts_with(b"%PDF"));
    }

    #[test]
    fn test_generate_pdf_with_fields() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("item1", "Gmail", Some("__ROOT__"), false, false),
        ];
        let fields = vec![
            make_field("item1", "f1", "Email", "user@gmail.com", 0, false),
            make_field("item1", "f2", "Password", "secret123", 1, false),
        ];
        let result = generate_pdf(&items, &fields);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert!(bytes.starts_with(b"%PDF"));
    }

    #[test]
    fn test_generate_pdf_skips_deleted_items() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("item1", "Active Entry", Some("__ROOT__"), false, false),
            make_item("item2", "Deleted Entry", Some("__ROOT__"), false, true),
        ];
        let fields = vec![
            make_field("item1", "f1", "User", "active", 0, false),
            make_field("item2", "f2", "User", "deleted", 0, false),
        ];
        let result = generate_pdf(&items, &fields);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_pdf_skips_deleted_fields() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("item1", "Entry", Some("__ROOT__"), false, false),
        ];
        let fields = vec![
            make_field("item1", "f1", "Email", "user@test.com", 0, false),
            make_field("item1", "f2", "Old Password", "deleted_pass", 1, true),
        ];
        let result = generate_pdf(&items, &fields);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_pdf_skips_folders() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("folder1", "Banking", Some("__ROOT__"), true, false),
            make_item("item1", "Visa Card", Some("folder1"), false, false),
        ];
        let result = generate_pdf(&items, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_pdf_nested_path() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("folder1", "Banking", Some("__ROOT__"), true, false),
            make_item("folder2", "Credit Cards", Some("folder1"), true, false),
            make_item("item1", "Visa", Some("folder2"), false, false),
        ];
        let result = generate_pdf(&items, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_pdf_multiple_items_sorted() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("item1", "Zebra", Some("__ROOT__"), false, false),
            make_item("item2", "Apple", Some("__ROOT__"), false, false),
            make_item("item3", "Mango", Some("__ROOT__"), false, false),
        ];
        // Just verify it produces a valid PDF — sorting is internal
        let result = generate_pdf(&items, &[]);
        assert!(result.is_ok());
        assert!(result.unwrap().starts_with(b"%PDF"));
    }

    #[test]
    fn test_generate_pdf_cyrillic_content() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("item1", "\u{041f}\u{043e}\u{0447}\u{0442}\u{0430}", Some("__ROOT__"), false, false),
        ];
        let fields = vec![
            make_field("item1", "f1", "\u{041b}\u{043e}\u{0433}\u{0438}\u{043d}", "\u{0442}\u{0435}\u{0441}\u{0442}@mail.ru", 0, false),
        ];
        let result = generate_pdf(&items, &fields);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_path_root_parent() {
        let items = [make_item("__ROOT__", "Root", None, true, false),
            make_item("item1", "Entry", Some("__ROOT__"), false, false)];
        let items_map: HashMap<&str, &IWItem> = items.iter().map(|i| (i.item_id.as_str(), i)).collect();
        let path = compute_path(&items[1], &items_map);
        assert_eq!(path, "");
    }

    #[test]
    fn test_compute_path_one_level() {
        let items = [make_item("__ROOT__", "Root", None, true, false),
            make_item("folder1", "Banking", Some("__ROOT__"), true, false),
            make_item("item1", "Entry", Some("folder1"), false, false)];
        let items_map: HashMap<&str, &IWItem> = items.iter().map(|i| (i.item_id.as_str(), i)).collect();
        let path = compute_path(&items[2], &items_map);
        assert_eq!(path, "Banking");
    }

    #[test]
    fn test_compute_path_two_levels() {
        let items = [make_item("__ROOT__", "Root", None, true, false),
            make_item("folder1", "Banking", Some("__ROOT__"), true, false),
            make_item("folder2", "Credit Cards", Some("folder1"), true, false),
            make_item("item1", "Visa", Some("folder2"), false, false)];
        let items_map: HashMap<&str, &IWItem> = items.iter().map(|i| (i.item_id.as_str(), i)).collect();
        let path = compute_path(&items[3], &items_map);
        assert_eq!(path, "Banking / Credit Cards");
    }

    #[test]
    fn test_compute_path_missing_parent() {
        let items = [make_item("item1", "Entry", Some("nonexistent"), false, false)];
        let items_map: HashMap<&str, &IWItem> = items.iter().map(|i| (i.item_id.as_str(), i)).collect();
        let path = compute_path(&items[0], &items_map);
        assert_eq!(path, "");
    }

    #[test]
    fn test_compute_path_parent_cycle_terminates() {
        // a -> b -> a: a corrupt or crafted vault must not hang an export.
        let items = [make_item("a", "A", Some("b"), true, false),
            make_item("b", "B", Some("a"), true, false),
            make_item("item1", "Entry", Some("a"), false, false)];
        let items_map: HashMap<&str, &IWItem> = items.iter().map(|i| (i.item_id.as_str(), i)).collect();
        assert_eq!(compute_path(&items[2], &items_map), "B / A");
    }

    #[test]
    fn test_compute_path_self_parent_terminates() {
        let items = [make_item("a", "A", Some("a"), true, false),
            make_item("item1", "Entry", Some("a"), false, false)];
        let items_map: HashMap<&str, &IWItem> = items.iter().map(|i| (i.item_id.as_str(), i)).collect();
        assert_eq!(compute_path(&items[1], &items_map), "A");
        assert_eq!(compute_path(&items[0], &items_map), "");
    }

    #[test]
    fn test_generate_pdf_with_parent_cycle_terminates() {
        let items = vec![make_item("a", "A", Some("b"), true, false),
            make_item("b", "B", Some("a"), true, false),
            make_item("item1", "Entry", Some("a"), false, false)];
        assert!(generate_pdf(&items, &[]).unwrap().starts_with(b"%PDF"));
    }

    #[test]
    fn test_compute_path_no_parent() {
        let items = [make_item("item1", "Entry", None, false, false)];
        let items_map: HashMap<&str, &IWItem> = items.iter().map(|i| (i.item_id.as_str(), i)).collect();
        let path = compute_path(&items[0], &items_map);
        assert_eq!(path, "");
    }

    #[test]
    fn test_export_item_type_display() {
        assert_eq!(ExportItemType::Item.to_string(), "Item");
        assert_eq!(ExportItemType::Folder.to_string(), "Folder");
        assert_eq!(ExportItemType::Field.to_string(), "Field");
    }

    #[test]
    fn test_export_item_type_equality() {
        assert_eq!(ExportItemType::Item, ExportItemType::Item);
        assert_ne!(ExportItemType::Item, ExportItemType::Folder);
        assert_ne!(ExportItemType::Folder, ExportItemType::Field);
    }

    #[test]
    fn test_pdf_item_model_new() {
        let model = PDFItemModel::new("Test", "icon_test", ExportItemType::Item, "/path/");
        assert_eq!(model.name, "Test");
        assert_eq!(model.image, "icon_test");
        assert_eq!(model.item_type, ExportItemType::Item);
        assert_eq!(model.path, "/path/");
    }

    #[test]
    fn test_pdf_item_model_item() {
        let model = PDFItemModel::item("My Item", "document", "/Banking/");
        assert!(model.is_item());
        assert!(!model.is_folder());
        assert!(!model.is_field());
    }

    #[test]
    fn test_pdf_item_model_folder() {
        let model = PDFItemModel::folder("My Folder", "folder", "/");
        assert!(!model.is_item());
        assert!(model.is_folder());
        assert!(!model.is_field());
    }

    #[test]
    fn test_pdf_item_model_field() {
        let model = PDFItemModel::field("Email", "icon_mail", "/Banking/Visa/");
        assert!(!model.is_item());
        assert!(!model.is_folder());
        assert!(model.is_field());
    }

    #[test]
    fn test_pdf_item_model_serialization() {
        let model = PDFItemModel::item("Test", "icon", "/path/");
        let json = serde_json::to_string(&model).unwrap();
        assert!(json.contains("\"name\":\"Test\""));
        assert!(json.contains("\"item_type\":\"Item\""));

        let deserialized: PDFItemModel = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "Test");
        assert_eq!(deserialized.item_type, ExportItemType::Item);
    }

    #[test]
    fn test_export_item_type_serialization() {
        assert_eq!(serde_json::to_string(&ExportItemType::Item).unwrap(), "\"Item\"");
        assert_eq!(serde_json::to_string(&ExportItemType::Folder).unwrap(), "\"Folder\"");
        assert_eq!(serde_json::to_string(&ExportItemType::Field).unwrap(), "\"Field\"");
    }
}
