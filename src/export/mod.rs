//! Export functionality for IntelliWallet
//!
//! This module provides data structures and utilities for exporting
//! wallet data to various formats (e.g., PDF).

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

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
