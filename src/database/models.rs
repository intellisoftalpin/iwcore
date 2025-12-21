//! Data models for IntelliWallet database entities

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Database properties and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IWProperties {
    /// Unique database identifier (32 chars)
    pub database_id: String,
    /// Language code (2 chars, e.g., "en", "de")
    pub lang: String,
    /// Database schema version
    pub version: String,
    /// Encryption iteration count (stored in 'email' field for legacy reasons)
    pub encryption_count: u32,
    /// Last sync timestamp
    pub sync_timestamp: Option<DateTime<Utc>>,
    /// Last update timestamp
    pub update_timestamp: Option<DateTime<Utc>>,
}

impl Default for IWProperties {
    fn default() -> Self {
        Self {
            database_id: String::new(),
            lang: "en".to_string(),
            version: crate::DB_VERSION.to_string(),
            encryption_count: crate::ENCRYPTION_COUNT_DEFAULT,
            sync_timestamp: None,
            update_timestamp: None,
        }
    }
}

/// Wallet item (folder or entry)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IWItem {
    /// Unique item ID (8 chars)
    pub item_id: String,
    /// Parent item ID (for hierarchy)
    pub parent_id: Option<String>,
    /// Decrypted item name
    pub name: String,
    /// Icon identifier
    pub icon: String,
    /// True if this is a folder, false if it's an entry
    pub folder: bool,
    /// Creation timestamp
    pub create_timestamp: DateTime<Utc>,
    /// Last modification timestamp
    pub change_timestamp: DateTime<Utc>,
    /// Soft delete flag
    pub deleted: bool,
}

impl IWItem {
    /// Check if this is the root item
    pub fn is_root(&self) -> bool {
        self.item_id == crate::ROOT_ID
    }
}

/// Field attached to an item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IWField {
    /// Parent item ID
    pub item_id: String,
    /// Field ID (4 chars)
    pub field_id: String,
    /// Field type code (e.g., "MAIL", "PASS")
    pub field_type: String,
    /// Decrypted field value
    pub value: String,
    /// Display label (from labels table)
    pub label: String,
    /// Icon identifier
    pub icon: String,
    /// Value type (e.g., "text", "pass", "date")
    pub value_type: String,
    /// Sort order weight
    pub sort_weight: i32,
    /// Last modification timestamp
    pub change_timestamp: DateTime<Utc>,
    /// Soft delete flag
    pub deleted: bool,
    /// True if this field has expired (for expiry date fields)
    pub expired: bool,
    /// True if this field is expiring soon
    pub expiring: bool,
}

/// Field type label definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IWLabel {
    /// Field type code (e.g., "MAIL", "PASS")
    pub field_type: String,
    /// Display name
    pub name: String,
    /// Value type (e.g., "text", "pass", "date")
    pub value_type: String,
    /// Icon identifier
    pub icon: String,
    /// True if this is a system-defined label
    pub system: bool,
    /// Last modification timestamp
    pub change_timestamp: DateTime<Utc>,
    /// Soft delete flag
    pub deleted: bool,
    /// Usage count (how many fields use this label)
    pub usage: u32,
}

/// Icon metadata (blob storage removed - only names)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IWIcon {
    /// Icon ID
    pub icon_id: String,
    /// Icon name/description
    pub name: String,
    /// Group ID
    pub group_id: i32,
    /// True if icon should be displayed as circle
    pub is_circle: bool,
    /// Soft delete flag
    pub deleted: bool,
}

/// Icon group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IWGroup {
    /// Group ID
    pub group_id: i32,
    /// Group name
    pub name: String,
    /// Soft delete flag
    pub deleted: bool,
}

/// Search result item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// The item that matched
    pub item: IWItem,
    /// Matching fields (if search matched field content)
    pub matching_fields: Vec<IWField>,
    /// Match type (name match, field match, or both)
    pub match_type: SearchMatchType,
}

/// Type of search match
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SearchMatchType {
    /// Match found in item name
    Name,
    /// Match found in field value
    Field,
    /// Match found in both name and field
    Both,
}

/// System field types with their metadata
pub const SYSTEM_FIELD_TYPES: &[(&str, &str, &str, &str)] = &[
    // (field_type, value_type, icon, label_key)
    ("MAIL", "mail", "icon_mail", "label_email"),
    ("PASS", "pass", "icon_pass", "label_password"),
    ("NOTE", "text", "icon_note", "label_note"),
    ("LINK", "link", "icon_link", "label_link"),
    ("ACNT", "text", "icon_account", "label_account"),
    ("CARD", "text", "icon_card", "label_card"),
    ("NAME", "text", "icon_name", "label_name"),
    ("PHON", "phon", "icon_phone", "label_phone"),
    ("PINC", "pass", "icon_pin", "label_pin"),
    ("USER", "text", "icon_user", "label_username"),
    ("OLDP", "pass", "icon_oldpass", "label_old_password"),
    ("DATE", "date", "icon_date", "label_date"),
    ("TIME", "time", "icon_time", "label_time"),
    ("EXPD", "date", "icon_expiry", "label_expiry_date"),
    ("SNUM", "text", "icon_serial", "label_serial_number"),
    ("ADDR", "text", "icon_address", "label_address"),
    ("SQUE", "text", "icon_question", "label_secret_question"),
    ("SANS", "pass", "icon_answer", "label_secret_answer"),
    ("2FAC", "pass", "icon_2fa", "label_2fa"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_properties_default() {
        let props = IWProperties::default();
        assert_eq!(props.lang, "en");
        assert_eq!(props.version, crate::DB_VERSION);
        assert_eq!(props.encryption_count, crate::ENCRYPTION_COUNT_DEFAULT);
        assert!(props.database_id.is_empty());
        assert!(props.sync_timestamp.is_none());
        assert!(props.update_timestamp.is_none());
    }

    #[test]
    fn test_item_is_root() {
        let root_item = IWItem {
            item_id: crate::ROOT_ID.to_string(),
            parent_id: None,
            name: "Root".to_string(),
            icon: "folder".to_string(),
            folder: true,
            create_timestamp: Utc::now(),
            change_timestamp: Utc::now(),
            deleted: false,
        };
        assert!(root_item.is_root());

        let regular_item = IWItem {
            item_id: "abc12345".to_string(),
            parent_id: Some(crate::ROOT_ID.to_string()),
            name: "Test".to_string(),
            icon: "document".to_string(),
            folder: false,
            create_timestamp: Utc::now(),
            change_timestamp: Utc::now(),
            deleted: false,
        };
        assert!(!regular_item.is_root());
    }

    #[test]
    fn test_search_match_type() {
        assert_eq!(SearchMatchType::Name, SearchMatchType::Name);
        assert_eq!(SearchMatchType::Field, SearchMatchType::Field);
        assert_eq!(SearchMatchType::Both, SearchMatchType::Both);
        assert_ne!(SearchMatchType::Name, SearchMatchType::Field);
    }

    #[test]
    fn test_system_field_types_count() {
        assert_eq!(SYSTEM_FIELD_TYPES.len(), 19);
    }
}
