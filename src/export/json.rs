//! JSON export functionality
//!
//! Produces a single JSON document with all non-deleted items and fields.
//! Reuses the existing `IWItem` / `IWField` `Serialize` derives.

use serde::Serialize;

use crate::database::models::{IWField, IWItem};
use crate::error::{Result, WalletError};

const FORMAT: &str = "intelliwallet-export";
const VERSION: &str = "1";

#[derive(Serialize)]
struct JsonExport<'a> {
    format: &'static str,
    version: &'static str,
    exported_at: chrono::DateTime<chrono::Utc>,
    items: Vec<&'a IWItem>,
    fields: Vec<&'a IWField>,
}

/// Generate a pretty-printed JSON document from wallet items and fields.
pub fn generate_json(items: &[IWItem], fields: &[IWField]) -> Result<Vec<u8>> {
    let payload = JsonExport {
        format: FORMAT,
        version: VERSION,
        exported_at: chrono::Utc::now(),
        items: items.iter().filter(|i| !i.deleted).collect(),
        fields: fields.iter().filter(|f| !f.deleted).collect(),
    };

    serde_json::to_vec_pretty(&payload)
        .map_err(|e| WalletError::ExportError(format!("Failed to serialize JSON: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::Value;

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

    fn make_field(item_id: &str, field_id: &str, label: &str, value: &str, deleted: bool) -> IWField {
        IWField {
            item_id: item_id.to_string(),
            field_id: field_id.to_string(),
            field_type: "TEXT".to_string(),
            value: value.to_string(),
            label: label.to_string(),
            icon: "icon".to_string(),
            value_type: "text".to_string(),
            sort_weight: 0,
            change_timestamp: Utc::now(),
            deleted,
            expired: false,
            expiring: false,
        }
    }

    #[test]
    fn empty_export_is_valid_json_with_metadata() {
        let bytes = generate_json(&[], &[]).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["format"], "intelliwallet-export");
        assert_eq!(v["version"], "1");
        assert!(v["exported_at"].is_string());
        assert_eq!(v["items"].as_array().unwrap().len(), 0);
        assert_eq!(v["fields"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn deleted_entities_are_excluded() {
        let items = vec![
            make_item("a", "Alive", None, false, false),
            make_item("d", "Dead", None, false, true),
        ];
        let fields = vec![
            make_field("a", "f1", "Lbl", "v1", false),
            make_field("a", "f2", "Lbl2", "purged", true),
        ];
        let bytes = generate_json(&items, &fields).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["items"].as_array().unwrap().len(), 1);
        assert_eq!(v["items"][0]["item_id"], "a");
        assert_eq!(v["fields"].as_array().unwrap().len(), 1);
        assert_eq!(v["fields"][0]["field_id"], "f1");
    }

    #[test]
    fn unicode_values_round_trip() {
        let items = vec![make_item("a", "Почта", None, false, false)];
        let fields = vec![make_field("a", "f1", "Логин", "тест@mail.ru", false)];
        let bytes = generate_json(&items, &fields).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["items"][0]["name"], "Почта");
        assert_eq!(v["fields"][0]["value"], "тест@mail.ru");
    }
}
