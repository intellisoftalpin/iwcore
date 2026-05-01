//! CSV export functionality
//!
//! Produces an RFC 4180 CSV with one row per non-deleted field, including
//! the parent item's id/name/path/folder flag as context columns.
//! Items with no fields still get one row (empty field columns).

use std::collections::HashMap;

use crate::database::models::{IWField, IWItem};
use crate::error::Result;

const HEADER: &str = "item_id,item_name,item_path,item_is_folder,field_id,field_type,field_label,field_value,field_value_type,field_sort_weight,field_change_timestamp\n";

/// Generate a CSV document from wallet items and fields.
pub fn generate_csv(items: &[IWItem], fields: &[IWField]) -> Result<Vec<u8>> {
    let items_map: HashMap<&str, &IWItem> = items
        .iter()
        .map(|item| (item.item_id.as_str(), item))
        .collect();

    let mut fields_by_item: HashMap<&str, Vec<&IWField>> = HashMap::new();
    for field in fields {
        if !field.deleted {
            fields_by_item
                .entry(field.item_id.as_str())
                .or_default()
                .push(field);
        }
    }
    for v in fields_by_item.values_mut() {
        v.sort_by_key(|f| f.sort_weight);
    }

    let mut out = String::new();
    out.push_str(HEADER);

    let mut entries: Vec<&IWItem> = items.iter().filter(|i| !i.deleted).collect();
    entries.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    for item in entries {
        let path = compute_path(item, &items_map);
        let item_cols = format!(
            "{},{},{},{}",
            csv_escape(&item.item_id),
            csv_escape(&item.name),
            csv_escape(&path),
            item.folder,
        );
        match fields_by_item.get(item.item_id.as_str()) {
            Some(item_fields) if !item_fields.is_empty() => {
                for f in item_fields {
                    out.push_str(&item_cols);
                    out.push(',');
                    out.push_str(&csv_escape(&f.field_id));
                    out.push(',');
                    out.push_str(&csv_escape(&f.field_type));
                    out.push(',');
                    out.push_str(&csv_escape(&f.label));
                    out.push(',');
                    out.push_str(&csv_escape(&f.value));
                    out.push(',');
                    out.push_str(&csv_escape(&f.value_type));
                    out.push(',');
                    out.push_str(&f.sort_weight.to_string());
                    out.push(',');
                    out.push_str(&csv_escape(&f.change_timestamp.to_rfc3339()));
                    out.push('\n');
                }
            }
            _ => {
                out.push_str(&item_cols);
                out.push_str(",,,,,,,\n");
            }
        }
    }

    Ok(out.into_bytes())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        s.to_string()
    }
}

fn compute_path(item: &IWItem, items_map: &HashMap<&str, &IWItem>) -> String {
    let mut parts = Vec::new();
    let mut cur = item.parent_id.as_deref();
    while let Some(pid) = cur {
        if pid == crate::ROOT_ID {
            break;
        }
        if let Some(parent) = items_map.get(pid) {
            parts.push(parent.name.clone());
            cur = parent.parent_id.as_deref();
        } else {
            break;
        }
    }
    parts.reverse();
    parts.join(" / ")
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn empty_export_only_contains_header() {
        let bytes = generate_csv(&[], &[]).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, HEADER);
    }

    #[test]
    fn single_item_with_fields_generates_one_row_per_field() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("entry1", "Gmail", Some("__ROOT__"), false, false),
        ];
        let fields = vec![
            make_field("entry1", "f1", "Email", "user@gmail.com", 0, false),
            make_field("entry1", "f2", "Password", "secret123", 1, false),
        ];
        let s = String::from_utf8(generate_csv(&items, &fields).unwrap()).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        // header + root row (no fields) + 2 entry rows
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("item_id,"));
        assert!(s.contains("user@gmail.com"));
        assert!(s.contains("secret123"));
    }

    #[test]
    fn deleted_items_and_fields_are_skipped() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("active", "Active", Some("__ROOT__"), false, false),
            make_item("gone", "Gone", Some("__ROOT__"), false, true),
        ];
        let fields = vec![
            make_field("active", "f1", "User", "alive", 0, false),
            make_field("active", "f2", "Old", "purged", 1, true),
            make_field("gone", "f3", "User", "ghost", 0, false),
        ];
        let s = String::from_utf8(generate_csv(&items, &fields).unwrap()).unwrap();
        assert!(s.contains("alive"));
        assert!(!s.contains("purged"));
        assert!(!s.contains("ghost"));
        assert!(!s.contains("Gone"));
    }

    #[test]
    fn values_with_commas_and_quotes_are_quoted_and_escaped() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("entry1", "Tricky, Name", Some("__ROOT__"), false, false),
        ];
        let fields = vec![
            make_field("entry1", "f1", "Note", "He said \"hi\", then left.", 0, false),
            make_field("entry1", "f2", "Multi", "line1\nline2", 1, false),
        ];
        let s = String::from_utf8(generate_csv(&items, &fields).unwrap()).unwrap();
        assert!(s.contains("\"Tricky, Name\""));
        assert!(s.contains("\"He said \"\"hi\"\", then left.\""));
        assert!(s.contains("\"line1\nline2\""));
    }

    #[test]
    fn item_path_reflects_folder_hierarchy() {
        let items = vec![
            make_item("__ROOT__", "Root", None, true, false),
            make_item("folder1", "Banking", Some("__ROOT__"), true, false),
            make_item("folder2", "Cards", Some("folder1"), true, false),
            make_item("entry1", "Visa", Some("folder2"), false, false),
        ];
        let s = String::from_utf8(generate_csv(&items, &[]).unwrap()).unwrap();
        assert!(s.contains("Banking / Cards"));
    }
}
