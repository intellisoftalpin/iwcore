//! XML export functionality
//!
//! Produces a UTF-8 XML document with all non-deleted items as elements,
//! each containing its non-deleted fields. Field values go in element
//! text content (so multi-line values aren't normalized away by attribute
//! parsing rules).

use std::collections::HashMap;

use crate::database::models::{IWField, IWItem};
use crate::error::Result;

const VERSION: &str = "1";

/// Generate an XML document from wallet items and fields.
pub fn generate_xml(items: &[IWItem], fields: &[IWField]) -> Result<Vec<u8>> {
    let mut fields_by_item: HashMap<&str, Vec<&IWField>> = HashMap::new();
    for f in fields {
        if !f.deleted {
            fields_by_item.entry(f.item_id.as_str()).or_default().push(f);
        }
    }
    for v in fields_by_item.values_mut() {
        v.sort_by_key(|f| f.sort_weight);
    }

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<intelliwallet version=\"{}\" exported_at=\"{}\">\n",
        VERSION,
        xml_escape_attr(&chrono::Utc::now().to_rfc3339()),
    ));
    out.push_str("  <items>\n");

    let mut entries: Vec<&IWItem> = items.iter().filter(|i| !i.deleted).collect();
    entries.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    for item in entries {
        let parent_attr = item.parent_id.as_deref().unwrap_or("");
        out.push_str(&format!(
            "    <item id=\"{}\" name=\"{}\" parent_id=\"{}\" folder=\"{}\" icon=\"{}\" change_timestamp=\"{}\">\n",
            xml_escape_attr(&item.item_id),
            xml_escape_attr(&item.name),
            xml_escape_attr(parent_attr),
            item.folder,
            xml_escape_attr(&item.icon),
            xml_escape_attr(&item.change_timestamp.to_rfc3339()),
        ));
        if let Some(item_fields) = fields_by_item.get(item.item_id.as_str()) {
            for f in item_fields {
                out.push_str(&format!(
                    "      <field id=\"{}\" type=\"{}\" label=\"{}\" value_type=\"{}\" sort_weight=\"{}\">{}</field>\n",
                    xml_escape_attr(&f.field_id),
                    xml_escape_attr(&f.field_type),
                    xml_escape_attr(&f.label),
                    xml_escape_attr(&f.value_type),
                    f.sort_weight,
                    xml_escape_text(&f.value),
                ));
            }
        }
        out.push_str("    </item>\n");
    }

    out.push_str("  </items>\n");
    out.push_str("</intelliwallet>\n");
    Ok(out.into_bytes())
}

fn xml_escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
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
    fn empty_export_has_well_formed_root() {
        let bytes = generate_xml(&[], &[]).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert!(s.contains("<intelliwallet version=\"1\""));
        assert!(s.contains("<items>"));
        assert!(s.contains("</items>"));
        assert!(s.trim_end().ends_with("</intelliwallet>"));
    }

    #[test]
    fn deleted_entities_are_skipped() {
        let items = vec![
            make_item("a", "Alive", None, false, false),
            make_item("d", "Dead", None, false, true),
        ];
        let fields = vec![
            make_field("a", "f1", "Lbl", "v1", false),
            make_field("a", "f2", "Lbl2", "purged", true),
        ];
        let s = String::from_utf8(generate_xml(&items, &fields).unwrap()).unwrap();
        assert!(s.contains("name=\"Alive\""));
        assert!(!s.contains("Dead"));
        assert!(s.contains(">v1<"));
        assert!(!s.contains("purged"));
    }

    #[test]
    fn special_characters_are_escaped() {
        let items = vec![
            make_item("a", "<Tag & \"quote\">", None, false, false),
        ];
        let fields = vec![
            make_field("a", "f1", "Note", "if a < b && c > d", false),
        ];
        let s = String::from_utf8(generate_xml(&items, &fields).unwrap()).unwrap();
        assert!(s.contains("name=\"&lt;Tag &amp; &quot;quote&quot;&gt;\""));
        assert!(s.contains(">if a &lt; b &amp;&amp; c &gt; d<"));
    }

    #[test]
    fn unicode_passes_through() {
        let items = vec![make_item("a", "Почта", None, false, false)];
        let fields = vec![make_field("a", "f1", "Логин", "тест@mail.ru", false)];
        let s = String::from_utf8(generate_xml(&items, &fields).unwrap()).unwrap();
        assert!(s.contains("name=\"Почта\""));
        assert!(s.contains(">тест@mail.ru<"));
    }
}
