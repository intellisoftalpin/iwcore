//! SQL query operations for database access
//!
//! This module provides low-level query functions for database operations.
//! For business-level operations, use the Wallet API.

use rusqlite::{Connection, params};
use chrono::{DateTime, Utc};
use crate::error::Result;

/// Timestamp format used in database
pub const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

/// Format a DateTime for database storage
pub fn format_timestamp(dt: &DateTime<Utc>) -> String {
    dt.format(TIMESTAMP_FORMAT).to_string()
}

/// Parse a timestamp from database
pub fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    chrono::NaiveDateTime::parse_from_str(s, TIMESTAMP_FORMAT)
        .ok()
        .map(|ndt| DateTime::from_naive_utc_and_offset(ndt, Utc))
}

/// Get current timestamp formatted for database
pub fn now_timestamp() -> String {
    format_timestamp(&Utc::now())
}

// ============================================================================
// Properties queries
// ============================================================================

/// Get database ID from properties
pub fn get_database_id(conn: &Connection) -> Result<Option<String>> {
    let result = conn.query_row(
        "SELECT database_id FROM nswallet_properties LIMIT 1",
        [],
        |row| row.get(0),
    );
    Ok(result.ok())
}

/// Check if properties table has any rows
pub fn has_properties(conn: &Connection) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_properties",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Get all properties from the database
pub fn get_properties(conn: &Connection) -> Result<Option<RawProperties>> {
    let result = conn.query_row(
        "SELECT database_id, lang, version, email, sync_timestamp, update_timestamp
         FROM nswallet_properties LIMIT 1",
        [],
        |row| {
            Ok(RawProperties {
                database_id: row.get(0)?,
                lang: row.get(1)?,
                version: row.get(2)?,
                email: row.get(3)?,
                sync_timestamp: row.get(4)?,
                update_timestamp: row.get(5)?,
            })
        },
    );
    Ok(result.ok())
}

/// Set properties (insert new row)
pub fn set_properties(
    conn: &Connection,
    database_id: &str,
    lang: &str,
    version: &str,
    encryption_count: u32,
) -> Result<()> {
    conn.execute(
        "INSERT INTO nswallet_properties (database_id, lang, version, email, sync_timestamp, update_timestamp)
         VALUES (?, ?, ?, ?, ?, ?)",
        params![database_id, lang, version, encryption_count.to_string(), now_timestamp(), now_timestamp()],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Update database version
pub fn set_db_version(conn: &Connection, version: &str) -> Result<()> {
    conn.execute(
        "UPDATE nswallet_properties SET version = ?, update_timestamp = ?",
        params![version, now_timestamp()],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

// ============================================================================
// Items queries
// ============================================================================

/// Get all items from database (encrypted)
pub fn get_all_items_raw(conn: &Connection) -> Result<Vec<RawItem>> {
    let mut stmt = conn.prepare(
        "SELECT item_id, parent_id, name, icon, folder, create_timestamp, change_timestamp, deleted
         FROM nswallet_items WHERE deleted = 0"
    )?;

    let items = stmt.query_map([], |row| {
        Ok(RawItem {
            item_id: row.get(0)?,
            parent_id: row.get(1)?,
            name_encrypted: row.get(2)?,
            icon: row.get(3)?,
            folder: row.get::<_, i32>(4)? != 0,
            create_timestamp: row.get(5)?,
            change_timestamp: row.get(6)?,
            deleted: row.get::<_, i32>(7)? != 0,
        })
    })?;

    items.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

/// Get root item (encrypted name)
pub fn get_root_item_raw(conn: &Connection) -> Result<Option<Vec<u8>>> {
    let result = conn.query_row(
        "SELECT name FROM nswallet_items WHERE item_id = '__ROOT__'",
        [],
        |row| row.get(0),
    );
    Ok(result.ok())
}

/// Check if root item exists
pub fn has_root_item(conn: &Connection) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_items WHERE item_id = '__ROOT__'",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Create a new item
pub fn create_item(
    conn: &Connection,
    item_id: &str,
    parent_id: &str,
    name_encrypted: &[u8],
    icon: &str,
    folder: bool,
) -> Result<()> {
    let now = now_timestamp();
    conn.execute(
        "INSERT INTO nswallet_items (item_id, parent_id, name, icon, folder, create_timestamp, change_timestamp, deleted)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
        params![item_id, parent_id, name_encrypted, icon, folder as i32, now, now],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Update item name (encrypted)
pub fn update_item_name(conn: &Connection, item_id: &str, name_encrypted: &[u8]) -> Result<()> {
    conn.execute(
        "UPDATE nswallet_items SET name = ?, change_timestamp = ? WHERE item_id = ?",
        params![name_encrypted, now_timestamp(), item_id],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Update item icon
pub fn update_item_icon(conn: &Connection, item_id: &str, icon: &str) -> Result<()> {
    conn.execute(
        "UPDATE nswallet_items SET icon = ?, change_timestamp = ? WHERE item_id = ?",
        params![icon, now_timestamp(), item_id],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Update item parent (move item)
pub fn update_item_parent(conn: &Connection, item_id: &str, parent_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE nswallet_items SET parent_id = ?, change_timestamp = ? WHERE item_id = ?",
        params![parent_id, now_timestamp(), item_id],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Soft delete an item and cascade to its fields
pub fn delete_item(conn: &Connection, item_id: &str) -> Result<()> {
    let now = now_timestamp();
    conn.execute(
        "UPDATE nswallet_items SET deleted = 1, change_timestamp = ? WHERE item_id = ?",
        params![now, item_id],
    )?;
    conn.execute(
        "UPDATE nswallet_fields SET deleted = 1, change_timestamp = ? WHERE item_id = ? AND deleted = 0",
        params![now, item_id],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Get all soft-deleted items from database (encrypted)
pub fn get_deleted_items_raw(conn: &Connection) -> Result<Vec<RawItem>> {
    let mut stmt = conn.prepare(
        "SELECT item_id, parent_id, name, COALESCE(icon, ''), folder, create_timestamp, change_timestamp, deleted
         FROM nswallet_items WHERE deleted = 1"
    )?;

    let items = stmt.query_map([], |row| {
        Ok(RawItem {
            item_id: row.get(0)?,
            parent_id: row.get(1)?,
            name_encrypted: row.get(2)?,
            icon: row.get(3)?,
            folder: row.get::<_, i32>(4)? != 0,
            create_timestamp: row.get(5)?,
            change_timestamp: row.get(6)?,
            deleted: row.get::<_, i32>(7)? != 0,
        })
    })?;

    items.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

/// Undelete an item (set deleted = 0, move to root)
pub fn undelete_item(conn: &Connection, item_id: &str) -> Result<()> {
    let rows = conn.execute(
        "UPDATE nswallet_items SET deleted = 0, parent_id = '__ROOT__', change_timestamp = ? WHERE item_id = ? AND deleted = 1",
        params![now_timestamp(), item_id],
    )?;
    if rows == 0 {
        return Err(crate::error::WalletError::ItemNotFound(item_id.to_string()));
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Soft-delete all descendants of a folder using recursive CTE, including their fields
pub fn delete_item_descendants(conn: &Connection, item_id: &str) -> Result<()> {
    let now = now_timestamp();
    conn.execute(
        "WITH RECURSIVE descendants(id) AS (
            SELECT item_id FROM nswallet_items WHERE parent_id = ?1 AND deleted = 0
            UNION ALL
            SELECT i.item_id FROM nswallet_items i JOIN descendants d ON i.parent_id = d.id WHERE i.deleted = 0
        )
        UPDATE nswallet_items SET deleted = 1, change_timestamp = ?2 WHERE item_id IN (SELECT id FROM descendants)",
        params![item_id, now],
    )?;
    conn.execute(
        "WITH RECURSIVE descendants(id) AS (
            SELECT item_id FROM nswallet_items WHERE parent_id = ?1
            UNION ALL
            SELECT i.item_id FROM nswallet_items i JOIN descendants d ON i.parent_id = d.id
        )
        UPDATE nswallet_fields SET deleted = 1, change_timestamp = ?2 WHERE item_id IN (SELECT id FROM descendants) AND deleted = 0",
        params![item_id, now],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Update item name without timestamp (for password change)
pub fn update_item_name_only(conn: &Connection, item_id: &str, name_encrypted: &[u8]) -> Result<()> {
    conn.execute(
        "UPDATE nswallet_items SET name = ? WHERE item_id = ?",
        params![name_encrypted, item_id],
    )?;
    Ok(())
}

// ============================================================================
// Fields queries
// ============================================================================

/// Get all fields from database (encrypted)
pub fn get_all_fields_raw(conn: &Connection) -> Result<Vec<RawField>> {
    let mut stmt = conn.prepare(
        "SELECT item_id, field_id, type, value, change_timestamp, deleted, sort_weight
         FROM nswallet_fields WHERE deleted = 0"
    )?;

    let fields = stmt.query_map([], |row| {
        Ok(RawField {
            item_id: row.get(0)?,
            field_id: row.get(1)?,
            field_type: row.get(2)?,
            value_encrypted: row.get(3)?,
            change_timestamp: row.get(4)?,
            deleted: row.get::<_, i32>(5)? != 0,
            sort_weight: row.get(6)?,
        })
    })?;

    fields.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

/// Create a new field
pub fn create_field(
    conn: &Connection,
    item_id: &str,
    field_id: &str,
    field_type: &str,
    value_encrypted: &[u8],
    sort_weight: i32,
) -> Result<()> {
    conn.execute(
        "INSERT INTO nswallet_fields (item_id, field_id, type, value, change_timestamp, deleted, sort_weight)
         VALUES (?, ?, ?, ?, ?, 0, ?)",
        params![item_id, field_id, field_type, value_encrypted, now_timestamp(), sort_weight],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Update field value (encrypted)
pub fn update_field(
    conn: &Connection,
    field_id: &str,
    value_encrypted: &[u8],
    sort_weight: Option<i32>,
) -> Result<()> {
    if let Some(weight) = sort_weight {
        conn.execute(
            "UPDATE nswallet_fields SET value = ?, sort_weight = ?, change_timestamp = ? WHERE field_id = ?",
            params![value_encrypted, weight, now_timestamp(), field_id],
        )?;
    } else {
        conn.execute(
            "UPDATE nswallet_fields SET value = ?, change_timestamp = ? WHERE field_id = ?",
            params![value_encrypted, now_timestamp(), field_id],
        )?;
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Soft delete a field
pub fn delete_field(conn: &Connection, item_id: &str, field_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE nswallet_fields SET deleted = 1, change_timestamp = ? WHERE item_id = ? AND field_id = ?",
        params![now_timestamp(), item_id, field_id],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Update field value only (for password change)
pub fn update_field_value_only(conn: &Connection, item_id: &str, field_id: &str, value_encrypted: &[u8]) -> Result<()> {
    conn.execute(
        "UPDATE nswallet_fields SET value = ? WHERE item_id = ? AND field_id = ?",
        params![value_encrypted, item_id, field_id],
    )?;
    Ok(())
}

/// Get all soft-deleted fields from database (encrypted)
pub fn get_deleted_fields_raw(conn: &Connection) -> Result<Vec<RawField>> {
    let mut stmt = conn.prepare(
        "SELECT item_id, field_id, type, value, change_timestamp, deleted, sort_weight
         FROM nswallet_fields WHERE deleted = 1"
    )?;

    let fields = stmt.query_map([], |row| {
        Ok(RawField {
            item_id: row.get(0)?,
            field_id: row.get(1)?,
            field_type: row.get(2)?,
            value_encrypted: row.get(3)?,
            change_timestamp: row.get(4)?,
            deleted: row.get::<_, i32>(5)? != 0,
            sort_weight: row.get(6)?,
        })
    })?;

    fields.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

/// Undelete a field (set deleted = 0)
pub fn undelete_field(conn: &Connection, item_id: &str, field_id: &str) -> Result<()> {
    let rows = conn.execute(
        "UPDATE nswallet_fields SET deleted = 0, change_timestamp = ? WHERE item_id = ? AND field_id = ? AND deleted = 1",
        params![now_timestamp(), item_id, field_id],
    )?;
    if rows == 0 {
        return Err(crate::error::WalletError::FieldNotFound(field_id.to_string()));
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Permanently purge all soft-deleted records.
/// Returns (purged_items_count, purged_fields_count).
pub fn purge_deleted(conn: &Connection) -> Result<(u32, u32)> {
    // Count before deleting
    let items_count: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_items WHERE deleted = 1",
        [],
        |row| row.get(0),
    )?;

    // Count deleted fields + orphaned fields (fields belonging to deleted items)
    let fields_count: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_fields WHERE deleted = 1 OR item_id IN (SELECT item_id FROM nswallet_items WHERE deleted = 1)",
        [],
        |row| row.get(0),
    )?;

    // Delete orphaned fields first (fields belonging to deleted items)
    conn.execute(
        "DELETE FROM nswallet_fields WHERE item_id IN (SELECT item_id FROM nswallet_items WHERE deleted = 1)",
        [],
    )?;

    // Delete soft-deleted fields
    conn.execute(
        "DELETE FROM nswallet_fields WHERE deleted = 1",
        [],
    )?;

    // Delete soft-deleted items
    conn.execute(
        "DELETE FROM nswallet_items WHERE deleted = 1",
        [],
    )?;

    // Delete soft-deleted labels
    conn.execute(
        "DELETE FROM nswallet_labels WHERE deleted = 1",
        [],
    )?;

    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;

    Ok((items_count, fields_count))
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    /// Active items (excluding root)
    pub total_items: u32,
    /// Active folders
    pub total_folders: u32,
    /// Active fields
    pub total_fields: u32,
    /// All labels (system + custom)
    pub total_labels: u32,
    /// User-created labels only
    pub custom_labels: u32,
    /// Soft-deleted items
    pub deleted_items: u32,
    /// Soft-deleted fields
    pub deleted_fields: u32,
    /// Database file size in bytes
    pub file_size_bytes: u64,
}

/// Get database statistics (counts of items, fields, labels, deleted records)
pub fn get_database_stats(conn: &Connection) -> Result<DatabaseStats> {
    let total_items: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_items WHERE deleted = 0 AND item_id != '__ROOT__' AND folder = 0",
        [],
        |row| row.get(0),
    )?;
    let total_folders: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_items WHERE deleted = 0 AND item_id != '__ROOT__' AND folder = 1",
        [],
        |row| row.get(0),
    )?;
    let total_fields: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_fields WHERE deleted = 0",
        [],
        |row| row.get(0),
    )?;
    let total_labels: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_labels WHERE deleted = 0",
        [],
        |row| row.get(0),
    )?;
    let custom_labels: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_labels WHERE deleted = 0 AND system = 0",
        [],
        |row| row.get(0),
    )?;
    let deleted_items: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_items WHERE deleted = 1",
        [],
        |row| row.get(0),
    )?;
    let deleted_fields: u32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_fields WHERE deleted = 1",
        [],
        |row| row.get(0),
    )?;

    Ok(DatabaseStats {
        total_items,
        total_folders,
        total_fields,
        total_labels,
        custom_labels,
        deleted_items,
        deleted_fields,
        file_size_bytes: 0, // Caller sets this from file metadata
    })
}

/// Get a single active field's raw data by field_id
pub fn get_field_raw_by_id(conn: &Connection, field_id: &str) -> Result<Option<RawField>> {
    let result = conn.query_row(
        "SELECT item_id, field_id, type, value, change_timestamp, deleted, sort_weight
         FROM nswallet_fields WHERE field_id = ? AND deleted = 0",
        params![field_id],
        |row| {
            Ok(RawField {
                item_id: row.get(0)?,
                field_id: row.get(1)?,
                field_type: row.get(2)?,
                value_encrypted: row.get(3)?,
                change_timestamp: row.get(4)?,
                deleted: row.get::<_, i32>(5)? != 0,
                sort_weight: row.get(6)?,
            })
        },
    );
    Ok(result.ok())
}

/// Get the OLDP field_id for a given item
pub fn get_oldp_field_id(conn: &Connection, item_id: &str) -> Result<Option<String>> {
    let result = conn.query_row(
        "SELECT field_id FROM nswallet_fields WHERE item_id = ? AND type = 'OLDP' AND deleted = 0",
        params![item_id],
        |row| row.get(0),
    );
    Ok(result.ok())
}

/// Get max sort weight for an item's fields
pub fn get_max_field_weight(conn: &Connection, item_id: &str) -> Result<i32> {
    let result: Option<i32> = conn.query_row(
        "SELECT MAX(sort_weight) FROM nswallet_fields WHERE item_id = ? AND deleted = 0",
        params![item_id],
        |row| row.get(0),
    ).ok().flatten();
    Ok(result.unwrap_or(0))
}

// ============================================================================
// Labels queries
// ============================================================================

/// Get all labels from database (with usage count)
pub fn get_all_labels(conn: &Connection) -> Result<Vec<RawLabel>> {
    let mut stmt = conn.prepare(
        "SELECT l.field_type, l.label_name, l.value_type, l.icon, l.system, l.change_timestamp, l.deleted,
                COALESCE((SELECT COUNT(*) FROM nswallet_fields f WHERE f.type = l.field_type AND f.deleted = 0), 0) as usage
         FROM nswallet_labels l WHERE l.deleted = 0"
    )?;

    let labels = stmt.query_map([], |row| {
        Ok(RawLabel {
            field_type: row.get(0)?,
            label_name: row.get(1)?,
            value_type: row.get(2)?,
            icon: row.get(3)?,
            system: row.get::<_, i32>(4)? != 0,
            change_timestamp: row.get(5)?,
            deleted: row.get::<_, i32>(6)? != 0,
            usage: row.get(7)?,
        })
    })?;

    labels.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

/// Create a new label
pub fn create_label(
    conn: &Connection,
    field_type: &str,
    label_name: &str,
    value_type: &str,
    icon: &str,
    system: bool,
) -> Result<bool> {
    let result = conn.execute(
        "INSERT OR IGNORE INTO nswallet_labels (field_type, label_name, value_type, icon, system, change_timestamp, deleted)
         VALUES (?, ?, ?, ?, ?, ?, 0)",
        params![field_type, label_name, value_type, icon, system as i32, now_timestamp()],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(result > 0)
}

/// Update label name
pub fn update_label_name(conn: &Connection, field_type: &str, label_name: &str) -> Result<()> {
    conn.execute(
        "UPDATE nswallet_labels SET label_name = ?, change_timestamp = ? WHERE field_type = ?",
        params![label_name, now_timestamp(), field_type],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Update label icon
pub fn update_label_icon(conn: &Connection, field_type: &str, icon: &str) -> Result<()> {
    conn.execute(
        "UPDATE nswallet_labels SET icon = ?, change_timestamp = ? WHERE field_type = ?",
        params![icon, now_timestamp(), field_type],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

/// Soft delete a label (returns count of fields using it)
pub fn delete_label(conn: &Connection, field_type: &str) -> Result<i32> {
    // Count fields using this label
    let count: i32 = conn.query_row(
        "SELECT COUNT(*) FROM nswallet_fields WHERE type = ? AND deleted = 0",
        params![field_type],
        |row| row.get(0),
    )?;

    if count == 0 {
        conn.execute(
            "UPDATE nswallet_labels SET deleted = 1, change_timestamp = ? WHERE field_type = ?",
            params![now_timestamp(), field_type],
        )?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    }

    Ok(count)
}

/// Permanently delete a label
pub fn remove_label_for_real(conn: &Connection, field_type: &str) -> Result<bool> {
    let result = conn.execute(
        "DELETE FROM nswallet_labels WHERE field_type = ?",
        params![field_type],
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(result > 0)
}

// ============================================================================
// Raw data structures (before decryption)
// ============================================================================

/// Raw properties data from database
#[derive(Debug, Clone)]
pub struct RawProperties {
    /// Unique database identifier
    pub database_id: String,
    /// Database language code (e.g. "en", "de")
    pub lang: String,
    /// Database schema version
    pub version: String,
    /// Encryption iteration count (stored in the legacy `email` column)
    pub email: String,
    /// Last cloud sync timestamp
    pub sync_timestamp: Option<String>,
    /// Last local update timestamp
    pub update_timestamp: Option<String>,
}

/// Raw item data from database (before decryption)
#[derive(Debug, Clone)]
pub struct RawItem {
    /// Unique item identifier
    pub item_id: String,
    /// Parent item/folder ID (`None` for root-level items)
    pub parent_id: Option<String>,
    /// AES-256 encrypted item name
    pub name_encrypted: Vec<u8>,
    /// Icon identifier
    pub icon: String,
    /// Whether this item is a folder
    pub folder: bool,
    /// Creation timestamp
    pub create_timestamp: Option<String>,
    /// Last modification timestamp
    pub change_timestamp: Option<String>,
    /// Whether this item is soft-deleted
    pub deleted: bool,
}

/// Raw field data from database (before decryption)
#[derive(Debug, Clone)]
pub struct RawField {
    /// Parent item ID
    pub item_id: String,
    /// Unique field identifier
    pub field_id: String,
    /// Field type code (e.g. "MAIL", "PASS", "NOTE")
    pub field_type: String,
    /// AES-256 encrypted field value
    pub value_encrypted: Vec<u8>,
    /// Last modification timestamp
    pub change_timestamp: Option<String>,
    /// Whether this field is soft-deleted
    pub deleted: bool,
    /// Display ordering weight
    pub sort_weight: Option<i32>,
}

/// Raw label data from database
#[derive(Debug, Clone)]
pub struct RawLabel {
    /// Label type code (e.g. "MAIL", "PASS")
    pub field_type: String,
    /// Human-readable label name
    pub label_name: String,
    /// Value type hint (e.g. "text", "password", "email")
    pub value_type: String,
    /// Icon identifier
    pub icon: String,
    /// Whether this is a built-in system label
    pub system: bool,
    /// Last modification timestamp
    pub change_timestamp: Option<String>,
    /// Whether this label is soft-deleted
    pub deleted: bool,
    /// Number of fields using this label
    pub usage: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Datelike, Timelike};

    #[test]
    fn test_format_timestamp() {
        let dt = Utc.with_ymd_and_hms(2023, 12, 15, 10, 30, 45).unwrap();
        assert_eq!(format_timestamp(&dt), "2023-12-15 10:30:45");
    }

    #[test]
    fn test_parse_timestamp() {
        let ts = parse_timestamp("2023-12-15 10:30:45").unwrap();
        assert_eq!(ts.year(), 2023);
        assert_eq!(ts.month(), 12);
        assert_eq!(ts.day(), 15);
        assert_eq!(ts.hour(), 10);
        assert_eq!(ts.minute(), 30);
        assert_eq!(ts.second(), 45);
    }

    #[test]
    fn test_parse_timestamp_invalid() {
        assert!(parse_timestamp("invalid").is_none());
        assert!(parse_timestamp("2023-13-01 00:00:00").is_none());
    }

    #[test]
    fn test_now_timestamp() {
        let ts = now_timestamp();
        // Should be in format YYYY-MM-DD HH:MM:SS
        assert_eq!(ts.len(), 19);
        assert!(ts.contains("-"));
        assert!(ts.contains(":"));
    }
}
