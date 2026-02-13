//! Database migration logic for version upgrades
//!
//! Handles upgrades from v1 through v4

use rusqlite::Connection;
use crate::error::Result;

/// Current database version
pub const CURRENT_VERSION: &str = "5";

/// Upgrade database to the latest version
pub fn upgrade_database(conn: &Connection, current_version: &str) -> Result<()> {
    let version: u32 = current_version.parse().unwrap_or(1);

    if version < 2 {
        upgrade_to_v2(conn)?;
    }
    if version < 3 {
        upgrade_to_v3(conn)?;
    }
    if version < 4 {
        upgrade_to_v4(conn)?;
    }
    if version < 5 {
        upgrade_to_v5(conn)?;
    }

    Ok(())
}

/// Upgrade from v1 to v2
/// Adds icons and groups tables
fn upgrade_to_v2(_conn: &Connection) -> Result<()> {
    // This is intentionally a no-op for Rust-created databases.
    // The original C# UpgradeTo02 imported custom icons from iconset.xml
    // and added system labels. For new databases created by iwcore:
    // - Icons/groups tables already exist from schema creation
    // - System labels are added during wallet creation
    // Legacy C# databases requiring icon XML import are not supported.
    Ok(())
}

/// Upgrade from v2 to v3
/// Adds is_circle and deleted columns to icons and groups
fn upgrade_to_v3(conn: &Connection) -> Result<()> {
    // Add is_circle column to icons if not exists
    let _ = conn.execute(
        "ALTER TABLE nswallet_icons ADD COLUMN is_circle INTEGER DEFAULT 1",
        [],
    );

    // Add deleted column to icons if not exists
    let _ = conn.execute(
        "ALTER TABLE nswallet_icons ADD COLUMN deleted INTEGER DEFAULT 0",
        [],
    );

    // Add deleted column to groups if not exists
    let _ = conn.execute(
        "ALTER TABLE nswallet_groups ADD COLUMN deleted INTEGER DEFAULT 0",
        [],
    );

    Ok(())
}

/// Upgrade from v3 to v4
/// Adds 2FA label
fn upgrade_to_v4(conn: &Connection) -> Result<()> {
    // Add 2FA label if not exists
    let _ = conn.execute(
        r#"INSERT OR IGNORE INTO nswallet_labels
           (field_type, label_name, value_type, icon, system, deleted)
           VALUES ('2FAC', '2FA', 'pass', 'icon_2fa', 1, 0)"#,
        [],
    );

    Ok(())
}

/// Upgrade from v4 to v5
/// Adds Seed Phrase label
fn upgrade_to_v5(conn: &Connection) -> Result<()> {
    let _ = conn.execute(
        r#"INSERT OR IGNORE INTO nswallet_labels
           (field_type, label_name, value_type, icon, system, deleted)
           VALUES ('SEED', 'Seed Phrase', 'text', 'icon_seed', 1, 0)"#,
        [],
    );

    Ok(())
}

/// Check if database version is compatible
pub fn is_version_compatible(version: &str) -> bool {
    let v: u32 = version.parse().unwrap_or(0);
    v <= CURRENT_VERSION.parse::<u32>().unwrap_or(4)
}

/// Get the current database version from properties
pub fn get_database_version(conn: &Connection) -> Result<String> {
    let version: String = conn.query_row(
        "SELECT version FROM nswallet_properties LIMIT 1",
        [],
        |row| row.get(0),
    ).unwrap_or_else(|_| "1".to_string());

    Ok(version)
}

/// Set the database version in properties
pub fn set_database_version(conn: &Connection, version: &str) -> Result<()> {
    conn.execute(
        "UPDATE nswallet_properties SET version = ?",
        [version],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_version_compatible() {
        assert!(is_version_compatible("1"));
        assert!(is_version_compatible("2"));
        assert!(is_version_compatible("3"));
        assert!(is_version_compatible("4"));
        assert!(is_version_compatible("5"));
        assert!(!is_version_compatible("6"));
        assert!(!is_version_compatible("999"));
        assert!(is_version_compatible("invalid")); // Parses to 0, which is <= 4
    }

    #[test]
    fn test_current_version() {
        assert_eq!(CURRENT_VERSION, "5");
    }

    #[test]
    fn test_upgrade_database_from_v1() {
        let conn = Connection::open_in_memory().unwrap();

        // Create minimal schema
        conn.execute_batch(r#"
            CREATE TABLE nswallet_properties (
                database_id TEXT PRIMARY KEY,
                version TEXT
            );
            INSERT INTO nswallet_properties (database_id, version) VALUES ('test', '1');

            CREATE TABLE nswallet_icons (
                icon_id TEXT PRIMARY KEY,
                name TEXT
            );
            CREATE TABLE nswallet_groups (
                group_id INTEGER PRIMARY KEY,
                name TEXT
            );
            CREATE TABLE nswallet_labels (
                field_type TEXT PRIMARY KEY,
                label_name TEXT,
                value_type TEXT,
                icon TEXT,
                system INTEGER,
                deleted INTEGER
            );
        "#).unwrap();

        // Should upgrade without error
        upgrade_database(&conn, "1").unwrap();
    }

    #[test]
    fn test_upgrade_database_from_v3() {
        let conn = Connection::open_in_memory().unwrap();

        // Create schema at v3
        conn.execute_batch(r#"
            CREATE TABLE nswallet_properties (
                database_id TEXT PRIMARY KEY,
                version TEXT
            );
            INSERT INTO nswallet_properties (database_id, version) VALUES ('test', '3');

            CREATE TABLE nswallet_labels (
                field_type TEXT PRIMARY KEY,
                label_name TEXT,
                value_type TEXT,
                icon TEXT,
                system INTEGER,
                deleted INTEGER
            );
        "#).unwrap();

        // Upgrade from v3 to v4
        upgrade_database(&conn, "3").unwrap();

        // Check 2FA label was added
        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM nswallet_labels WHERE field_type = '2FAC'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_get_set_database_version() {
        let conn = Connection::open_in_memory().unwrap();

        conn.execute_batch(r#"
            CREATE TABLE nswallet_properties (
                database_id TEXT PRIMARY KEY,
                version TEXT
            );
            INSERT INTO nswallet_properties (database_id, version) VALUES ('test', '1');
        "#).unwrap();

        assert_eq!(get_database_version(&conn).unwrap(), "1");

        set_database_version(&conn, "4").unwrap();
        assert_eq!(get_database_version(&conn).unwrap(), "4");
    }

    #[test]
    fn test_get_database_version_missing_table() {
        let conn = Connection::open_in_memory().unwrap();
        // No properties table - should return default "1"
        assert_eq!(get_database_version(&conn).unwrap(), "1");
    }
}
