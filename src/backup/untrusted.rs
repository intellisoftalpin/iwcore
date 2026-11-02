//! Opening a database that comes from a backup file.
//!
//! A backup can come from anywhere (a file the user was sent, a cloud folder),
//! so its database is treated as untrusted input until it has been checked:
//!
//! - the file must start with the SQLite header;
//! - it is opened read-only, with `SQLITE_DBCONFIG_DEFENSIVE` on,
//!   `trusted_schema` off and `query_only` on;
//! - every statement on the connection shares one work budget, enforced by a
//!   progress handler, so no query can run for long;
//! - `PRAGMA quick_check` must report `ok`;
//! - the wallet tables must be real tables, not views or virtual tables.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags};

use crate::error::{Result, WalletError};

/// The first 16 bytes of every SQLite database file.
pub(crate) const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// How many virtual machine instructions run between two progress checks.
const PROGRESS_INTERVAL_OPS: i32 = 1_000;

/// Work allowed on one connection regardless of its size, in progress checks
/// (so `PROGRESS_INTERVAL_OPS` times this many instructions).
pub(crate) const WORK_BUDGET_BASE_CHECKS: u64 = 2_000;

/// Extra work allowed per this many bytes of database file. Checking and
/// counting a large vault needs about one check per 4.5 KiB; this allows over
/// four times that, so a real vault never runs out while a small crafted file
/// is stopped quickly.
const WORK_BUDGET_BYTES_PER_CHECK: u64 = 1024;

/// Tables a wallet database always has.
const REQUIRED_TABLES: [&str; 3] = ["nswallet_items", "nswallet_fields", "nswallet_properties"];

/// Tables that are optional, but must be real tables when present.
const OPTIONAL_TABLES: [&str; 1] = ["nswallet_crypto"];

/// Whether `bytes` starts with the SQLite file header.
pub(crate) fn has_sqlite_header(bytes: &[u8]) -> bool {
    bytes.starts_with(SQLITE_HEADER)
}

fn not_a_wallet(detail: &str) -> WalletError {
    WalletError::BackupError(format!("The backup does not hold a wallet database: {detail}"))
}

/// Check that the file at `path` starts with the SQLite header.
pub(crate) fn check_sqlite_header(path: &Path) -> Result<()> {
    let mut head = [0u8; SQLITE_HEADER.len()];
    let mut file = File::open(path)
        .map_err(|e| WalletError::BackupError(format!("Failed to open database: {e}")))?;
    file.read_exact(&mut head)
        .map_err(|_| not_a_wallet("the file is too short"))?;
    if !has_sqlite_header(&head) {
        return Err(not_a_wallet("the file is not an SQLite database"));
    }
    Ok(())
}

/// Open the database at `path` read-only with the checks described in the
/// module documentation. Every check runs before any wallet query.
pub(crate) fn open_untrusted(path: &Path) -> Result<Connection> {
    let len = std::fs::metadata(path)
        .map_err(|e| WalletError::BackupError(format!("Failed to open database: {e}")))?
        .len();
    open_untrusted_with_budget(path, work_budget(len))
}

/// The work budget for a database file of `len` bytes.
pub(crate) fn work_budget(len: u64) -> u64 {
    WORK_BUDGET_BASE_CHECKS.saturating_add(len / WORK_BUDGET_BYTES_PER_CHECK)
}

/// [`open_untrusted`] with an explicit work budget (in progress checks).
pub(crate) fn open_untrusted_with_budget(path: &Path, budget_checks: u64) -> Result<Connection> {
    check_sqlite_header(path)?;

    let mut conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| WalletError::DatabaseError(format!("Failed to open database: {e}")))?;

    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA query_only = 1;")?;

    let mut checks: u64 = 0;
    conn.progress_handler(
        PROGRESS_INTERVAL_OPS,
        Some(move || {
            checks = checks.saturating_add(1);
            checks > budget_checks
        }),
    )?;

    let integrity: String = conn
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|e| not_a_wallet(&format!("integrity check failed: {e}")))?;
    if integrity != "ok" {
        return Err(not_a_wallet("integrity check failed"));
    }

    check_wallet_tables(&conn)?;
    Ok(conn)
}

/// Require the wallet tables to be ordinary tables of the main schema.
/// Names are compared without case, as SQLite resolves them.
fn check_wallet_tables(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT lower(name), type FROM pragma_table_list WHERE schema = 'main'",
    )?;
    let objects = stmt
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let kind_of = |name: &str| {
        objects
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, kind)| kind.as_str())
    };
    for name in REQUIRED_TABLES {
        match kind_of(name) {
            Some("table") => {}
            Some(_) => return Err(not_a_wallet(&format!("{name} is not a table"))),
            None => return Err(not_a_wallet(&format!("{name} is missing"))),
        }
    }
    for name in OPTIONAL_TABLES {
        match kind_of(name) {
            None | Some("table") => {}
            Some(_) => return Err(not_a_wallet(&format!("{name} is not a table"))),
        }
    }
    Ok(())
}

/// The database version stored in `nswallet_properties`, `"1"` when the
/// table has no row or no usable value (as the oldest databases).
pub(crate) fn read_db_version(conn: &Connection) -> Result<String> {
    use rusqlite::types::Value;
    use rusqlite::OptionalExtension;

    let value = conn
        .query_row("SELECT version FROM nswallet_properties LIMIT 1", [], |row| {
            row.get::<_, Value>(0)
        })
        .optional()?;
    Ok(match value {
        Some(Value::Text(s)) => s,
        Some(Value::Integer(i)) => i.to_string(),
        _ => "1".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    const WALLET_SCHEMA: &str = "
        CREATE TABLE nswallet_properties (database_id TEXT, version TEXT);
        CREATE TABLE nswallet_items (item_id TEXT, deleted INT, folder INT);
        CREATE TABLE nswallet_fields (item_id TEXT, type TEXT, deleted INT);";

    fn db_with(dir: &Path, sql: &str) -> std::path::PathBuf {
        let path = dir.join("t.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(sql).unwrap();
        path
    }

    #[test]
    fn a_wallet_shaped_database_opens() {
        let dir = TempDir::new().unwrap();
        let path = db_with(
            dir.path(),
            &format!("{WALLET_SCHEMA} INSERT INTO nswallet_properties VALUES ('abc', '6');"),
        );
        let conn = open_untrusted(&path).unwrap();
        assert_eq!(read_db_version(&conn).unwrap(), "6");
    }

    #[test]
    fn the_connection_cannot_write() {
        let dir = TempDir::new().unwrap();
        let path = db_with(dir.path(), WALLET_SCHEMA);
        let conn = open_untrusted(&path).unwrap();
        assert!(conn.execute("INSERT INTO nswallet_items VALUES ('a', 0, 0)", []).is_err());
        assert!(conn.execute_batch("PRAGMA query_only = 0; INSERT INTO nswallet_items VALUES ('a', 0, 0)").is_err());
    }

    #[test]
    fn version_and_id_fall_back_when_missing_or_odd() {
        let dir = TempDir::new().unwrap();
        let path = db_with(dir.path(), WALLET_SCHEMA);
        let conn = open_untrusted(&path).unwrap();
        assert_eq!(read_db_version(&conn).unwrap(), "1");
        drop(conn);

        let c = Connection::open(&path).unwrap();
        c.execute_batch("INSERT INTO nswallet_properties VALUES (NULL, NULL)").unwrap();
        drop(c);
        let conn = open_untrusted(&path).unwrap();
        assert_eq!(read_db_version(&conn).unwrap(), "1");
    }

    #[test]
    fn an_integer_version_reads_as_text() {
        let dir = TempDir::new().unwrap();
        let path = db_with(
            dir.path(),
            "CREATE TABLE nswallet_properties (database_id, version);
             CREATE TABLE nswallet_items (item_id TEXT);
             CREATE TABLE nswallet_fields (item_id TEXT);
             INSERT INTO nswallet_properties VALUES (1, 5);",
        );
        let conn = open_untrusted(&path).unwrap();
        assert_eq!(read_db_version(&conn).unwrap(), "5");
    }

    #[test]
    fn a_file_without_the_sqlite_header_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("x.db");
        std::fs::write(&path, b"definitely not sqlite, but long enough").unwrap();
        assert!(matches!(open_untrusted(&path), Err(WalletError::BackupError(_))));
        std::fs::write(&path, b"short").unwrap();
        assert!(matches!(open_untrusted(&path), Err(WalletError::BackupError(_))));
        assert!(open_untrusted(&dir.path().join("missing.db")).is_err());
    }

    #[test]
    fn has_sqlite_header_checks_the_prefix() {
        assert!(has_sqlite_header(b"SQLite format 3\0rest"));
        assert!(!has_sqlite_header(b"SQLite format 3"));
        assert!(!has_sqlite_header(b"PK\x03\x04"));
    }

    #[test]
    fn missing_wallet_tables_are_refused() {
        let dir = TempDir::new().unwrap();
        let path = db_with(
            dir.path(),
            "CREATE TABLE nswallet_properties (version TEXT);
             CREATE TABLE nswallet_items (item_id TEXT);",
        );
        assert!(matches!(open_untrusted(&path), Err(WalletError::BackupError(_))));
    }

    #[test]
    fn a_view_in_place_of_a_wallet_table_is_refused() {
        for (name, extra) in [
            ("nswallet_items", "CREATE TABLE nswallet_fields (a); CREATE TABLE nswallet_properties (version);"),
            ("nswallet_fields", "CREATE TABLE nswallet_items (a); CREATE TABLE nswallet_properties (version);"),
            ("nswallet_properties", "CREATE TABLE nswallet_items (a); CREATE TABLE nswallet_fields (a);"),
            ("NSWALLET_ITEMS", "CREATE TABLE nswallet_fields (a); CREATE TABLE nswallet_properties (version);"),
        ] {
            let dir = TempDir::new().unwrap();
            let path = db_with(dir.path(), &format!("{extra} CREATE VIEW {name} AS SELECT 1 AS a;"));
            assert!(
                matches!(open_untrusted(&path), Err(WalletError::BackupError(_))),
                "{name} as a view must be refused"
            );
        }
    }

    #[test]
    fn a_crypto_view_is_refused_but_a_crypto_table_is_fine() {
        let dir = TempDir::new().unwrap();
        let path = db_with(dir.path(), &format!("{WALLET_SCHEMA} CREATE VIEW nswallet_crypto AS SELECT 1;"));
        assert!(matches!(open_untrusted(&path), Err(WalletError::BackupError(_))));

        let dir = TempDir::new().unwrap();
        let path = db_with(dir.path(), &format!("{WALLET_SCHEMA} CREATE TABLE nswallet_crypto (id);"));
        open_untrusted(&path).unwrap();
    }

    #[test]
    fn a_virtual_table_in_place_of_a_wallet_table_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = db_with(
            dir.path(),
            "CREATE TABLE nswallet_fields (a); CREATE TABLE nswallet_properties (version);
             CREATE VIRTUAL TABLE nswallet_items USING fts5(item_id);",
        );
        assert!(matches!(open_untrusted(&path), Err(WalletError::BackupError(_))));
    }

    #[test]
    fn a_damaged_database_fails_the_integrity_check() {
        let dir = TempDir::new().unwrap();
        let path = db_with(
            dir.path(),
            &format!(
                "{WALLET_SCHEMA}
                 WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 2000)
                 INSERT INTO nswallet_items SELECT printf('%08d', n), 0, 0 FROM r;"
            ),
        );
        // Overwrite one page past the schema with garbage.
        let mut bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() > 3 * 4096);
        for b in &mut bytes[2 * 4096..3 * 4096] {
            *b = 0xA5;
        }
        std::fs::write(&path, bytes).unwrap();
        assert!(open_untrusted(&path).is_err());
    }

    /// A query that never ends on its own is stopped by the work budget.
    #[test]
    fn an_endless_query_stops_at_the_work_budget() {
        let dir = TempDir::new().unwrap();
        let path = db_with(dir.path(), WALLET_SCHEMA);
        let conn = open_untrusted(&path).unwrap();
        let started = Instant::now();
        let r: rusqlite::Result<i64> = conn.query_row(
            "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT count(*) FROM r",
            [],
            |row| row.get(0),
        );
        assert!(r.is_err());
        assert!(started.elapsed() < Duration::from_secs(1), "took {:?}", started.elapsed());
    }

    #[test]
    fn the_budget_is_shared_by_the_whole_connection() {
        let dir = TempDir::new().unwrap();
        let path = db_with(dir.path(), WALLET_SCHEMA);
        let count = |conn: &Connection| {
            conn.query_row(
                "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 20000)
                 SELECT count(*) FROM r",
                [],
                |r| r.get::<_, i64>(0),
            )
        };
        // A small budget opens, then runs out on the first long query.
        let conn = open_untrusted_with_budget(&path, 20).unwrap();
        assert!(count(&conn).is_err());
        // The default budget has room for it, three times over.
        let conn = open_untrusted(&path).unwrap();
        for _ in 0..3 {
            assert_eq!(count(&conn).unwrap(), 20000);
        }
    }

    #[test]
    fn the_budget_grows_with_the_file() {
        assert_eq!(work_budget(0), WORK_BUDGET_BASE_CHECKS);
        assert_eq!(work_budget(1 << 20), WORK_BUDGET_BASE_CHECKS + 1024);
        assert_eq!(work_budget(u64::MAX), WORK_BUDGET_BASE_CHECKS + u64::MAX / 1024);
    }

    fn big_vault(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("big.db");
        let conn = Connection::open(&path).unwrap();
        for sql in crate::database::schema::CREATE_ALL_TABLES {
            conn.execute(sql, []).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO nswallet_properties (database_id, version) VALUES ('big', '6');
             WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 20000)
             INSERT INTO nswallet_items (item_id, parent_id, name, folder, deleted)
               SELECT printf('%08d', n), '__ROOT__', randomblob(64), 0, 0 FROM r;
             WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 200000)
             INSERT INTO nswallet_fields (item_id, field_id, type, value, deleted)
               SELECT printf('%08d', n % 20000 + 1), printf('%04d', n / 20000), 'PASS', randomblob(48), 0 FROM r;",
        )
        .unwrap();
        path
    }

    fn big_count(conn: &Connection) -> rusqlite::Result<i64> {
        conn.query_row(
            "SELECT COUNT(*) FROM nswallet_fields f JOIN nswallet_items i ON i.item_id = f.item_id
             WHERE f.type = 'PASS' AND COALESCE(f.deleted, 0) = 0 AND COALESCE(i.deleted, 0) = 0",
            [],
            |r| r.get(0),
        )
    }

    /// Far more data than any real vault still reads within the budget.
    #[test]
    fn a_large_vault_fits_the_budget() {
        let dir = TempDir::new().unwrap();
        let path = big_vault(dir.path());
        let conn = open_untrusted(&path).unwrap();
        assert_eq!(big_count(&conn).unwrap(), 200000);
        // It needs under a third of its budget.
        let third = work_budget(std::fs::metadata(&path).unwrap().len()) / 3;
        let conn = open_untrusted_with_budget(&path, third).unwrap();
        assert_eq!(big_count(&conn).unwrap(), 200000);
    }
}
