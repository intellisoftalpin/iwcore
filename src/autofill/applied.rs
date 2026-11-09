//! Which journal records this vault has already applied.
//!
//! A journal record's tag proves the provider wrote it, but not when: the same
//! bytes verify on every drain until the journal auth key rotates. So the vault
//! remembers the `record_id` of every record it has applied, and a drain skips
//! a record it has seen before, whatever journal it arrives in. This state
//! lives in the vault database, in the app's own storage, not next to the
//! journal in storage the provider shares.
//!
//! The memory is bounded. Only the [`MAX_REMEMBERED`] newest ids (by
//! `created_at`) are kept; when older ones are forgotten, the newest
//! `created_at` among them becomes a floor, and a record created at or before
//! the floor counts as applied too. A replayed record is therefore refused
//! whether its id is still remembered or not.
//!
//! The state is recorded in the same transaction as the drain that applied
//! the records, so a drain that fails leaves no trace here either.

use std::collections::HashSet;

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::Result;

use super::journal::PendingRecord;

/// Record ids kept before the oldest are folded into the floor. Twenty full
/// journals' worth.
pub(crate) const MAX_REMEMBERED: usize = 1024;

const CREATE_TABLES: &str = "
CREATE TABLE IF NOT EXISTS nswallet_autofill_applied (
    record_id   TEXT PRIMARY KEY NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nswallet_autofill_applied_floor (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    created_at  INTEGER NOT NULL
);
";

/// What the vault has applied so far.
#[derive(Debug, Default)]
pub(crate) struct Applied {
    ids: HashSet<String>,
    floor: Option<i64>,
}

impl Applied {
    /// Whether `record` was applied by an earlier drain.
    pub(crate) fn contains(&self, record: &PendingRecord) -> bool {
        self.ids.contains(&record.record_id) || self.floor.is_some_and(|floor| record.created_at <= floor)
    }
}

/// Read the applied state, creating its tables on first use.
pub(crate) fn load(conn: &Connection) -> Result<Applied> {
    conn.execute_batch(CREATE_TABLES)?;
    let mut stmt = conn.prepare("SELECT record_id FROM nswallet_autofill_applied")?;
    let ids = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<HashSet<_>>>()?;
    let floor = read_floor(conn)?;
    Ok(Applied { ids, floor })
}

fn read_floor(conn: &Connection) -> Result<Option<i64>> {
    Ok(conn
        .query_row("SELECT created_at FROM nswallet_autofill_applied_floor WHERE id = 1", [], |row| {
            row.get::<_, i64>(0)
        })
        .optional()?)
}

/// Remember `records` as applied, then fold everything beyond
/// [`MAX_REMEMBERED`] into the floor. Call inside the drain's transaction.
pub(crate) fn remember(conn: &Connection, records: &[(String, i64)]) -> Result<()> {
    conn.execute_batch(CREATE_TABLES)?;
    for (record_id, created_at) in records {
        conn.execute(
            "INSERT OR IGNORE INTO nswallet_autofill_applied (record_id, created_at) VALUES (?1, ?2)",
            params![record_id, created_at],
        )?;
    }

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM nswallet_autofill_applied", [], |row| row.get(0))?;
    let keep = i64::try_from(MAX_REMEMBERED).unwrap_or(i64::MAX);
    let excess = count.saturating_sub(keep);
    if excess <= 0 {
        return Ok(());
    }

    // The oldest rows go; the newest creation time among them is the floor.
    let mut stmt = conn.prepare(
        "SELECT rowid, created_at FROM nswallet_autofill_applied ORDER BY created_at ASC, rowid ASC LIMIT ?1",
    )?;
    let oldest = stmt
        .query_map([excess], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let Some(dropped_floor) = oldest.iter().map(|(_, created_at)| *created_at).max() else {
        return Ok(());
    };
    let floor = read_floor(conn)?.map_or(dropped_floor, |old| old.max(dropped_floor));
    conn.execute(
        "INSERT INTO nswallet_autofill_applied_floor (id, created_at) VALUES (1, ?1)
         ON CONFLICT(id) DO UPDATE SET created_at = excluded.created_at",
        [floor],
    )?;
    for (rowid, _) in oldest {
        conn.execute("DELETE FROM nswallet_autofill_applied WHERE rowid = ?1", [rowid])?;
    }
    // Rows at the floor are covered by it now; dropping them keeps the set
    // to what the floor does not already answer.
    conn.execute("DELETE FROM nswallet_autofill_applied WHERE created_at <= ?1", [floor])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, created_at: i64) -> PendingRecord {
        PendingRecord::new_login(id, "T", "https://example.com", "bkv", "pw", created_at)
    }

    #[test]
    fn remembered_ids_are_applied_and_others_are_not() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(!load(&conn).unwrap().contains(&rec("a", 1)));

        remember(&conn, &[("a".into(), 1), ("b".into(), 2)]).unwrap();
        remember(&conn, &[("a".into(), 1)]).unwrap();
        let applied = load(&conn).unwrap();
        assert!(applied.contains(&rec("a", 1)));
        assert!(applied.contains(&rec("b", 99)), "by id, whatever the time");
        assert!(!applied.contains(&rec("c", 0)), "no floor yet");
        assert_eq!(applied.floor, None);
    }

    #[test]
    fn forgotten_ids_are_still_refused_through_the_floor() {
        let conn = Connection::open_in_memory().unwrap();
        let first: Vec<(String, i64)> = (0..MAX_REMEMBERED).map(|i| (format!("r{i}"), 100 + i as i64)).collect();
        remember(&conn, &first).unwrap();
        assert_eq!(load(&conn).unwrap().floor, None, "exactly at the cap nothing is folded");

        remember(&conn, &[("new1".into(), 5_000), ("new2".into(), 5_001)]).unwrap();
        let applied = load(&conn).unwrap();
        // The two oldest (created 100 and 101) were folded into the floor.
        assert_eq!(applied.floor, Some(101));
        assert_eq!(applied.ids.len(), MAX_REMEMBERED);
        assert!(!applied.ids.contains("r0") && !applied.ids.contains("r1"));
        assert!(applied.contains(&rec("r0", 100)), "forgotten, but under the floor");
        assert!(applied.contains(&rec("anything", 101)));
        assert!(!applied.contains(&rec("fresh", 102)));
        assert!(applied.contains(&rec("r2", 102)), "still remembered by id");

        // The floor never moves back.
        let conn2 = &conn;
        conn2.execute("UPDATE nswallet_autofill_applied_floor SET created_at = 10000", []).unwrap();
        remember(conn2, &[("late".into(), 6_000)]).unwrap();
        assert_eq!(load(conn2).unwrap().floor, Some(10_000));
    }
}
