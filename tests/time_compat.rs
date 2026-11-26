//! Date and time behaviour that must survive the move from `chrono` to `jiff`
//! (RUSTSEC-2026-0543). Written against the chrono implementation first and
//! kept unchanged through the migration: every stored, parsed and exported
//! date reads and prints exactly as before. Only the helper `secs` knows the
//! concrete timestamp type.

use iwcore::backup::get_date_from_backup_filename;
use iwcore::database::queries::{format_timestamp, now_timestamp, parse_timestamp};
use iwcore::export::{generate_csv, generate_json, generate_xml};
use iwcore::utils::{format_datetime, parse_datetime, parse_short_date};
use iwcore::Wallet;
use tempfile::TempDir;

/// Unix seconds of a timestamp, whatever its type.
fn secs<T: Secs>(t: &T) -> i64 {
    t.unix_seconds()
}

trait Secs {
    fn unix_seconds(&self) -> i64;
}

impl Secs for iwcore::Timestamp {
    fn unix_seconds(&self) -> i64 {
        self.as_second()
    }
}

/// Database timestamps: `%Y-%m-%d %H:%M:%S`, UTC. Results recorded from the
/// chrono implementation with a differential run over the same inputs.
#[test]
fn database_timestamps_parse_as_before() {
    let cases: &[(&str, Option<i64>)] = &[
        ("2023-12-15 10:30:45", Some(1_702_636_245)),
        ("1970-01-01 00:00:00", Some(0)),
        ("2024-02-29 00:00:00", Some(1_709_164_800)),
        ("0000-01-01 00:00:00", Some(-62_167_219_200)),
        ("0099-01-01 00:00:00", Some(-59_042_995_200)),
        ("-0001-01-01 00:00:00", Some(-62_198_755_200)),
        ("+2023-12-15 10:30:45", Some(1_702_636_245)),
        // Unpadded numbers and whitespace before a number are accepted.
        ("2023-1-5 1:2:3", Some(1_672_880_523)),
        ("2023-12-15 1:30:45", Some(1_702_603_845)),
        ("2023-12-15 10:3:45", Some(1_702_634_625)),
        ("2023-12-15 10:30:4", Some(1_702_636_204)),
        ("99-01-01 00:00:00", Some(-59_042_995_200)),
        (" 2023-12-15 10:30:45", Some(1_702_636_245)),
        ("\t2023-12-15 10:30:45", Some(1_702_636_245)),
        ("2023-12-15  10:30:45", Some(1_702_636_245)),
        ("2023-12-15 10:30: 45", Some(1_702_636_245)),
        ("2023- 12-15 10:30:45", Some(1_702_636_245)),
        // A leap second reads as the last second of its minute.
        ("2023-12-15 23:59:60", Some(1_702_684_799)),
        ("2023-12-15 10:30:60", Some(1_702_636_259)),
        // Everything else is refused.
        ("2023-02-29 00:00:00", None),
        ("2023-12-15 24:00:00", None),
        ("2023-012-15 10:30:45", None),
        ("2023-12-15 10:30:45 ", None),
        ("2023-12-15 10:30:45\n", None),
        ("2023-12-15 10:30", None),
        ("2023-12-15 10:30:45.123", None),
        ("2023-12-15T10:30:45", None),
        ("2023-12-15 10:30:45Z", None),
        ("2023/12/15 10:30:45", None),
        ("12023-12-15 10:30:45", None),
        ("99999-01-01 00:00:00", None),
        ("", None),
        ("invalid", None),
    ];
    for (input, want) in cases {
        assert_eq!(parse_timestamp(input).map(|t| secs(&t)), *want, "parse_timestamp({input:?})");
        assert_eq!(parse_datetime(input).map(|t| secs(&t)), *want, "parse_datetime({input:?})");
    }
}

#[test]
fn database_timestamps_print_as_before() {
    for s in ["2023-12-15 10:30:45", "1970-01-01 00:00:00", "2024-02-29 23:59:59", "0099-01-01 00:00:00"] {
        let t = parse_timestamp(s).unwrap();
        assert_eq!(format_timestamp(&t), s);
        assert_eq!(format_datetime(&t), s);
    }
    // Unpadded input prints padded.
    assert_eq!(format_timestamp(&parse_timestamp("2023-1-5 1:2:3").unwrap()), "2023-01-05 01:02:03");
    let now = now_timestamp();
    assert_eq!(now.len(), 19, "{now}");
    assert!(parse_timestamp(&now).is_some());
}

#[test]
fn short_dates_parse_as_before() {
    assert_eq!(parse_short_date("20231215").map(|t| secs(&t)), Some(1_702_598_400));
    assert_eq!(parse_short_date("20240229").map(|t| secs(&t)), Some(1_709_164_800));
    for bad in ["20230229", "20231315", "2023121", "202312155", "2023-12-15", "abcdefgh", ""] {
        assert_eq!(parse_short_date(bad).map(|t| secs(&t)), None, "{bad}");
    }
}

#[test]
fn backup_file_dates_parse_as_before() {
    let ok = |name: &str| get_date_from_backup_filename(name).map(|t| secs(&t));
    assert_eq!(ok("iwb-20231215-103045-auto.zip"), Some(1_702_636_245));
    assert_eq!(ok("/some/dir/nswb-20240229-000000-manual.zip"), Some(1_709_164_800));
    assert_eq!(ok("iwb-20231215-235960-auto.zip"), Some(1_702_684_799));
    for bad in [
        "iwb-20231215-246000-auto.zip",
        "iwb-20231315-103045-auto.zip",
        "iwb-2023121-5103045-auto.zip",
        "iwb-+2023121-103045-auto.zip",
        "iwb-2023121--103045-auto.zip",
        "iwb-20231215-10304-auto.zip",
        "iwb.zip",
        "",
    ] {
        assert_eq!(ok(bad), None, "{bad}");
    }
}

fn one_item(at: &str) -> (TempDir, Vec<iwcore::IWItem>, Vec<iwcore::IWField>) {
    let dir = TempDir::new().unwrap();
    let mut w = Wallet::create(dir.path(), "pw123", "en").unwrap();
    let item = w.add_item("Bank", "bank", false, None).unwrap();
    w.add_field(&item, "USER", "bkv", None).unwrap();
    let t = parse_timestamp(at).unwrap();
    let mut items: Vec<_> = w.get_items().unwrap().iter().filter(|i| i.item_id == item).cloned().collect();
    for i in &mut items {
        i.create_timestamp = t;
        i.change_timestamp = t;
    }
    let mut fields: Vec<_> = w.get_fields().unwrap().iter().filter(|f| f.item_id == item).cloned().collect();
    for f in &mut fields {
        f.change_timestamp = t;
    }
    (dir, items, fields)
}

/// RFC 3339 as chrono printed it: whole seconds, or 3, 6 or 9 fraction
/// digits, then `Z` (serde) or `+00:00` (`to_rfc3339`).
fn is_chrono_rfc3339(s: &str, zone: &str) -> bool {
    let Some(body) = s.strip_suffix(zone) else { return false };
    let (base, frac) = body.split_once('.').unwrap_or((body, ""));
    base.len() == 19
        && base.as_bytes()[10] == b'T'
        && matches!(frac.len(), 0 | 3 | 6 | 9)
        && frac.bytes().all(|b| b.is_ascii_digit())
}

#[test]
fn json_export_prints_timestamps_as_before() {
    let (_d, items, fields) = one_item("2023-12-15 10:30:45");
    let v: serde_json::Value = serde_json::from_slice(&generate_json(&items, &fields).unwrap()).unwrap();
    assert_eq!(v["items"][0]["create_timestamp"], "2023-12-15T10:30:45Z");
    assert_eq!(v["items"][0]["change_timestamp"], "2023-12-15T10:30:45Z");
    assert_eq!(v["fields"][0]["change_timestamp"], "2023-12-15T10:30:45Z");
    let at = v["exported_at"].as_str().unwrap();
    assert!(is_chrono_rfc3339(at, "Z"), "{at}");
}

#[test]
fn json_timestamps_read_back_as_before() {
    let (_d, items, _) = one_item("2023-12-15 10:30:45");
    let mut json = serde_json::to_value(&items[0]).unwrap();
    for (input, want) in [
        ("2023-12-15T10:30:45Z", Some(1_702_636_245)),
        ("2023-12-15T10:30:45+02:00", Some(1_702_629_045)),
        ("2023-12-15T10:30:45-00:00", Some(1_702_636_245)),
        ("2023-12-15T10:30:45.5Z", Some(1_702_636_245)),
        ("2023-12-15t10:30:45z", Some(1_702_636_245)),
        ("2023-12-15 10:30:45Z", Some(1_702_636_245)),
        ("2023-12-15T10:30:60Z", Some(1_702_636_259)),
        ("+2023-12-15T10:30:45Z", Some(1_702_636_245)),
        ("2023-12-15T10:30:45.123456789123Z", Some(1_702_636_245)),
        ("2023-12-15T10:30:45", None),
        ("not a date", None),
    ] {
        json["change_timestamp"] = serde_json::Value::from(input);
        let got = serde_json::from_value::<iwcore::IWItem>(json.clone()).ok().map(|i| secs(&i.change_timestamp));
        assert_eq!(got, want, "{input}");
    }
}

#[test]
fn csv_and_xml_exports_print_timestamps_as_before() {
    let (_d, items, fields) = one_item("2023-12-15 10:30:45");
    let csv = String::from_utf8(generate_csv(&items, &fields).unwrap()).unwrap();
    assert!(csv.contains("2023-12-15T10:30:45+00:00"), "{csv}");
    let xml = String::from_utf8(generate_xml(&items, &fields).unwrap()).unwrap();
    assert!(xml.contains("\"2023-12-15T10:30:45+00:00\""), "{xml}");
    let at = xml.split("exported_at=\"").nth(1).and_then(|r| r.split('"').next()).unwrap();
    assert!(is_chrono_rfc3339(at, "+00:00"), "{at}");
}

/// Days from 1970-01-01 to a proleptic Gregorian date (H. Hinnant's
/// algorithm): an oracle that shares no code with either library.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

proptest::proptest! {
    /// Every database timestamp of years 0000..=9998 parses to the instant
    /// the oracle computes and prints back unchanged; serde and the backup
    /// file name agree with it.
    #[test]
    fn every_stored_timestamp_round_trips(
        y in 0i64..=9998, m in 1i64..=12, d in 1i64..=31, h in 0i64..24, mi in 0i64..60, s in 0i64..60,
    ) {
        let d = d.min(days_in_month(y, m));
        let text = format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}");
        let want = days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60 + s;
        let t = parse_timestamp(&text).unwrap();
        proptest::prop_assert_eq!(secs(&t), want);
        proptest::prop_assert_eq!(format_timestamp(&t), text.clone());
        let name = format!("iwb-{y:04}{m:02}{d:02}-{h:02}{mi:02}{s:02}-auto.zip");
        proptest::prop_assert_eq!(get_date_from_backup_filename(&name).map(|t| secs(&t)), Some(want));
        let iso = format!("\"{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z\"");
        let back: iwcore::Timestamp = serde_json::from_value(serde_json::json!({
            "item_id": "i", "parent_id": "p", "name": "n", "icon": "x", "folder": false,
            "create_timestamp": serde_json::from_str::<serde_json::Value>(&iso).unwrap(),
            "change_timestamp": serde_json::from_str::<serde_json::Value>(&iso).unwrap(),
            "deleted": false
        }))
        .map(|i: iwcore::IWItem| i.change_timestamp)
        .unwrap();
        proptest::prop_assert_eq!(secs(&back), want);
    }
}
