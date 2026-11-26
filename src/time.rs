//! Every date and time operation of iwcore, in one place.
//!
//! Backed by `jiff` since 0.8.0 (chrono became unmaintained,
//! RUSTSEC-2026-0543). The functions here reproduce what the chrono code did,
//! byte for byte where a value is stored or exported, and
//! `tests/time_compat.rs` holds the recorded chrono results they must keep
//! matching. Known differences, all outside real vault data:
//!
//! - a leap second (`23:59:60`) reads as `23:59:59` (chrono kept the 60 in
//!   its fraction, same unix second);
//! - instants after `9999-12-30 22:00 UTC` do not exist in jiff. A stored
//!   timestamp past it reads as unparseable, which every caller already treats
//!   as "now";
//! - CXF card expiry years outside 1..=9999 are refused.
//!
//! All times are UTC. Nothing here consults a time zone database.

use jiff::civil::{Date, DateTime};
use jiff::fmt::strtime;
use jiff::tz::TimeZone;
use jiff::{SignedDuration, Timestamp};

/// Seconds in a day, for whole-day offsets that must not depend on a calendar.
const DAY_SECONDS: i64 = 86_400;

/// The current instant.
pub fn now() -> Timestamp {
    Timestamp::now()
}

/// `ts` printed in UTC with a strftime format.
pub(crate) fn format_utc(ts: &Timestamp, format: &str) -> String {
    TimeZone::UTC.to_datetime(*ts).strftime(format).to_string()
}

/// A date and time in `format`, read as UTC. `None` when it does not parse,
/// names no real time, or lies outside the range a [`Timestamp`] holds.
pub(crate) fn parse_utc(text: &str, format: &str) -> Option<Timestamp> {
    let text = chrono_signed_year(text, format)?;
    let dt: DateTime = strtime::parse(format, text.as_ref()).ok()?.to_datetime().ok()?;
    TimeZone::UTC.to_timestamp(dt).ok()
}

/// The text jiff should read for a format starting with `%Y`, so that a
/// signed year reads as chrono read it. chrono took every digit after a sign
/// as the year and allowed whitespace before the sign; jiff wants exactly
/// four digits and no whitespace. `None` where chrono refused the text, or
/// where the year is outside the -9999..=9999 a jiff date holds. A compact
/// format (`%Y%m%d`) with a signed year is refused, as chrono refused it.
fn chrono_signed_year<'a>(text: &'a str, format: &str) -> Option<std::borrow::Cow<'a, str>> {
    use std::borrow::Cow;
    let trimmed = text.trim_start();
    let negative = match trimmed.as_bytes().first() {
        Some(b'+') => false,
        Some(b'-') => true,
        _ => return Some(Cow::Borrowed(text)),
    };
    if !format.starts_with("%Y") {
        return Some(Cow::Borrowed(text));
    }
    if format.starts_with("%Y%") {
        return None;
    }
    let rest = trimmed.get(1..)?;
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let year: i64 = rest.get(..digits)?.parse().ok()?;
    if year > 9999 {
        return None;
    }
    let sign = if negative && year != 0 { '-' } else { '+' };
    Some(Cow::Owned(format!("{sign}{year:04}{}", rest.get(digits..)?)))
}

/// A date in `format`. A leading sign is refused for compact formats (no
/// separator after the year), as chrono refused it: `+2023121` is not a date.
pub(crate) fn parse_date(text: &str, format: &str) -> Option<Date> {
    let text = chrono_signed_year(text, format)?;
    strtime::parse(format, text.as_ref()).ok()?.to_date().ok()
}

/// `ts` moved by a whole number of days of exactly 24 hours. `None` past the
/// range a [`Timestamp`] holds.
pub(crate) fn add_days(ts: Timestamp, days: i64) -> Option<Timestamp> {
    let secs = days.checked_mul(DAY_SECONDS)?;
    ts.checked_add(SignedDuration::from_secs(secs)).ok()
}

/// Today's date in UTC.
pub(crate) fn today_utc() -> Date {
    TimeZone::UTC.to_datetime(now()).date()
}

/// Midnight UTC at the start of `date`.
pub(crate) fn start_of_day(date: Date) -> Option<Timestamp> {
    TimeZone::UTC.to_timestamp(date.to_datetime(jiff::civil::Time::midnight())).ok()
}

/// Whole days from `from` to `to` (negative when `to` is earlier). Calendar
/// arithmetic on dates, so it holds over the whole calendar, past the last
/// instant a [`Timestamp`] holds too.
pub(crate) fn days_between(from: Date, to: Date) -> i64 {
    to.since(from).map_or(0, |span| i64::from(span.get_days()))
}

/// RFC 3339 exactly as chrono printed a UTC time: whole seconds, or 3, 6 or 9
/// fraction digits, whichever is shortest without losing precision; then `Z`
/// (`zulu`, chrono's serde form) or `+00:00` (chrono's `to_rfc3339`).
pub(crate) fn rfc3339(ts: &Timestamp, zulu: bool) -> String {
    let dt = TimeZone::UTC.to_datetime(*ts);
    let mut out = dt.strftime("%Y-%m-%dT%H:%M:%S").to_string();
    let nanos = dt.subsec_nanosecond().unsigned_abs();
    if nanos != 0 {
        if nanos.is_multiple_of(1_000_000) {
            out.push_str(&format!(".{:03}", nanos / 1_000_000));
        } else if nanos.is_multiple_of(1_000) {
            out.push_str(&format!(".{:06}", nanos / 1_000));
        } else {
            out.push_str(&format!(".{nanos:09}"));
        }
    }
    out.push_str(if zulu { "Z" } else { "+00:00" });
    out
}

/// RFC 3339 text as chrono's `DateTime<Utc>` read it: an offset is required
/// (`Z` or `±hh:mm`), `T` or a space separates date and time, a `+` before the
/// year is allowed and fraction digits past nine are ignored.
pub(crate) fn parse_rfc3339(text: &str) -> Option<Timestamp> {
    let text = text.strip_prefix('+').unwrap_or(text);
    let (head, tail) = match text.find('.') {
        Some(dot) => text.split_at(dot),
        None => (text, ""),
    };
    let mut fixed = String::with_capacity(text.len());
    fixed.push_str(head);
    if let Some(frac) = tail.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        let (num, rest) = frac.split_at(digits);
        fixed.push('.');
        fixed.push_str(num.get(..9).unwrap_or(num));
        fixed.push_str(rest);
    }
    // jiff reads a leap second as :59 like chrono's seconds do, and accepts
    // `-00:00`. A timestamp without an offset is refused by both.
    fixed.parse::<Timestamp>().ok()
}

/// Serde for timestamps in chrono's form, for the model structs.
pub(crate) mod serde_rfc3339 {
    use jiff::Timestamp;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(ts: &Timestamp, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::rfc3339(ts, true))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Timestamp, D::Error> {
        let text = std::borrow::Cow::<'de, str>::deserialize(d)?;
        super::parse_rfc3339(&text).ok_or_else(|| serde::de::Error::custom(format!("not an RFC 3339 time: {text}")))
    }

    /// The same, for `Option<Timestamp>` (`null` is `None`).
    pub(crate) mod option {
        use jiff::Timestamp;
        use serde::{Deserialize, Deserializer, Serializer};

        pub(crate) fn serialize<S: Serializer>(ts: &Option<Timestamp>, s: S) -> Result<S::Ok, S::Error> {
            match ts {
                Some(ts) => s.serialize_some(&super::super::rfc3339(ts, true)),
                None => s.serialize_none(),
            }
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Timestamp>, D::Error> {
            match Option::<std::borrow::Cow<'de, str>>::deserialize(d)? {
                None => Ok(None),
                Some(text) => super::super::parse_rfc3339(&text)
                    .map(Some)
                    .ok_or_else(|| serde::de::Error::custom(format!("not an RFC 3339 time: {text}"))),
            }
        }
    }
}

/// Test helper: the UTC instant of a calendar date and time.
#[cfg(test)]
pub(crate) fn utc(y: i16, mo: i8, d: i8, h: i8, mi: i8, s: i8) -> Timestamp {
    TimeZone::UTC
        .to_timestamp(jiff::civil::date(y, mo, d).at(h, mi, s, 0))
        .expect("test date in range")
}

/// Test helper: the UTC calendar date and time of an instant.
#[cfg(test)]
pub(crate) fn civil(ts: &Timestamp) -> DateTime {
    TimeZone::UTC.to_datetime(*ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64, nanos: i32) -> Timestamp {
        Timestamp::new(secs, nanos).unwrap()
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct Opt {
        #[serde(default, with = "super::serde_rfc3339::option")]
        at: Option<Timestamp>,
    }

    /// `Option<DateTime<Utc>>` as chrono's serde wrote and read it: the
    /// RFC 3339 string, `null` for none, a missing member as none.
    #[test]
    fn optional_timestamps_serialize_like_chrono() {
        let some = Opt { at: Some(ts(1_702_636_245, 500_000_000)) };
        assert_eq!(serde_json::to_string(&some).unwrap(), r#"{"at":"2023-12-15T10:30:45.500Z"}"#);
        assert_eq!(serde_json::to_string(&Opt { at: None }).unwrap(), r#"{"at":null}"#);
        assert_eq!(serde_json::from_str::<Opt>(r#"{"at":"2023-12-15T10:30:45.5Z"}"#).unwrap(), some);
        assert_eq!(serde_json::from_str::<Opt>(r#"{"at":null}"#).unwrap(), Opt { at: None });
        assert_eq!(serde_json::from_str::<Opt>("{}").unwrap(), Opt { at: None });
        let err = serde_json::from_str::<Opt>(r#"{"at":"yesterday"}"#).unwrap_err().to_string();
        assert!(err.contains("not an RFC 3339 time: yesterday"), "{err}");
        assert!(serde_json::from_str::<Opt>(r#"{"at":5}"#).is_err());
    }

    #[test]
    fn rfc3339_prints_like_chrono() {
        // Recorded from chrono 0.4.45 (`to_rfc3339` and serde).
        assert_eq!(rfc3339(&ts(1_702_636_245, 0), false), "2023-12-15T10:30:45+00:00");
        assert_eq!(rfc3339(&ts(1_702_636_245, 0), true), "2023-12-15T10:30:45Z");
        assert_eq!(rfc3339(&ts(1_702_636_245, 500_000_000), true), "2023-12-15T10:30:45.500Z");
        assert_eq!(rfc3339(&ts(1_702_636_245, 120_000), false), "2023-12-15T10:30:45.000120+00:00");
        assert_eq!(rfc3339(&ts(1_702_636_245, 123_456_789), true), "2023-12-15T10:30:45.123456789Z");
        assert_eq!(rfc3339(&ts(1_702_636_245, 1), true), "2023-12-15T10:30:45.000000001Z");
        assert_eq!(rfc3339(&ts(0, 0), true), "1970-01-01T00:00:00Z");
        // Before the epoch the fraction still counts forward from the second.
        assert_eq!(rfc3339(&ts(-1, 500_000_000), true), "1969-12-31T23:59:59.500Z");
    }

    #[test]
    fn rfc3339_reads_like_chrono() {
        let s = |t: &str| parse_rfc3339(t).map(|t| (t.as_second(), t.subsec_nanosecond()));
        assert_eq!(s("2023-12-15T10:30:45Z"), Some((1_702_636_245, 0)));
        assert_eq!(s("2023-12-15T10:30:45+02:00"), Some((1_702_629_045, 0)));
        assert_eq!(s("2023-12-15 10:30:45Z"), Some((1_702_636_245, 0)));
        assert_eq!(s("+2023-12-15T10:30:45Z"), Some((1_702_636_245, 0)));
        assert_eq!(s("2023-12-15T10:30:45.123456789123Z"), Some((1_702_636_245, 123_456_789)));
        assert_eq!(s("2023-12-15T10:30:45.5Z"), Some((1_702_636_245, 500_000_000)));
        assert_eq!(s("2023-12-15T10:30:60Z"), Some((1_702_636_259, 0)));
        assert_eq!(s("2023-12-15T10:30:45"), None);
        assert_eq!(s("2023-12-15T10:30:45."), None);
        assert_eq!(s(""), None);
        assert_eq!(s("+"), None);
    }

    #[test]
    fn compact_dates_refuse_a_sign_and_dashed_ones_keep_chronos_rule() {
        assert_eq!(parse_date("20231215", "%Y%m%d"), Some(jiff::civil::date(2023, 12, 15)));
        assert_eq!(parse_date("2023121", "%Y%m%d"), Some(jiff::civil::date(2023, 12, 1)));
        assert_eq!(parse_date("+2023121", "%Y%m%d"), None);
        assert_eq!(parse_date(" -2023121", "%Y%m%d"), None);
        assert_eq!(parse_date("2023-12-15", "%Y-%m-%d"), Some(jiff::civil::date(2023, 12, 15)));
        assert_eq!(parse_date("20230229", "%Y%m%d"), None);
    }

    /// Signed years, as chrono 0.4.45 read them (recorded), except years past
    /// 9999, which no jiff date holds.
    #[test]
    fn signed_years_read_as_chrono_read_them() {
        let d = |s: &str| parse_date(s, "%Y-%m-%d").map(|d| d.to_string());
        assert_eq!(d("+2026-12-01").as_deref(), Some("2026-12-01"));
        assert_eq!(d(" +2026-12-01").as_deref(), Some("2026-12-01"));
        assert_eq!(d("+02026-12-01").as_deref(), Some("2026-12-01"));
        assert_eq!(d("+002026-12-01").as_deref(), Some("2026-12-01"));
        assert_eq!(d("-2026-12-01"), Some(jiff::civil::date(-2026, 12, 1).to_string()));
        assert_eq!(d("-0000-01-01").as_deref(), Some("0000-01-01"));
        assert_eq!(d("+ 2026-12-01"), None);
        assert_eq!(d("+-2026-12-01"), None);
        assert_eq!(d("+20261201"), None);
        assert_eq!(d("+"), None);
        assert_eq!(d("+99999999999999999999999-01-01"), None);
        // Past 9999: chrono held these, jiff does not.
        assert_eq!(d("+10000-12-01"), None);
        assert_eq!(d("+202612-01-01"), None);
        let t = |s: &str| parse_utc(s, "%Y-%m-%d %H:%M:%S").map(|t| t.as_second());
        assert_eq!(t("+2026-12-01 10:00:00"), t("2026-12-01 10:00:00"));
        assert_eq!(t("+20261201 10:00:00"), None);
        assert_eq!(t("+12026-12-01 10:00:00"), None);
        // A format not starting with a year is left to jiff.
        assert_eq!(parse_date("+01-2026", "%m-%Y"), None);
    }

    #[test]
    fn whole_days_are_exactly_24_hours() {
        let t = ts(1_702_636_245, 7);
        assert_eq!(add_days(t, 1).map(|x| x.as_second()), Some(1_702_636_245 + 86_400));
        assert_eq!(add_days(t, -30).map(|x| x.as_second()), Some(1_702_636_245 - 30 * 86_400));
        assert_eq!(add_days(t, 0), Some(t));
        assert_eq!(add_days(t, i64::MAX), None);
        assert_eq!(add_days(t, 10_000 * 366), None);
    }

    #[test]
    fn days_between_counts_calendar_days() {
        let d = jiff::civil::date;
        assert_eq!(days_between(d(2024, 2, 28), d(2024, 3, 1)), 2);
        assert_eq!(days_between(d(2024, 3, 1), d(2024, 2, 28)), -2);
        assert_eq!(days_between(d(2024, 1, 1), d(2024, 1, 1)), 0);
        assert_eq!(days_between(d(2023, 1, 1), d(2024, 1, 1)), 365);
        // The calendar's last day is past the last Timestamp, still counted.
        assert_eq!(days_between(d(9999, 12, 30), d(9999, 12, 31)), 1);
        assert!(days_between(d(-9999, 1, 1), d(9999, 12, 31)) > 7_000_000);
    }

    #[test]
    fn parse_and_format_utc_round_trip() {
        let t = parse_utc("2023-12-15 10:30:45", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(t.as_second(), 1_702_636_245);
        assert_eq!(format_utc(&t, "%Y%m%d-%H%M%S"), "20231215-103045");
        assert_eq!(parse_utc("9999-12-31 23:59:59", "%Y-%m-%d %H:%M:%S"), None);
        assert_eq!(parse_utc("+2023121-103045", "%Y%m%d-%H%M%S"), None);
        assert!(parse_utc("+2023-12-15 10:30:45", "%Y-%m-%d %H:%M:%S").is_some());
        assert_eq!(start_of_day(jiff::civil::date(1970, 1, 2)).map(|t| t.as_second()), Some(86_400));
        let today = today_utc();
        assert!(start_of_day(today).unwrap() <= now());
    }
}
