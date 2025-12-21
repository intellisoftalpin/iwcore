//! Common utility functions

use chrono::{DateTime, Utc, NaiveDateTime};

/// Date format for database storage
pub const DB_DATE_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

/// Date format for display (8 chars: YYYYMMDD)
pub const SHORT_DATE_FORMAT: &str = "%Y%m%d";

/// Convert DateTime to database string format
pub fn format_datetime(dt: &DateTime<Utc>) -> String {
    dt.format(DB_DATE_FORMAT).to_string()
}

/// Parse database datetime string
pub fn parse_datetime(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, DB_DATE_FORMAT)
        .ok()
        .map(|ndt| DateTime::from_naive_utc_and_offset(ndt, Utc))
}

/// Get current UTC datetime
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Convert a string to asterisks (for masking passwords)
pub fn mask_string(s: &str) -> String {
    "*".repeat(s.chars().count())
}

/// Format a credit card number with spaces
pub fn format_card_number(card: &str) -> String {
    let digits: String = card.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 16 {
        format!(
            "{} {} {} {}",
            &digits[0..4],
            &digits[4..8],
            &digits[8..12],
            &digits[12..16]
        )
    } else {
        card.to_string()
    }
}

/// Format time string (HHmm -> HH:mm)
pub fn format_time(time: &str) -> String {
    if time.len() == 4 {
        format!("{}:{}", &time[0..2], &time[2..4])
    } else {
        time.to_string()
    }
}

/// Parse short date (YYYYMMDD) to DateTime
pub fn parse_short_date(s: &str) -> Option<DateTime<Utc>> {
    if s.len() != 8 {
        return None;
    }

    let year: i32 = s[0..4].parse().ok()?;
    let month: u32 = s[4..6].parse().ok()?;
    let day: u32 = s[6..8].parse().ok()?;

    chrono::NaiveDate::from_ymd_opt(year, month, day)
        .map(|d| d.and_hms_opt(0, 0, 0))
        .flatten()
        .map(|ndt| DateTime::from_naive_utc_and_offset(ndt, Utc))
}

/// Remove text between and including the specified tags
pub fn remove_text_between_tags(text: &str, start_tag: &str, end_tag: &str) -> String {
    let mut result = text.to_string();
    while let Some(start_pos) = result.find(start_tag) {
        if let Some(end_pos) = result[start_pos..].find(end_tag) {
            let end_pos = start_pos + end_pos + end_tag.len();
            result = format!("{}{}", &result[..start_pos], &result[end_pos..]);
        } else {
            break;
        }
    }
    result
}

/// Remove only the tags but keep the content between them
pub fn remove_tags(text: &str, start_tag: &str, end_tag: &str) -> String {
    text.replace(start_tag, "").replace(end_tag, "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Datelike};

    #[test]
    fn test_mask_string() {
        assert_eq!(mask_string("password"), "********");
        assert_eq!(mask_string(""), "");
        assert_eq!(mask_string("abc"), "***");
    }

    #[test]
    fn test_format_card_number() {
        assert_eq!(format_card_number("1234567890123456"), "1234 5678 9012 3456");
        assert_eq!(format_card_number("123"), "123");
    }

    #[test]
    fn test_format_time() {
        assert_eq!(format_time("1430"), "14:30");
        assert_eq!(format_time("0900"), "09:00");
        assert_eq!(format_time("invalid"), "invalid");
    }

    /// Test: CheckRemovingTags from C# CommonFixture
    #[test]
    fn test_remove_tags() {
        let str2test = "something here[iosonly]<ul><li> Payment will be charged[/iosonly] bla-blah test";
        let result = "something here<ul><li> Payment will be charged bla-blah test";
        let processed_text = remove_tags(str2test, "[iosonly]", "[/iosonly]");
        assert_eq!(result, processed_text);
    }

    /// Test: CheckRemovingTextBetweenTags from C# CommonFixture
    #[test]
    fn test_remove_text_between_tags() {
        let str2test = "something here[iosonly]<ul><li> Payment will be charged[/iosonly] bla-blah test";
        let result = "something here bla-blah test";
        let processed_text = remove_text_between_tags(str2test, "[iosonly]", "[/iosonly]");
        assert_eq!(result, processed_text);
    }

    /// Test: CheckDateToDBConversion from C# CommonFixture
    #[test]
    fn test_date_to_db_conversion() {
        let dt = Utc.with_ymd_and_hms(2016, 12, 15, 17, 23, 54).unwrap();
        let converted = format_datetime(&dt);
        assert_eq!("2016-12-15 17:23:54", converted);
    }

    /// Test: CheckDBDateTimeConversion from C# CommonFixture
    #[test]
    fn test_db_datetime_conversion() {
        let db_value = "2016-12-15 17:23:54";
        let expected = Utc.with_ymd_and_hms(2016, 12, 15, 17, 23, 54).unwrap();
        let converted = parse_datetime(db_value).unwrap();
        assert_eq!(expected, converted);
    }

    #[test]
    fn test_parse_short_date() {
        let dt = parse_short_date("20231215").unwrap();
        assert_eq!(dt.year(), 2023);
        assert_eq!(dt.month(), 12);
        assert_eq!(dt.day(), 15);

        // Invalid length
        assert!(parse_short_date("2023121").is_none());
        assert!(parse_short_date("202312150").is_none());

        // Invalid date
        assert!(parse_short_date("20231315").is_none()); // Month 13
        assert!(parse_short_date("20231232").is_none()); // Day 32
    }

    #[test]
    fn test_parse_datetime_invalid() {
        assert!(parse_datetime("invalid").is_none());
        assert!(parse_datetime("2023-13-01 00:00:00").is_none());
    }

    #[test]
    fn test_now() {
        let before = Utc::now();
        let result = now();
        let after = Utc::now();
        assert!(result >= before);
        assert!(result <= after);
    }

    #[test]
    fn test_format_card_number_with_spaces() {
        // Card with spaces/dashes should extract digits
        assert_eq!(format_card_number("1234-5678-9012-3456"), "1234 5678 9012 3456");
        assert_eq!(format_card_number("1234 5678 9012 3456"), "1234 5678 9012 3456");
    }

    #[test]
    fn test_remove_text_between_tags_multiple() {
        let text = "start[tag]first[/tag]middle[tag]second[/tag]end";
        let result = remove_text_between_tags(text, "[tag]", "[/tag]");
        assert_eq!(result, "startmiddleend");
    }

    #[test]
    fn test_remove_text_between_tags_no_end() {
        let text = "start[tag]no end tag";
        let result = remove_text_between_tags(text, "[tag]", "[/tag]");
        assert_eq!(result, "start[tag]no end tag"); // Unchanged if no end tag
    }
}
