//! Search functionality
//!
//! This module provides search utilities matching the original C# SearchManager (SM) class.

use crate::SEARCH_MIN_LENGTH;

/// Check if the search phrase meets the minimum length requirement
///
/// # Arguments
/// * `phrase` - The search phrase to check
/// * `min_length` - Minimum required length (use SEARCH_MIN_LENGTH constant)
///
/// # Returns
/// `true` if the phrase is at least `min_length` characters
pub fn check_phrase_length(phrase: &str, min_length: usize) -> bool {
    phrase.len() >= min_length
}

/// Check if the search phrase meets the default minimum length
pub fn is_valid_search_phrase(phrase: &str) -> bool {
    check_phrase_length(phrase, SEARCH_MIN_LENGTH)
}

/// Convert a string to lowercase for case-insensitive search
pub fn to_lower(s: &str) -> String {
    s.to_lowercase()
}

/// Check if a string contains the search phrase (case-insensitive)
pub fn contains_phrase(text: &str, phrase: &str) -> bool {
    to_lower(text).contains(&to_lower(phrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_phrase_length_valid() {
        assert!(check_phrase_length("abc", 3));
        assert!(check_phrase_length("abcd", 3));
        assert!(check_phrase_length("hello world", 3));
    }

    #[test]
    fn test_check_phrase_length_invalid() {
        assert!(!check_phrase_length("ab", 3));
        assert!(!check_phrase_length("a", 3));
        assert!(!check_phrase_length("", 3));
    }

    #[test]
    fn test_is_valid_search_phrase() {
        assert!(is_valid_search_phrase("abc"));
        assert!(is_valid_search_phrase("test"));
        assert!(!is_valid_search_phrase("ab"));
        assert!(!is_valid_search_phrase(""));
    }

    #[test]
    fn test_to_lower() {
        assert_eq!(to_lower("ABC"), "abc");
        assert_eq!(to_lower("Hello World"), "hello world");
        assert_eq!(to_lower("already lowercase"), "already lowercase");
        assert_eq!(to_lower("MiXeD CaSe"), "mixed case");
    }

    #[test]
    fn test_contains_phrase() {
        assert!(contains_phrase("Hello World", "hello"));
        assert!(contains_phrase("Hello World", "HELLO"));
        assert!(contains_phrase("Hello World", "World"));
        assert!(contains_phrase("Hello World", "lo wo"));
        assert!(!contains_phrase("Hello World", "xyz"));
    }

    #[test]
    fn test_contains_phrase_case_insensitive() {
        assert!(contains_phrase("MyEmailAccount", "email"));
        assert!(contains_phrase("myemailaccount", "EMAIL"));
        assert!(contains_phrase("MYEMAILACCOUNT", "Email"));
    }

    #[test]
    fn test_contains_phrase_special_chars() {
        assert!(contains_phrase("test@example.com", "@example"));
        assert!(contains_phrase("Password123!", "123!"));
    }
}
