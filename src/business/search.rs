//! Search functionality
//!
//! This module provides search utilities matching the original C# SearchManager (SM) class.

use crate::SEARCH_MIN_LENGTH;
use crate::ROOT_ID;
use crate::error::Result;
use crate::database::{IWField, SearchResult, SearchMatchType};
use super::wallet::Wallet;

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

impl Wallet {
    /// Search items and fields
    ///
    /// Matches the original C# implementation:
    /// - Requires minimum search phrase length (SEARCH_MIN_LENGTH = 3)
    /// - Name matches exclude folders (only items are matched by name)
    /// - Field value matches include all items
    /// - Returns distinct results
    pub fn search(&mut self, query: &str) -> Result<Vec<SearchResult>> {
        self.ensure_unlocked()?;

        // Check minimum phrase length (matching C# SM.CheckPhraseLength)
        if !is_valid_search_phrase(query) {
            return Ok(Vec::new());
        }

        let query_lower = query.to_lowercase();
        let items = self.get_items()?.to_vec();
        let fields = self.get_fields()?.to_vec();

        let mut results = Vec::new();

        for item in items.iter() {
            if item.item_id == ROOT_ID {
                continue;
            }

            // Name match: only for non-folders (matching original C# behavior: !x.Folder)
            let name_match = !item.folder && item.name.to_lowercase().contains(&query_lower);

            // Field match: search in field values
            let matching_fields: Vec<IWField> = fields.iter()
                .filter(|f| f.item_id == item.item_id && f.value.to_lowercase().contains(&query_lower))
                .cloned()
                .collect();

            let field_match = !matching_fields.is_empty();

            if name_match || field_match {
                let match_type = match (name_match, field_match) {
                    (true, true) => SearchMatchType::Both,
                    (true, false) => SearchMatchType::Name,
                    (false, true) => SearchMatchType::Field,
                    (false, false) => unreachable!(),
                };

                results.push(SearchResult {
                    item: item.clone(),
                    matching_fields,
                    match_type,
                });
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::business::wallet::tests::create_test_wallet;

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

    #[test]
    fn test_search() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("My Email Account", "document", false, None).unwrap();
        wallet.add_field(&item_id, "MAIL", "john@example.com", None).unwrap();

        let results = wallet.search("email").unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].item.name, "My Email Account");
    }

    #[test]
    fn test_search_minimum_length() {
        let (mut wallet, _temp) = create_test_wallet();
        wallet.add_item("AB", "document", false, None).unwrap();

        // Search with phrase shorter than minimum length should return empty
        let results = wallet.search("ab").unwrap();
        assert!(results.is_empty());

        // Search with phrase at minimum length should work
        let results = wallet.search("abc").unwrap();
        assert!(results.is_empty()); // No match, but search executed
    }

    #[test]
    fn test_search_excludes_folders() {
        let (mut wallet, _temp) = create_test_wallet();
        wallet.add_item("Banking Folder", "folder", true, None).unwrap();
        wallet.add_item("Banking Card", "document", false, None).unwrap();

        let results = wallet.search("Banking").unwrap();
        // Should find the item but not the folder
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].item.name, "Banking Card");
        assert!(!results[0].item.folder);
    }

    #[test]
    fn test_search_field_values() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("My Account", "document", false, None).unwrap();
        wallet.add_field(&item_id, "MAIL", "user@example.com", None).unwrap();

        let results = wallet.search("example.com").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_type, SearchMatchType::Field);
        assert_eq!(results[0].matching_fields.len(), 1);
    }

    #[test]
    fn test_search_case_insensitive() {
        let (mut wallet, _temp) = create_test_wallet();
        wallet.add_item("MyEmailAccount", "document", false, None).unwrap();

        let results = wallet.search("MYEMAIL").unwrap();
        assert_eq!(results.len(), 1);

        let results = wallet.search("myemail").unwrap();
        assert_eq!(results.len(), 1);

        let results = wallet.search("MyEmail").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_match_type_both() {
        let (mut wallet, _temp) = create_test_wallet();
        let item_id = wallet.add_item("Test Item", "document", false, None).unwrap();
        wallet.add_field(&item_id, "NOTE", "This is a test note", None).unwrap();

        let results = wallet.search("test").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_type, SearchMatchType::Both);
    }
}
