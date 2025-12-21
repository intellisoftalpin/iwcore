//! Password generation functionality
//!
//! Implements password generation matching the original C# implementation.

use rand::Rng;

const LOWER_LETTERS: &str = "qwertyuiopasdfghjklzxcvbnm";
const UPPER_LETTERS: &str = "QWERTYUIOPASDFGHJKLZXCVBNM";
const DIGITS: &str = "1234567890";
const SPECIAL_SYMBOLS: &str = "!@#$%^&*()_+-={}[];:|,.<>?~";

/// Options for password generation
#[derive(Debug, Clone)]
pub struct PasswordOptions {
    /// Include lowercase letters (a-z)
    pub lowercase: bool,
    /// Include uppercase letters (A-Z)
    pub uppercase: bool,
    /// Include digits (0-9)
    pub digits: bool,
    /// Include special symbols (!@#$%...)
    pub special: bool,
    /// Password length
    pub length: usize,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            lowercase: true,
            uppercase: true,
            digits: true,
            special: false,
            length: 16,
        }
    }
}

/// Generate a random password with the specified options.
///
/// This matches the original C# `GeneratePassword` function.
/// The character pool is weighted: letters are tripled, digits doubled,
/// special symbols once - this gives more readable passwords with good entropy.
///
/// # Arguments
/// * `options` - Password generation options
///
/// # Returns
/// Generated password string
///
/// # Example
/// ```
/// use iwcore::crypto::password::{generate_password, PasswordOptions};
///
/// let options = PasswordOptions {
///     lowercase: true,
///     uppercase: true,
///     digits: true,
///     special: false,
///     length: 12,
/// };
/// let password = generate_password(&options);
/// assert_eq!(password.len(), 12);
/// ```
pub fn generate_password(options: &PasswordOptions) -> String {
    let mut rng = rand::rng();
    let mut char_pool = String::new();

    // Build character pool with weighting (matching C# implementation)
    if options.lowercase {
        char_pool.push_str(LOWER_LETTERS);
        char_pool.push_str(LOWER_LETTERS);
        char_pool.push_str(LOWER_LETTERS);
    }

    if options.uppercase {
        char_pool.push_str(UPPER_LETTERS);
        char_pool.push_str(UPPER_LETTERS);
        char_pool.push_str(UPPER_LETTERS);
    }

    if options.digits {
        char_pool.push_str(DIGITS);
        char_pool.push_str(DIGITS);
    }

    if options.special {
        char_pool.push_str(SPECIAL_SYMBOLS);
    }

    // If nothing selected, use lowercase as fallback
    if char_pool.is_empty() {
        char_pool.push_str(LOWER_LETTERS);
    }

    let chars: Vec<char> = char_pool.chars().collect();
    let mut password = String::with_capacity(options.length);

    for _ in 0..options.length {
        let idx = rng.random_range(0..chars.len());
        password.push(chars[idx]);
    }

    password
}

/// Generate a password based on a pattern.
///
/// This matches the original C# `GenerateCleverPassword` function.
/// Each character in the pattern is replaced with a random character
/// of the same type:
/// - lowercase letter -> random lowercase letter
/// - uppercase letter -> random uppercase letter
/// - digit -> random digit
/// - special symbol -> random special symbol
/// - anything else -> random from all characters
///
/// # Arguments
/// * `pattern` - Password pattern (e.g., "Aaaa0000" for uppercase + 3 lower + 4 digits)
///
/// # Returns
/// Generated password string matching the pattern
///
/// # Example
/// ```
/// use iwcore::crypto::password::generate_clever_password;
///
/// let password = generate_clever_password("Aaaa0000");
/// assert_eq!(password.len(), 8);
/// // First char is uppercase, next 3 lowercase, last 4 digits
/// ```
pub fn generate_clever_password(pattern: &str) -> String {
    let mut rng = rand::rng();
    let all_symbols = format!("{}{}{}{}", LOWER_LETTERS, UPPER_LETTERS, DIGITS, SPECIAL_SYMBOLS);
    let all_chars: Vec<char> = all_symbols.chars().collect();
    let lower_chars: Vec<char> = LOWER_LETTERS.chars().collect();
    let upper_chars: Vec<char> = UPPER_LETTERS.chars().collect();
    let digit_chars: Vec<char> = DIGITS.chars().collect();
    let special_chars: Vec<char> = SPECIAL_SYMBOLS.chars().collect();

    let mut password = String::with_capacity(pattern.len());

    for ch in pattern.chars() {
        let generated_char = if LOWER_LETTERS.contains(ch) {
            lower_chars[rng.random_range(0..lower_chars.len())]
        } else if UPPER_LETTERS.contains(ch) {
            upper_chars[rng.random_range(0..upper_chars.len())]
        } else if DIGITS.contains(ch) {
            digit_chars[rng.random_range(0..digit_chars.len())]
        } else if SPECIAL_SYMBOLS.contains(ch) {
            special_chars[rng.random_range(0..special_chars.len())]
        } else {
            all_chars[rng.random_range(0..all_chars.len())]
        };
        password.push(generated_char);
    }

    password
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_default() {
        let options = PasswordOptions::default();
        let password = generate_password(&options);
        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_generate_password_length() {
        let options = PasswordOptions {
            length: 32,
            ..Default::default()
        };
        let password = generate_password(&options);
        assert_eq!(password.len(), 32);
    }

    #[test]
    fn test_generate_password_lowercase_only() {
        let options = PasswordOptions {
            lowercase: true,
            uppercase: false,
            digits: false,
            special: false,
            length: 20,
        };
        let password = generate_password(&options);
        assert_eq!(password.len(), 20);
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn test_generate_password_uppercase_only() {
        let options = PasswordOptions {
            lowercase: false,
            uppercase: true,
            digits: false,
            special: false,
            length: 20,
        };
        let password = generate_password(&options);
        assert_eq!(password.len(), 20);
        assert!(password.chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn test_generate_password_digits_only() {
        let options = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: true,
            special: false,
            length: 20,
        };
        let password = generate_password(&options);
        assert_eq!(password.len(), 20);
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_password_special_only() {
        let options = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            special: true,
            length: 20,
        };
        let password = generate_password(&options);
        assert_eq!(password.len(), 20);
        assert!(password.chars().all(|c| SPECIAL_SYMBOLS.contains(c)));
    }

    #[test]
    fn test_generate_password_all_types() {
        let options = PasswordOptions {
            lowercase: true,
            uppercase: true,
            digits: true,
            special: true,
            length: 100,
        };
        let password = generate_password(&options);
        assert_eq!(password.len(), 100);
        // With 100 chars, we should have some of each type (probabilistically)
    }

    #[test]
    fn test_generate_password_empty_options_fallback() {
        let options = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            special: false,
            length: 10,
        };
        let password = generate_password(&options);
        assert_eq!(password.len(), 10);
        // Should fallback to lowercase
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn test_generate_password_uniqueness() {
        let options = PasswordOptions::default();
        let p1 = generate_password(&options);
        let p2 = generate_password(&options);
        // Passwords should be different (extremely high probability)
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_generate_clever_password_length() {
        let password = generate_clever_password("Aaaa0000");
        assert_eq!(password.len(), 8);
    }

    #[test]
    fn test_generate_clever_password_pattern() {
        let password = generate_clever_password("aaaa");
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));

        let password = generate_clever_password("AAAA");
        assert!(password.chars().all(|c| c.is_ascii_uppercase()));

        let password = generate_clever_password("0000");
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_clever_password_mixed() {
        let password = generate_clever_password("Aa00");
        assert_eq!(password.len(), 4);
        let chars: Vec<char> = password.chars().collect();
        assert!(chars[0].is_ascii_uppercase());
        assert!(chars[1].is_ascii_lowercase());
        assert!(chars[2].is_ascii_digit());
        assert!(chars[3].is_ascii_digit());
    }

    #[test]
    fn test_generate_clever_password_special() {
        let password = generate_clever_password("!@#$");
        assert_eq!(password.len(), 4);
        assert!(password.chars().all(|c| SPECIAL_SYMBOLS.contains(c)));
    }

    #[test]
    fn test_generate_clever_password_unknown_chars() {
        // Unknown characters should map to random from all
        let password = generate_clever_password("    "); // spaces
        assert_eq!(password.len(), 4);
    }

    #[test]
    fn test_generate_clever_password_empty() {
        let password = generate_clever_password("");
        assert!(password.is_empty());
    }

    #[test]
    fn test_generate_clever_password_uniqueness() {
        let p1 = generate_clever_password("Aaaa0000@@");
        let p2 = generate_clever_password("Aaaa0000@@");
        // Passwords should be different (extremely high probability)
        assert_ne!(p1, p2);
    }
}
