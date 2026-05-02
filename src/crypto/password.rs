//! Password generation functionality
//!
//! Implements three modes:
//! - `generate_password` — uniformly random, weighted character pool. Matches
//!   the original NS Wallet C# algorithm.
//! - `generate_clever_password` — preserves the per-character category of the
//!   input pattern (lower→lower, upper→upper, digit→digit, special→special).
//! - `generate_memorable_password` — `<prefix><sep><Word><digits><sep>...`
//!   using a 1024-word public wordlist. Customizable separator, prefix,
//!   digits-per-word, and capitalisation position.
//!
//! All three generators draw from `rand::rngs::OsRng` — the OS CSPRNG —
//! so randomness is cryptographically secure on every supported platform.
//!
//! SECURITY NOTE on the memorable mode: the wordlist is fully public
//! (open source on crates.io) and the format is deterministic, so per-word
//! entropy is exactly `log2(1024) = 10 bits` plus `log2(10) ≈ 3.32 bits`
//! per appended digit. Format-aware crackers benefit from knowing this
//! structure. Use the random mode for high-value secrets.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::wordlist::WORDS;

/// Build a fresh CSPRNG seeded from the OS entropy source.
///
/// `StdRng` in rand 0.9 is a ChaCha12 stream cipher; `from_os_rng()` seeds
/// it from `OsRng` (which on Apple platforms is `SecRandomCopyBytes`,
/// `getrandom(2)` on modern Linux, `BCryptGenRandom` on Windows).
/// We re-seed per call so password generation always reflects the current
/// OS entropy state — never thread-local cached state.
fn csprng() -> StdRng {
    StdRng::from_os_rng()
}

const LOWER_LETTERS: &str = "qwertyuiopasdfghjklzxcvbnm";
const UPPER_LETTERS: &str = "QWERTYUIOPASDFGHJKLZXCVBNM";
const DIGITS: &str = "1234567890";
const SPECIAL_SYMBOLS: &str = "!@#$%^&*()_+-=;:,.?~";

/// Characters that look alike in many fonts and confuse the user when
/// reading a password aloud or copying it by hand.
/// Pairs/groups: l-1-I-i, o-O-0, B-8, S-5-s, Z-2.
const AMBIGUOUS_CHARS: &str = "lIi1oO0B8Ss5Z2";

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
    /// Exclude visually-similar characters (l/I/i/1, o/O/0, B/8, S/5/s, Z/2).
    pub avoid_ambiguous: bool,
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
            avoid_ambiguous: false,
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
///     avoid_ambiguous: false,
///     length: 12,
/// };
/// let password = generate_password(&options);
/// assert_eq!(password.len(), 12);
/// ```
pub fn generate_password(options: &PasswordOptions) -> String {
    let mut rng = csprng();
    let mut char_pool = String::new();

    // Build weighted character pool (matching C# implementation: letters×3, digits×2)
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

    // Strip visually-similar characters when requested. Done after pool
    // construction so the per-class weighting (lower×3, upper×3, digit×2)
    // is preserved across the surviving characters.
    if options.avoid_ambiguous {
        char_pool = char_pool
            .chars()
            .filter(|c| !AMBIGUOUS_CHARS.contains(*c))
            .collect();
        if char_pool.is_empty() {
            char_pool.push_str(LOWER_LETTERS);
        }
    }

    let pool_chars: Vec<char> = char_pool.chars().collect();

    // Guarantee at least one character from EACH selected class. Many
    // third-party password rules ("must contain a digit", "must contain a
    // symbol", etc.) demand this — without it a long random password can
    // randomly fail validation on, say, a banking site.
    let mut required: Vec<char> = Vec::new();
    if options.lowercase {
        if let Some(c) = pick_from_class(LOWER_LETTERS, options.avoid_ambiguous, &mut rng) {
            required.push(c);
        }
    }
    if options.uppercase {
        if let Some(c) = pick_from_class(UPPER_LETTERS, options.avoid_ambiguous, &mut rng) {
            required.push(c);
        }
    }
    if options.digits {
        if let Some(c) = pick_from_class(DIGITS, options.avoid_ambiguous, &mut rng) {
            required.push(c);
        }
    }
    if options.special {
        if let Some(c) = pick_from_class(SPECIAL_SYMBOLS, options.avoid_ambiguous, &mut rng) {
            required.push(c);
        }
    }

    // If the user asked for a length shorter than the number of selected
    // classes, shuffle the required chars and truncate. (Practically
    // impossible — UI enforces length ≥ 8 — but we handle it cleanly.)
    if options.length <= required.len() {
        shuffle(&mut required, &mut rng);
        return required.into_iter().take(options.length).collect();
    }

    // Fill the rest from the weighted pool.
    let remaining = options.length - required.len();
    let mut password_chars: Vec<char> = required;
    for _ in 0..remaining {
        let idx = rng.random_range(0..pool_chars.len());
        password_chars.push(pool_chars[idx]);
    }

    // Shuffle so the guaranteed chars aren't always at the start.
    shuffle(&mut password_chars, &mut rng);
    password_chars.into_iter().collect()
}

/// Pick a single random character from a character-class string, optionally
/// honouring the avoid-ambiguous filter. Returns None if every char in the
/// class is filtered out (shouldn't happen for the current ambiguous set
/// but guarded for future-proofing).
fn pick_from_class(class: &str, avoid_ambiguous: bool, rng: &mut StdRng) -> Option<char> {
    let candidates: Vec<char> = class
        .chars()
        .filter(|c| !avoid_ambiguous || !AMBIGUOUS_CHARS.contains(*c))
        .collect();
    if candidates.is_empty() {
        None
    } else {
        Some(candidates[rng.random_range(0..candidates.len())])
    }
}

/// Fisher-Yates shuffle in place using the given CSPRNG.
fn shuffle<T>(items: &mut [T], rng: &mut StdRng) {
    for i in (1..items.len()).rev() {
        let j = rng.random_range(0..=i);
        items.swap(i, j);
    }
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
    let mut rng = csprng();
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

/// Capitalisation style for memorable-password words.
///
/// `First` → `Word` (default; uppercase first letter, lowercase rest).
/// `Last` → `worD` (lowercase first letters, uppercase final letter).
/// Both styles always produce mixed case, satisfying typical site
/// password-strength requirements that demand both upper and lower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorableCaps {
    First,
    Last,
}

/// Options for [`generate_memorable_password`].
#[derive(Debug, Clone)]
pub struct MemorableOptions {
    /// How many words to include. 0 returns an empty string. UI should
    /// constrain this to a safe range (e.g. 3..=6).
    pub num_words: usize,
    /// How many random digits (0–9) to append to each word. 0 = none.
    pub digits_per_word: usize,
    /// Separator placed between words AND between prefix (if any) and the
    /// first word. Arbitrary string; "-" is a sensible default.
    pub separator: String,
    /// Free-text prefix prepended to the result. When non-empty it is
    /// joined to the first word using `separator` (so it reads as a first
    /// segment, not concatenated to the first word). Empty by default.
    pub prefix: String,
    /// Capitalisation style.
    pub caps: MemorableCaps,
}

impl Default for MemorableOptions {
    fn default() -> Self {
        Self {
            num_words: 4,
            digits_per_word: 1,
            separator: "-".to_string(),
            prefix: String::new(),
            caps: MemorableCaps::First,
        }
    }
}

/// Generate a memorable password of the form
/// `<prefix><sep><Word1><digits1><sep><Word2><digits2>...`.
///
/// See [`MemorableOptions`] for the customizable parts.
pub fn generate_memorable_password(opts: &MemorableOptions) -> String {
    if opts.num_words == 0 {
        return String::new();
    }

    let mut rng = csprng();
    let mut segments: Vec<String> = Vec::with_capacity(opts.num_words);

    if !opts.prefix.is_empty() {
        segments.push(opts.prefix.clone());
    }

    for _ in 0..opts.num_words {
        let word = WORDS[rng.random_range(0..WORDS.len())];
        let mut s = apply_caps(word, opts.caps);
        for _ in 0..opts.digits_per_word {
            let digit = rng.random_range(0..10u32);
            s.push(char::from_digit(digit, 10).unwrap());
        }
        segments.push(s);
    }

    segments.join(&opts.separator)
}

fn apply_caps(word: &str, caps: MemorableCaps) -> String {
    let chars: Vec<char> = word.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    match caps {
        MemorableCaps::First => {
            let mut out = String::with_capacity(word.len());
            out.push(chars[0].to_ascii_uppercase());
            for &c in &chars[1..] {
                out.push(c);
            }
            out
        }
        MemorableCaps::Last => {
            let mut out = String::with_capacity(word.len());
            for &c in &chars[..chars.len() - 1] {
                out.push(c);
            }
            out.push(chars[chars.len() - 1].to_ascii_uppercase());
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
            avoid_ambiguous: false,
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
            avoid_ambiguous: false,
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
            avoid_ambiguous: false,
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
            avoid_ambiguous: false,
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
            avoid_ambiguous: false,
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
            avoid_ambiguous: false,
            length: 10,
        };
        let password = generate_password(&options);
        assert_eq!(password.len(), 10);
        // Should fallback to lowercase
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn test_generate_password_avoid_ambiguous() {
        let options = PasswordOptions {
            lowercase: true,
            uppercase: true,
            digits: true,
            special: false,
            avoid_ambiguous: true,
            length: 200,
        };
        let password = generate_password(&options);
        assert_eq!(password.len(), 200);
        for c in password.chars() {
            assert!(
                !AMBIGUOUS_CHARS.contains(c),
                "ambiguous char {c:?} should be excluded but appeared in {password}",
            );
        }
    }

    #[test]
    fn test_generate_password_avoid_ambiguous_off_does_not_filter() {
        // Sanity guard: with avoid_ambiguous=false, ambiguous chars CAN
        // appear (probabilistically — with length 1000 it's effectively
        // certain).
        let options = PasswordOptions {
            lowercase: true,
            uppercase: true,
            digits: true,
            special: false,
            avoid_ambiguous: false,
            length: 1000,
        };
        let password = generate_password(&options);
        let saw_any_ambiguous =
            password.chars().any(|c| AMBIGUOUS_CHARS.contains(c));
        assert!(
            saw_any_ambiguous,
            "expected at least one ambiguous char in 1000-char password",
        );
    }

    #[test]
    fn test_generate_password_guarantees_each_selected_class() {
        // Run many short passwords with all 4 classes. Every single result
        // must contain at least one of each class — never zero.
        let options = PasswordOptions {
            lowercase: true,
            uppercase: true,
            digits: true,
            special: true,
            avoid_ambiguous: false,
            length: 8,
        };
        for _ in 0..200 {
            let pwd = generate_password(&options);
            assert_eq!(pwd.len(), 8);
            assert!(pwd.chars().any(|c| c.is_ascii_lowercase()), "{pwd}");
            assert!(pwd.chars().any(|c| c.is_ascii_uppercase()), "{pwd}");
            assert!(pwd.chars().any(|c| c.is_ascii_digit()), "{pwd}");
            assert!(
                pwd.chars().any(|c| SPECIAL_SYMBOLS.contains(c)),
                "expected a special symbol in {pwd}",
            );
        }
    }

    #[test]
    fn test_generate_password_unselected_class_never_appears() {
        // Inverse guard: classes the user did NOT select must not appear.
        let options = PasswordOptions {
            lowercase: true,
            uppercase: false,
            digits: true,
            special: false,
            avoid_ambiguous: false,
            length: 100,
        };
        for _ in 0..50 {
            let pwd = generate_password(&options);
            assert!(
                pwd.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "unexpected char in {pwd}",
            );
        }
    }

    #[test]
    fn test_generate_password_guarantees_with_avoid_ambiguous() {
        // Combined: avoid ambiguous + at-least-one-of-each.
        let options = PasswordOptions {
            lowercase: true,
            uppercase: true,
            digits: true,
            special: true,
            avoid_ambiguous: true,
            length: 8,
        };
        for _ in 0..200 {
            let pwd = generate_password(&options);
            assert!(pwd.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pwd.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pwd.chars().any(|c| c.is_ascii_digit()));
            assert!(pwd.chars().any(|c| SPECIAL_SYMBOLS.contains(c)));
            for c in pwd.chars() {
                assert!(!AMBIGUOUS_CHARS.contains(c), "ambiguous {c} in {pwd}");
            }
        }
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

    // ─── memorable password tests ───────────────────────────────────────

    fn opts(num_words: usize) -> MemorableOptions {
        MemorableOptions {
            num_words,
            ..Default::default()
        }
    }

    fn wordlist_set() -> HashSet<&'static str> {
        WORDS.iter().copied().collect()
    }

    /// Strip the trailing digits from a word segment and return the word
    /// (lowercased).
    fn strip_digits_and_lower(seg: &str) -> String {
        seg.chars()
            .filter(|c| !c.is_ascii_digit())
            .collect::<String>()
            .to_ascii_lowercase()
    }

    #[test]
    fn memorable_zero_words_returns_empty() {
        let p = generate_memorable_password(&opts(0));
        assert_eq!(p, "");
    }

    #[test]
    fn memorable_one_word_no_separator() {
        let p = generate_memorable_password(&opts(1));
        assert!(!p.contains('-'), "single-word output should have no separator: {p}");
        // Format: <Word><digit>
        assert!(p.chars().last().unwrap().is_ascii_digit());
        assert!(p.chars().next().unwrap().is_ascii_uppercase());
    }

    #[test]
    fn memorable_default_four_words_three_dashes() {
        let p = generate_memorable_password(&opts(4));
        let dashes = p.chars().filter(|&c| c == '-').count();
        assert_eq!(dashes, 3, "4 words → 3 dashes; got: {p}");
        for seg in p.split('-') {
            assert!(seg.chars().next().unwrap().is_ascii_uppercase());
            assert!(seg.chars().last().unwrap().is_ascii_digit());
        }
    }

    #[test]
    fn memorable_custom_separator() {
        let mut o = opts(3);
        o.separator = "_".to_string();
        let p = generate_memorable_password(&o);
        assert_eq!(p.matches('_').count(), 2, "3 words → 2 underscores: {p}");
        assert!(!p.contains('-'));
    }

    #[test]
    fn memorable_multi_char_separator() {
        let mut o = opts(3);
        o.separator = "--".to_string();
        let p = generate_memorable_password(&o);
        // Two "--" separators → 4 dash chars total
        assert_eq!(p.matches("--").count(), 2, "3 words joined by '--': {p}");
    }

    #[test]
    fn memorable_zero_digits_per_word() {
        let mut o = opts(3);
        o.digits_per_word = 0;
        let p = generate_memorable_password(&o);
        for seg in p.split('-') {
            assert!(
                !seg.chars().any(|c| c.is_ascii_digit()),
                "segment {seg:?} should have no digits"
            );
        }
    }

    #[test]
    fn memorable_three_digits_per_word() {
        let mut o = opts(3);
        o.digits_per_word = 3;
        let p = generate_memorable_password(&o);
        for seg in p.split('-') {
            let trailing_digits =
                seg.chars().rev().take_while(|c| c.is_ascii_digit()).count();
            assert_eq!(trailing_digits, 3, "segment {seg:?} should end with 3 digits");
        }
    }

    #[test]
    fn memorable_caps_last() {
        let mut o = opts(3);
        o.caps = MemorableCaps::Last;
        o.digits_per_word = 1;
        let p = generate_memorable_password(&o);
        for seg in p.split('-') {
            // Format: <lower><lower>...<UPPER><digit>
            let chars: Vec<char> = seg.chars().collect();
            assert!(chars[0].is_ascii_lowercase(), "first char should be lowercase: {seg:?}");
            // Last is the digit; second-to-last is the uppercased letter
            assert!(chars.last().unwrap().is_ascii_digit());
            let upper = chars[chars.len() - 2];
            assert!(upper.is_ascii_uppercase(), "letter before digit should be uppercase: {seg:?}");
        }
    }

    #[test]
    fn memorable_with_prefix_uses_separator() {
        let mut o = opts(3);
        o.prefix = "@home".to_string();
        let p = generate_memorable_password(&o);
        assert!(p.starts_with("@home-"), "prefix must be joined by separator: {p}");
        // 1 prefix + 3 words → 3 dashes
        assert_eq!(p.matches('-').count(), 3, "{p}");
    }

    #[test]
    fn memorable_words_come_from_wordlist() {
        let words = wordlist_set();
        let p = generate_memorable_password(&opts(4));
        for seg in p.split('-') {
            let bare = strip_digits_and_lower(seg);
            assert!(
                words.contains(bare.as_str()),
                "segment {seg:?} stripped to {bare:?} not in wordlist"
            );
        }
    }

    #[test]
    fn memorable_two_calls_produce_different_outputs() {
        let p1 = generate_memorable_password(&opts(4));
        let p2 = generate_memorable_password(&opts(4));
        assert_ne!(p1, p2, "two consecutive calls must differ");
    }

    #[test]
    fn memorable_wordlist_length_is_1024() {
        // Same as the wordlist module's own test, but kept here so changing
        // password.rs alone still trips the regression guard if the wordlist
        // is swapped out.
        assert_eq!(WORDS.len(), 1024);
    }
}
