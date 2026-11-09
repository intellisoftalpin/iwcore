//! Key derivation for AES-256 encryption
//!
//! Implements the exact key derivation algorithm from the original C# code:
//! 1. If hash provided and re_encryption_count > 0: use hash directly
//! 2. Otherwise: pad password by doubling until >= 32 chars
//! 3. Truncate to 32 chars
//! 4. If re_encryption_count > 0: apply MD5 that many times
//! 5. UTF-8 encode to 32 bytes

use md5::{Digest, Md5};
use zeroize::Zeroizing;

/// Key length for AES-256 (32 bytes = 256 bits)
pub const KEY_LENGTH: usize = 32;

/// Prepare encryption key from password
///
/// This function replicates the exact behavior of the C# `prepareKey` function
/// to ensure byte-compatibility with existing encrypted data.
///
/// # Arguments
///
/// * `password` - The user's password
/// * `hash` - Optional pre-computed hash (used when re_encryption_count > 0)
/// * `re_encryption_count` - Number of MD5 iterations to apply
///
/// # Returns
///
/// A 32-byte key suitable for AES-256 encryption
pub fn prepare_key(password: &str, hash: Option<&str>, re_encryption_count: u32) -> Zeroizing<[u8; KEY_LENGTH]> {
    let key_string = match hash {
        // Use provided hash directly
        Some(h) if !h.is_empty() && re_encryption_count > 0 => Zeroizing::new(h.to_string()),
        _ => derive_key_from_password(password, re_encryption_count),
    };

    // Convert to UTF-8 bytes and ensure exactly 32 bytes: copy up to
    // KEY_LENGTH bytes, zero-pad the rest.
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    for (dst, src) in key.iter_mut().zip(key_string.as_bytes()) {
        *dst = *src;
    }

    key
}

/// Derive key from password with optional MD5 iterations. Every
/// intermediate string is wiped when dropped; the buffers are sized up front
/// so no growth leaves an unwiped copy behind.
fn derive_key_from_password(password: &str, re_encryption_count: u32) -> Zeroizing<String> {
    // Step 1: Pad password by doubling until >= 32 chars. An empty password
    // cannot be padded: it stays empty (an all-zero key) instead of looping
    // forever. At most one copy beyond 32 chars, of up to 4 bytes each.
    let mut padded = Zeroizing::new(String::with_capacity(password.len() + 4 * KEY_LENGTH));
    padded.push_str(password);
    while !password.is_empty() && padded.chars().count() < KEY_LENGTH {
        padded.push_str(password);
    }

    // Step 2: Truncate to exactly 32 characters
    let mut truncated = Zeroizing::new(String::with_capacity(4 * KEY_LENGTH));
    truncated.extend(padded.chars().take(KEY_LENGTH));

    // Step 3: Apply MD5 iterations if re_encryption_count > 0
    if re_encryption_count > 0 {
        apply_md5_iterations(&truncated, re_encryption_count)
    } else {
        truncated
    }
}

/// Apply MD5 hash repeatedly, in place in one wiped buffer.
fn apply_md5_iterations(input: &str, count: u32) -> Zeroizing<String> {
    let mut result = Zeroizing::new(String::with_capacity(input.len().max(2 * 16)));
    result.push_str(input);
    for _ in 0..count {
        let mut digest = Zeroizing::new([0u8; 16]);
        digest.copy_from_slice(&Md5::digest(result.as_bytes()));
        result.clear();
        for b in digest.iter() {
            for nibble in [b >> 4, b & 0x0f] {
                result.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_hash_is_ignored_without_iterations() {
        let hash = "ffffffffffffffffffffffffffffffff";
        assert_eq!(*prepare_key("Sun001!", Some(hash), 0), *prepare_key("Sun001!", None, 0));
        assert_ne!(*prepare_key("Sun001!", Some(hash), 0), *prepare_key(hash, None, 0));
        assert_eq!(&prepare_key("Sun001!", Some(hash), 1)[..], hash.as_bytes());
    }

    #[test]
    fn test_key_short_password() {
        // Password "Sun001!" (7 chars) should be padded to 32
        let key = prepare_key("Sun001!", None, 0);

        // Expected: "Sun001!Sun001!Sun001!Sun001!Sun0" (32 chars) as UTF-8 bytes
        let expected = b"Sun001!Sun001!Sun001!Sun001!Sun0";
        assert_eq!(&key[..], &expected[..]);
    }

    #[test]
    fn test_key_exact_32_chars() {
        let password = "12345678901234567890123456789012"; // Exactly 32 chars
        let key = prepare_key(password, None, 0);
        assert_eq!(&key[..], password.as_bytes());
    }

    #[test]
    fn test_key_longer_than_32() {
        let password = "1234567890123456789012345678901234567890"; // 40 chars
        let key = prepare_key(password, None, 0);

        // Should be truncated to first 32 chars
        let expected = b"12345678901234567890123456789012";
        assert_eq!(&key[..], &expected[..]);
    }

    #[test]
    fn test_key_with_hash() {
        // When hash is provided and re_encryption_count > 0, use hash directly
        let hash = "12345678901234567890123456789012";
        let key = prepare_key("ignored", Some(hash), 1);
        assert_eq!(&key[..], hash.as_bytes());
    }

    #[test]
    fn test_key_short_hash_is_zero_padded() {
        let key = prepare_key("ignored", Some("abc"), 1);
        assert_eq!(&key[..3], b"abc");
        assert!(key[3..].iter().all(|b| *b == 0));
    }

    #[test]
    fn test_key_multibyte_password_truncates_to_32_bytes() {
        // 32 Cyrillic chars = 64 UTF-8 bytes; only the first 32 bytes are kept.
        let key = prepare_key("ж", None, 0);
        assert_eq!(&key[..], "ж".repeat(16).as_bytes());
    }

    #[test]
    fn test_key_with_empty_hash() {
        // When hash is empty, derive from password
        let key = prepare_key("Sun001!", Some(""), 0);
        let expected = b"Sun001!Sun001!Sun001!Sun001!Sun0";
        assert_eq!(&key[..], &expected[..]);
    }

    #[test]
    fn test_key_with_reencryption() {
        // With re_encryption_count > 0, apply MD5 iterations
        let key = prepare_key("test", None, 1);

        // First pad "test" to "testtesttesttesttesttesttesttest" (32 chars)
        // Then apply MD5 once
        let padded: String = "test".repeat(8);
        let expected_hash = crate::crypto::md5::md5_hex(&padded);
        assert_eq!(&key[..], expected_hash.as_bytes());
    }

    #[test]
    fn test_key_empty_password_terminates() {
        // An empty password must not hang the padding loop.
        assert_eq!(*prepare_key("", None, 0), [0u8; KEY_LENGTH]);
        assert_eq!(*prepare_key("", Some(""), 200), md5_iterated_empty(200));
    }

    fn md5_iterated_empty(count: u32) -> [u8; KEY_LENGTH] {
        let mut s = String::new();
        for _ in 0..count {
            s = crate::crypto::md5::md5_hex(&s);
        }
        let mut key = [0u8; KEY_LENGTH];
        key.copy_from_slice(s.as_bytes());
        key
    }

    #[test]
    fn md5_iterations_match_the_hex_chain() {
        let mut s = "Sun001!Sun001!Sun001!Sun001!Sun0".to_string();
        for _ in 0..3 {
            s = crate::crypto::md5::md5_hex(&s);
        }
        assert_eq!(&prepare_key("Sun001!", None, 3)[..], s.as_bytes());
        assert_eq!(apply_md5_iterations("x", 0).as_str(), "x");
    }
}
