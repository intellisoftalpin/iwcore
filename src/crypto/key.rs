//! Key derivation for AES-256 encryption
//!
//! Implements the exact key derivation algorithm from the original C# code:
//! 1. If hash provided and re_encryption_count > 0: use hash directly
//! 2. Otherwise: pad password by doubling until >= 32 chars
//! 3. Truncate to 32 chars
//! 4. If re_encryption_count > 0: apply MD5 that many times
//! 5. UTF-8 encode to 32 bytes

use super::md5::md5_hex;

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
pub fn prepare_key(password: &str, hash: Option<&str>, re_encryption_count: u32) -> [u8; KEY_LENGTH] {
    let key_string = if let Some(h) = hash {
        if !h.is_empty() && re_encryption_count > 0 {
            // Use provided hash directly
            h.to_string()
        } else {
            derive_key_from_password(password, re_encryption_count)
        }
    } else {
        derive_key_from_password(password, re_encryption_count)
    };

    // Convert to UTF-8 bytes and ensure exactly 32 bytes
    let key_bytes = key_string.as_bytes();
    let mut key = [0u8; KEY_LENGTH];

    // Copy up to KEY_LENGTH bytes
    let copy_len = std::cmp::min(key_bytes.len(), KEY_LENGTH);
    key[..copy_len].copy_from_slice(&key_bytes[..copy_len]);

    key
}

/// Derive key from password with optional MD5 iterations
fn derive_key_from_password(password: &str, re_encryption_count: u32) -> String {
    // Step 1: Pad password by doubling until >= 32 chars
    let mut padded = password.to_string();
    while padded.chars().count() < KEY_LENGTH {
        padded.push_str(password);
    }

    // Step 2: Truncate to exactly 32 characters
    let truncated: String = padded.chars().take(KEY_LENGTH).collect();

    // Step 3: Apply MD5 iterations if re_encryption_count > 0
    if re_encryption_count > 0 {
        apply_md5_iterations(&truncated, re_encryption_count)
    } else {
        truncated
    }
}

/// Apply MD5 hash repeatedly
fn apply_md5_iterations(input: &str, count: u32) -> String {
    let mut result = input.to_string();
    for _ in 0..count {
        result = md5_hex(&result);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let expected_hash = super::md5_hex(&padded);
        assert_eq!(&key[..], expected_hash.as_bytes());
    }

}
