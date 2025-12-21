//! AES-256-CBC encryption and decryption
//!
//! This module implements the exact encryption scheme from the original C# code:
//! - AES-256-CBC with PKCS7 padding
//! - Fixed zero IV (16 bytes of zeros)
//! - MD5 checksum prepended to plaintext before encryption
//!
//! **IMPORTANT**: The zero IV is a security weakness but is required for
//! backward compatibility with existing encrypted data.

use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use block_padding::Pkcs7;

use super::key::{prepare_key, KEY_LENGTH};
use super::md5::md5_hex;

/// IV size for AES-CBC (16 bytes = 128 bits)
const IV_SIZE: usize = 16;

/// Fixed zero IV for backward compatibility
/// WARNING: This is a security weakness but required for compatibility
const ZERO_IV: [u8; IV_SIZE] = [0u8; IV_SIZE];

/// MD5 hex string length
const MD5_HEX_LENGTH: usize = 32;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Encrypt plaintext using AES-256-CBC
///
/// # Arguments
///
/// * `plaintext` - The text to encrypt
/// * `password` - The encryption password
/// * `re_encryption_count` - Number of MD5 iterations for key derivation
/// * `hash` - Optional pre-computed hash
///
/// # Returns
///
/// Encrypted bytes on success, or error message on failure
pub fn encrypt(
    plaintext: &str,
    password: &str,
    re_encryption_count: u32,
    hash: Option<&str>,
) -> Result<Vec<u8>, String> {
    // Derive encryption key
    let key = prepare_key(password, hash, re_encryption_count);

    // Prepend MD5 checksum to plaintext
    let md5_checksum = md5_hex(plaintext);
    let full_text = format!("{}{}", md5_checksum, plaintext);
    let data = full_text.as_bytes();

    // Calculate padded length (must be multiple of 16)
    let block_size = 16;
    let padded_len = ((data.len() / block_size) + 1) * block_size;

    // Create buffer with space for padding
    let mut buffer = vec![0u8; padded_len];
    buffer[..data.len()].copy_from_slice(data);

    // Create encryptor and encrypt
    let encryptor = Aes256CbcEnc::new(&key.into(), &ZERO_IV.into());

    let encrypted = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    Ok(encrypted.to_vec())
}

/// Decrypt ciphertext using AES-256-CBC
///
/// Implements the original decryption with iOS workaround fallback:
/// 1. Try normal decryption
/// 2. If MD5 verification fails, try iOS workaround (zero first byte of key)
///
/// # Arguments
///
/// * `ciphertext` - The encrypted bytes
/// * `password` - The decryption password
/// * `re_encryption_count` - Number of MD5 iterations for key derivation
/// * `hash` - Optional pre-computed hash
///
/// # Returns
///
/// Decrypted plaintext on success, or error message on failure
pub fn decrypt(
    ciphertext: &[u8],
    password: &str,
    re_encryption_count: u32,
    hash: Option<&str>,
) -> Result<String, String> {
    // Try normal decryption first
    let key = prepare_key(password, hash, re_encryption_count);

    match decrypt_with_key(ciphertext, &key) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => {
            // Try iOS workaround: zero first byte of key
            let mut ios_key = key;
            ios_key[0] = 0;
            decrypt_with_key(ciphertext, &ios_key)
        }
    }
}

/// Internal decryption with a specific key
fn decrypt_with_key(ciphertext: &[u8], key: &[u8; KEY_LENGTH]) -> Result<String, String> {
    if ciphertext.is_empty() {
        return Err("Empty ciphertext".to_string());
    }

    // Create a mutable copy for in-place decryption
    let mut buffer = ciphertext.to_vec();

    // Create decryptor and decrypt
    let decryptor = Aes256CbcDec::new(key.into(), &ZERO_IV.into());

    let decrypted = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    // Convert to UTF-8 string
    let full_text = String::from_utf8(decrypted.to_vec())
        .map_err(|e| format!("Invalid UTF-8: {}", e))?;

    // Verify MD5 checksum
    if full_text.len() < MD5_HEX_LENGTH {
        return Err("Decrypted text too short".to_string());
    }

    let (checksum, plaintext) = full_text.split_at(MD5_HEX_LENGTH);
    let computed_checksum = md5_hex(plaintext);

    if checksum != computed_checksum {
        return Err("MD5 checksum mismatch".to_string());
    }

    Ok(plaintext.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from C# SecurityFixture.cs - TestCaseEncrypt
    #[test]
    fn test_encrypt_vector() {
        let password = "Sun001!";
        let plaintext = "Test Item";

        // Expected output from C# implementation
        let expected: [u8; 48] = [
            0x03, 0xde, 0xd5, 0x8a, 0x00, 0xcf, 0x22, 0x15,
            0x76, 0x6b, 0x57, 0x5d, 0xbe, 0xdb, 0xf2, 0xd2,
            0x0f, 0x84, 0xec, 0x9b, 0x68, 0x41, 0x59, 0xb3,
            0x05, 0x6f, 0x75, 0x45, 0xe7, 0x1b, 0xe4, 0x9d,
            0x1d, 0xef, 0xa5, 0xb2, 0x9d, 0xcd, 0x4a, 0x06,
            0xa1, 0x18, 0xa8, 0xa6, 0x91, 0x29, 0x13, 0x00,
        ];

        let result = encrypt(plaintext, password, 0, None).unwrap();
        assert_eq!(result, expected.to_vec());
    }

    /// Test vector from C# SecurityFixture.cs - TestCaseDecrypt
    #[test]
    fn test_decrypt_vector() {
        let password = "Sun001!";

        // Encrypted data from C# implementation (first 96 bytes as shown in test)
        let encrypted: [u8; 112] = [
            0x53, 0xda, 0x92, 0xa5, 0xf5, 0x48, 0x90, 0xc5,
            0xd5, 0xb4, 0x13, 0xbb, 0xad, 0x51, 0xc5, 0xf6,
            0xfb, 0xf2, 0xa3, 0x0a, 0x27, 0x98, 0x7c, 0xed,
            0xad, 0x9e, 0xea, 0xed, 0x08, 0xa7, 0xd8, 0xa1,
            0x42, 0x0c, 0xe1, 0xe4, 0xf4, 0xf5, 0x16, 0x03,
            0x96, 0x55, 0x80, 0xc6, 0x88, 0x39, 0x16, 0x85,
            0x2e, 0xce, 0x48, 0xf9, 0x8d, 0x5e, 0x6e, 0xb4,
            0x53, 0x36, 0x51, 0x2e, 0x86, 0x1f, 0xff, 0xb6,
            0x89, 0xf2, 0xbb, 0x5b, 0x49, 0x2c, 0x7d, 0x92,
            0xae, 0x23, 0xac, 0xbb, 0x3f, 0xd2, 0x91, 0x21,
            0x98, 0x20, 0x18, 0x45, 0xad, 0xa0, 0x9a, 0x14,
            0x18, 0x99, 0xec, 0x2d, 0xed, 0x29, 0xb9, 0xd0,
            0x2f, 0xed, 0xe9, 0xe4, 0xd2, 0xf3, 0x3d, 0x87,
            0x89, 0xf5, 0xd3, 0xda, 0xb7, 0x6d, 0xda, 0x55,
        ];

        let expected = "nhh86c4uQKXu8rTjp4sL8rr2fxRMmnhWWhan8LiaVb4ZhTdF4RTlX4xcHYjwsfDu";

        let result = decrypt(&encrypted, password, 0, None).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "TestPassword123!";
        let plaintext = "Hello, World! This is a test message.";

        let encrypted = encrypt(plaintext, password, 0, None).unwrap();
        let decrypted = decrypt(&encrypted, password, 0, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_utf8() {
        let password = "TestPassword";
        let plaintext = "Привет мир! 你好世界! مرحبا بالعالم";

        let encrypted = encrypt(plaintext, password, 0, None).unwrap();
        let decrypted = decrypt(&encrypted, password, 0, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let password = "TestPassword";
        let plaintext = "";

        let encrypted = encrypt(plaintext, password, 0, None).unwrap();
        let decrypted = decrypt(&encrypted, password, 0, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let plaintext = "Secret message";
        let encrypted = encrypt(plaintext, "correct_password", 0, None).unwrap();

        let result = decrypt(&encrypted, "wrong_password", 0, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_with_reencryption_count() {
        let password = "TestPassword";
        let plaintext = "Test with reencryption";

        // Encrypt with re_encryption_count = 2
        let encrypted = encrypt(plaintext, password, 2, None).unwrap();

        // Must decrypt with same re_encryption_count
        let decrypted = decrypt(&encrypted, password, 2, None).unwrap();
        assert_eq!(decrypted, plaintext);

        // Different re_encryption_count should fail
        let result = decrypt(&encrypted, password, 0, None);
        assert!(result.is_err());
    }
}
