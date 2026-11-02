//! AES-256-CBC encryption and decryption
//!
//! This module implements the exact encryption scheme from the original C# code:
//! - AES-256-CBC with PKCS7 padding
//! - Fixed zero IV (16 bytes of zeros)
//! - MD5 checksum prepended to plaintext before encryption
//!
//! **IMPORTANT**: The zero IV is a security weakness but is required for
//! backward compatibility with existing encrypted data.

#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

use aes::Aes256;
#[cfg(test)]
use cbc::Encryptor;
#[cfg(test)]
use cbc::cipher::BlockModeEncrypt;
use cbc::Decryptor;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use block_padding::Pkcs7;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::key::{prepare_key, KEY_LENGTH};
use super::md5::md5_hex;

/// IV size for AES-CBC (16 bytes = 128 bits)
const IV_SIZE: usize = 16;

/// Fixed zero IV for backward compatibility
/// WARNING: This is a security weakness but required for compatibility
const ZERO_IV: [u8; IV_SIZE] = [0u8; IV_SIZE];

/// MD5 hex string length
const MD5_HEX_LENGTH: usize = 32;

#[cfg(test)]
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
///
/// Test-only: the legacy scheme is never written, it is only read for the
/// migration. Tests use this to build legacy fixtures.
#[cfg(test)]
pub(crate) fn encrypt(
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

    // Buffer with room for the PKCS7 padding (always 1..=16 extra bytes).
    let padded_len = padded_len(data.len())
        .ok_or_else(|| "Encryption failed: plaintext too long".to_string())?;
    let mut buffer = data.to_vec();
    buffer.resize(padded_len, 0);

    // Create encryptor and encrypt
    let encryptor = Aes256CbcEnc::new(&key.into(), &ZERO_IV.into());

    let encrypted = encryptor
        .encrypt_padded::<Pkcs7>(&mut buffer, data.len())
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
///
/// Test-only reference for the single stored-count derivation; the migration
/// reads through [`LegacyKeyChain`], which tries this key first.
#[cfg(test)]
pub(crate) fn decrypt(
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
            decrypt_with_key(ciphertext, &ios_variant(key))
        }
    }
}

/// Length of a PKCS7-padded buffer for `len` bytes of input: the next
/// multiple of the block size strictly greater than `len`.
#[cfg(test)]
fn padded_len(len: usize) -> Option<usize> {
    len.checked_div(IV_SIZE)?.checked_add(1)?.checked_mul(IV_SIZE)
}

/// The iOS-workaround variant of a key: the same key with its first byte
/// zeroed.
fn ios_variant(key: [u8; KEY_LENGTH]) -> [u8; KEY_LENGTH] {
    let mut k = key;
    if let Some(first) = k.first_mut() {
        *first = 0;
    }
    k
}

/// Key-derivation modes the original C# app effectively used over its life.
///
/// The C# `prepareKey(password, hash, count)` had three outcomes, because
/// every caller passed the password itself as `hash`:
/// - count == 0: padded/doubled password truncated to 32 chars, no MD5
///   (the only path the 5.x app's ENCRYPT callers ever used — they hardcoded
///   count 0, and a non-empty `hash` suppressed the MD5 chain anyway);
/// - count > 0 with empty hash: the MD5-iterated chain (never reached by the
///   5.x callers, but possibly by older app generations that wrote the data);
/// - count > 0 with non-empty hash: `key = hash` — i.e. the RAW password's
///   first 32 UTF-8 bytes (the path the 5.x app used at DECRYPT time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyKeyMode {
    /// Padded/truncated password, no MD5 iterations (count treated as 0).
    NoChain,
    /// Padded/truncated password + MD5^count chain.
    Md5Chain,
    /// Raw password bytes, first 32 UTF-8 bytes, zero-padded when shorter.
    RawPassword,
}

impl LegacyKeyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            LegacyKeyMode::NoChain => "no_chain",
            LegacyKeyMode::Md5Chain => "md5_chain",
            LegacyKeyMode::RawPassword => "raw_password",
        }
    }
}

/// First 32 UTF-8 bytes of the raw password, zero-padded (the C# `key = hash`
/// path; C# threw for shorter passwords, zero-padding just makes the attempt
/// harmless).
fn raw_password_key(password: &str) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    for (dst, src) in key.iter_mut().zip(password.as_bytes()) {
        *dst = *src;
    }
    key
}

/// All plausible legacy key candidates for one vault, each with its
/// iOS-workaround variant (first byte zeroed), tried in order until the
/// MD5-checksum validation inside `decrypt_with_key` passes. The chain
/// remembers the last successful candidate/variant and tries it first for
/// the next blob, so bulk migration pays no repeated derivation or failed
/// AES passes once the vault's real mode is known.
///
/// For `re_encryption_count == 0` all three C# modes collapse into one key,
/// so the chain holds a single candidate and behaves exactly like a one-shot
/// decrypt with the stored count — zero change for the healthy majority of
/// vaults.
///
/// Every candidate key is wiped when the chain is dropped.
pub struct LegacyKeyChain {
    /// (mode, normal key, iOS-workaround key)
    candidates: Vec<(LegacyKeyMode, [u8; KEY_LENGTH], [u8; KEY_LENGTH])>,
    /// Index of the candidate that decrypted the previous blob.
    preferred: usize,
    /// Whether the preferred candidate succeeded via its iOS variant.
    prefer_ios: bool,
}

impl Zeroize for LegacyKeyChain {
    fn zeroize(&mut self) {
        for (_, key, ios_key) in self.candidates.iter_mut() {
            key.zeroize();
            ios_key.zeroize();
        }
        self.candidates.clear();
        self.preferred = 0;
        self.prefer_ios = false;
    }
}

impl Drop for LegacyKeyChain {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for LegacyKeyChain {}

impl LegacyKeyChain {
    /// The historical default iteration count of the C# app (`// 200` in its
    /// model). Tried as an extra MD5-chain candidate even when the stored
    /// count differs, because real vaults exist whose `email` column was
    /// lost, zeroed, or rewritten while the data kept the old derivation.
    const DEFAULT_HISTORICAL_COUNT: u32 = 200;

    pub fn new(password: &str, re_encryption_count: u32) -> Self {
        let ios = ios_variant;

        let mut candidates = Vec::with_capacity(4);
        if re_encryption_count > 0 {
            // Chain-with-stored-count first: matches what this crate has
            // always tried, so any vault that unlocked before keeps
            // unlocking via the same key on the first attempt.
            let chained = prepare_key(password, None, re_encryption_count);
            candidates.push((LegacyKeyMode::Md5Chain, chained, ios(chained)));
        }
        // What the 5.x app actually WROTE with (count hardcoded to 0). For
        // count == 0 vaults this is the first and usually only attempt.
        let plain = prepare_key(password, None, 0);
        candidates.push((LegacyKeyMode::NoChain, plain, ios(plain)));
        // The historical default chain, unless it is already covered above.
        if re_encryption_count != Self::DEFAULT_HISTORICAL_COUNT {
            let default_chained =
                prepare_key(password, None, Self::DEFAULT_HISTORICAL_COUNT);
            candidates.push((LegacyKeyMode::Md5Chain, default_chained, ios(default_chained)));
        }
        // What the 5.x app DECRYPTED with when count > 0 (`key = hash`).
        let raw = raw_password_key(password);
        candidates.push((LegacyKeyMode::RawPassword, raw, ios(raw)));

        Self { candidates, preferred: 0, prefer_ios: false }
    }

    /// The mode of the candidate that decrypted the most recent blob.
    pub fn preferred_mode(&self) -> LegacyKeyMode {
        // `preferred` is only ever set to an index of `candidates`.
        self.candidates
            .get(self.preferred)
            .map_or(LegacyKeyMode::NoChain, |c| c.0)
    }

    /// Decrypt a legacy blob, trying the last-successful candidate/variant
    /// first, then every remaining candidate (normal then iOS variant).
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<String, String> {
        // Preferred candidate, preferred variant first.
        if let Some((_, key, ios_key)) = self.candidates.get(self.preferred) {
            let (first, second) = if self.prefer_ios { (ios_key, key) } else { (key, ios_key) };
            if let Ok(plaintext) = decrypt_with_key(ciphertext, first) {
                return Ok(plaintext);
            }
            if let Ok(plaintext) = decrypt_with_key(ciphertext, second) {
                self.prefer_ios = !self.prefer_ios;
                return Ok(plaintext);
            }
        }

        // Remaining candidates in declaration order. Only the final failure
        // message survives; the per-variant errors carry no extra signal.
        let mut last_err = String::from("no key candidate matched");
        for (idx, (_, key, ios_key)) in self.candidates.iter().enumerate() {
            if idx == self.preferred {
                continue;
            }
            if let Ok(plaintext) = decrypt_with_key(ciphertext, key) {
                self.preferred = idx;
                self.prefer_ios = false;
                return Ok(plaintext);
            }
            match decrypt_with_key(ciphertext, ios_key) {
                Ok(plaintext) => {
                    self.preferred = idx;
                    self.prefer_ios = true;
                    return Ok(plaintext);
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

/// Internal decryption with a specific key
fn decrypt_with_key(ciphertext: &[u8], key: &[u8; KEY_LENGTH]) -> Result<String, String> {
    if ciphertext.is_empty() {
        return Err("Empty ciphertext".to_string());
    }

    // Create a mutable copy for in-place decryption; it ends up holding the
    // plaintext, so it is wiped on drop.
    let mut buffer = Zeroizing::new(ciphertext.to_vec());

    // Create decryptor and decrypt
    let decryptor = Aes256CbcDec::new(key.into(), &ZERO_IV.into());

    let decrypted = decryptor
        .decrypt_padded::<Pkcs7>(&mut buffer)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    // Validate UTF-8 in place (no further copy of the plaintext).
    let full_text = std::str::from_utf8(decrypted)
        .map_err(|e| format!("Invalid UTF-8: {}", e))?;

    // Verify MD5 checksum. The checksum is 32 ASCII hex characters; a
    // plaintext that is shorter, or whose 32nd byte is inside a multi-byte
    // character, is malformed and refused.
    if full_text.len() < MD5_HEX_LENGTH {
        return Err("Decrypted text too short".to_string());
    }
    let (Some(checksum), Some(plaintext)) =
        (full_text.get(..MD5_HEX_LENGTH), full_text.get(MD5_HEX_LENGTH..))
    else {
        return Err("Malformed checksum prefix".to_string());
    };
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

    /// Encrypt with an explicit key, bypassing prepare_key — used to fabricate
    /// ciphertext written under the iOS-workaround key variant.
    fn encrypt_with_raw_key(plaintext: &str, key: &[u8; KEY_LENGTH]) -> Vec<u8> {
        let md5_checksum = md5_hex(plaintext);
        let full_text = format!("{}{}", md5_checksum, plaintext);
        let data = full_text.as_bytes();
        let padded_len = ((data.len() / 16) + 1) * 16;
        let mut buffer = vec![0u8; padded_len];
        buffer[..data.len()].copy_from_slice(data);
        let encryptor = Aes256CbcEnc::new(key.into(), &ZERO_IV.into());
        encryptor
            .encrypt_padded::<Pkcs7>(&mut buffer, data.len())
            .unwrap()
            .to_vec()
    }

    /// Encrypt raw bytes under `key` with no checksum prefix, so a test can
    /// choose exactly what the decrypted plaintext looks like.
    fn encrypt_raw_bytes(data: &[u8], key: &[u8; KEY_LENGTH]) -> Vec<u8> {
        let mut buffer = data.to_vec();
        buffer.resize(padded_len(data.len()).unwrap(), 0);
        Aes256CbcEnc::new(key.into(), &ZERO_IV.into())
            .encrypt_padded::<Pkcs7>(&mut buffer, data.len())
            .unwrap()
            .to_vec()
    }

    fn odd_plaintexts() -> Vec<(&'static str, Vec<u8>)> {
        let mut split_char = vec![b'a'; 31];
        split_char.extend_from_slice("ж tail".as_bytes()); // byte 32 is inside 'ж'
        let mut split_emoji = vec![b'0'; 30];
        split_emoji.extend_from_slice("😀".as_bytes()); // 4-byte char over byte 32
        vec![
            ("empty", Vec::new()),
            ("one byte", b"x".to_vec()),
            ("31 bytes", vec![b'f'; 31]),
            ("multi-byte char across byte 32", split_char),
            ("4-byte char across byte 32", split_emoji),
            ("only multi-byte chars", "жжжжжжжжжжжжжжжжжжжж".as_bytes().to_vec()),
            ("invalid utf-8", vec![0xff; 40]),
            ("32 bytes, wrong checksum", vec![b'0'; 32]),
            ("non-hex 32 bytes", vec![b'z'; 48]),
        ]
    }

    #[test]
    fn odd_legacy_plaintexts_are_errors_not_panics() {
        let password = "TestPassword123!";
        let key = prepare_key(password, None, 0);
        for (name, data) in odd_plaintexts() {
            let blob = encrypt_raw_bytes(&data, &key);
            assert!(decrypt_with_key(&blob, &key).is_err(), "{name}");
            assert!(decrypt(&blob, password, 0, None).is_err(), "{name}");
            assert!(decrypt(&blob, password, 200, Some(password)).is_err(), "{name}");
            let mut chain = LegacyKeyChain::new(password, 200);
            assert!(chain.decrypt(&blob).is_err(), "{name}");
        }
    }

    #[test]
    fn checksum_prefix_split_inside_a_character_is_refused() {
        let key = prepare_key("pw", None, 0);
        let mut data = vec![b'a'; 31];
        data.extend_from_slice("жж".as_bytes());
        let err = decrypt_with_key(&encrypt_raw_bytes(&data, &key), &key).unwrap_err();
        assert_eq!(err, "Malformed checksum prefix");
        let short = decrypt_with_key(&encrypt_raw_bytes(b"abc", &key), &key).unwrap_err();
        assert_eq!(short, "Decrypted text too short");
    }

    #[test]
    fn exactly_a_checksum_decrypts_to_empty() {
        let key = prepare_key("pw", None, 0);
        let blob = encrypt_raw_bytes(md5_hex("").as_bytes(), &key);
        assert_eq!(decrypt_with_key(&blob, &key).unwrap(), "");
    }

    #[test]
    fn malformed_ciphertexts_are_errors() {
        let password = "pw";
        let mut chain = LegacyKeyChain::new(password, 7);
        for blob in [vec![], vec![0u8; 1], vec![0u8; 15], vec![0u8; 16], vec![0xAB; 33], vec![0u8; 64]] {
            assert!(decrypt(&blob, password, 0, None).is_err());
            assert!(chain.decrypt(&blob).is_err());
        }
        assert_eq!(chain.preferred_mode(), LegacyKeyMode::Md5Chain);
    }

    #[test]
    fn padding_length_and_ios_variant() {
        assert_eq!(padded_len(0), Some(16));
        assert_eq!(padded_len(15), Some(16));
        assert_eq!(padded_len(16), Some(32));
        assert_eq!(padded_len(usize::MAX), None);
        let v = ios_variant([7u8; KEY_LENGTH]);
        assert_eq!(v[0], 0);
        assert!(v[1..].iter().all(|b| *b == 7));
    }

    #[test]
    fn test_key_chain_matches_decrypt_for_md5_chain_data() {
        // Synthetic vaults whose data really was written with the MD5 chain
        // must keep decrypting exactly as before (first candidate wins).
        let password = "TestPassword123!";
        for count in [0u32, 2, 200] {
            let plaintext = format!("record at count {count}");
            let encrypted = encrypt(&plaintext, password, count, None).unwrap();
            let mut chain = LegacyKeyChain::new(password, count);
            assert_eq!(chain.decrypt(&encrypted).unwrap(), plaintext);
            let expected_mode = if count == 0 {
                LegacyKeyMode::NoChain
            } else {
                LegacyKeyMode::Md5Chain
            };
            assert_eq!(chain.preferred_mode(), expected_mode);
            // Same result as the one-shot path.
            assert_eq!(decrypt(&encrypted, password, count, None).unwrap(), plaintext);
        }
    }

    #[test]
    fn test_key_chain_candidate_sets() {
        // count 0: no-chain first (the healthy fast path), then the
        // historical default chain and the raw key as fallbacks.
        let chain = LegacyKeyChain::new("TestPassword123!", 0);
        assert_eq!(chain.candidates.len(), 3);
        assert_eq!(chain.candidates[0].0, LegacyKeyMode::NoChain);
        // count == historical default: no duplicate chain candidate.
        let chain200 = LegacyKeyChain::new("TestPassword123!", 200);
        assert_eq!(chain200.candidates.len(), 3);
        assert_eq!(chain200.candidates[0].0, LegacyKeyMode::Md5Chain);
        // other count: stored chain + no-chain + default chain + raw.
        let chain33 = LegacyKeyChain::new("TestPassword123!", 33);
        assert_eq!(chain33.candidates.len(), 4);
    }

    #[test]
    fn test_key_chain_default_count_fallback() {
        // Vault whose email column reads 0/NULL but whose data was written
        // with the historical default MD5 chain (200): the extra candidate
        // must recover it.
        let password = "TestPassword123!";
        let blob = encrypt("chained under 200", password, 200, None).unwrap();
        assert!(decrypt(&blob, password, 0, None).is_err());

        let mut chain = LegacyKeyChain::new(password, 0);
        assert_eq!(chain.decrypt(&blob).unwrap(), "chained under 200");
        assert_eq!(chain.preferred_mode(), LegacyKeyMode::Md5Chain);
    }

    #[test]
    fn test_key_chain_ios_variant_and_preference() {
        let password = "TestPassword123!";
        let mut ios_key = prepare_key(password, None, 0);
        ios_key[0] = 0;

        let ios_blob_1 = encrypt_with_raw_key("ios record one", &ios_key);
        let ios_blob_2 = encrypt_with_raw_key("ios record two", &ios_key);
        let normal_blob = encrypt("normal record", password, 0, None).unwrap();

        let mut chain = LegacyKeyChain::new(password, 0);
        // First iOS blob decrypts via the fallback and flips the preference...
        assert_eq!(chain.decrypt(&ios_blob_1).unwrap(), "ios record one");
        assert!(chain.prefer_ios);
        // ...so the second one hits the iOS variant on the first try.
        assert_eq!(chain.decrypt(&ios_blob_2).unwrap(), "ios record two");
        // A normal blob still decrypts (and flips the preference back).
        assert_eq!(chain.decrypt(&normal_blob).unwrap(), "normal record");
        assert!(!chain.prefer_ios);
    }

    #[test]
    fn test_key_chain_no_chain_fallback() {
        // The realistic 5.x scenario: email column says 200, but the app's
        // encrypt callers hardcoded count 0, so the data was written with
        // the un-chained key. The chain must fall back and remember it.
        let password = "TestPassword123!";
        let blob_1 = encrypt("written with count 0", password, 0, None).unwrap();
        let blob_2 = encrypt("second record", password, 0, None).unwrap();

        // The one-shot legacy decrypt (pre-chain behavior) fails here.
        assert!(decrypt(&blob_1, password, 200, None).is_err());

        let mut chain = LegacyKeyChain::new(password, 200);
        assert_eq!(chain.decrypt(&blob_1).unwrap(), "written with count 0");
        assert_eq!(chain.preferred_mode(), LegacyKeyMode::NoChain);
        // Preference sticks: second record hits the right key immediately.
        assert_eq!(chain.decrypt(&blob_2).unwrap(), "second record");
    }

    #[test]
    fn test_key_chain_raw_password_fallback() {
        // The C# `key = hash` decrypt path: raw password bytes as the key.
        // A short non-ASCII password makes this key genuinely different from
        // the padded/truncated derivations.
        let password = "пароль12"; // 8 chars, 14 UTF-8 bytes
        let raw = raw_password_key(password);
        assert_ne!(raw, prepare_key(password, None, 0));

        let blob = encrypt_with_raw_key("raw key record", &raw);
        assert!(decrypt(&blob, password, 200, None).is_err());

        let mut chain = LegacyKeyChain::new(password, 200);
        assert_eq!(chain.decrypt(&blob).unwrap(), "raw key record");
        assert_eq!(chain.preferred_mode(), LegacyKeyMode::RawPassword);
    }

    #[test]
    fn test_key_chain_mixed_modes_in_one_vault() {
        let password = "TestPassword123!";
        let chained_blob = encrypt("md5 chained", password, 200, None).unwrap();
        let plain_blob = encrypt("plain", password, 0, None).unwrap();

        let mut chain = LegacyKeyChain::new(password, 200);
        assert_eq!(chain.decrypt(&plain_blob).unwrap(), "plain");
        assert_eq!(chain.decrypt(&chained_blob).unwrap(), "md5 chained");
        assert_eq!(chain.decrypt(&plain_blob).unwrap(), "plain");
    }

    #[test]
    fn test_key_chain_wrong_password_fails() {
        let encrypted = encrypt("secret", "correct_password", 0, None).unwrap();
        assert!(LegacyKeyChain::new("wrong_password", 0).decrypt(&encrypted).is_err());
        // Even with all three candidates active, a wrong password never
        // passes the MD5 checksum.
        assert!(LegacyKeyChain::new("wrong_password", 200).decrypt(&encrypted).is_err());
    }

    #[test]
    fn key_chain_zeroize_wipes_every_candidate() {
        let mut chain = LegacyKeyChain::new("TestPassword123!", 33);
        assert_eq!(chain.candidates.len(), 4);
        chain.zeroize();
        assert!(chain.candidates.is_empty());
        assert_eq!(chain.preferred, 0);
        assert!(!chain.prefer_ios);
        // A wiped chain decrypts nothing, and does not panic.
        let blob = encrypt("x", "TestPassword123!", 0, None).unwrap();
        assert!(chain.decrypt(&blob).is_err());
        assert_eq!(chain.preferred_mode(), LegacyKeyMode::NoChain);
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<LegacyKeyChain>();
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
