//! Comprehensive tests for the crypto module

use super::aes::{encrypt, decrypt};
use super::md5::md5_hex;
use super::key;

// Test character set matching C# CommonUT.RandomString
const TEST_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\
    0123456789_!@#$%^&*()<>,./?ЙЦУКЕНГШЩЗФЫВАПРОЛДЯЧСМИТЬБЮйцукенгшщзхъфывапролджэёячсмитьбю";

fn random_string(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let chars: Vec<char> = TEST_CHARS.chars().collect();
    (0..len)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect()
}

/// Stress test with short strings - from C# SecurityStressFixture.StressShortStrings
/// 100 iterations, strings up to 100 chars
#[test]
fn test_stress_short_strings() {
    use rand::Rng;
    let mut rng = rand::rng();

    for i in 0..100 {
        let password_len: usize = rng.random_range(1..100);
        let data_len: usize = rng.random_range(1..100);

        let password = random_string(password_len);
        let plaintext = random_string(data_len);

        let encrypted = encrypt(&plaintext, &password, 0, None)
            .expect(&format!("Encryption should succeed, iteration {}", i));

        let decrypted = decrypt(&encrypted, &password, 0, None)
            .expect(&format!("Decryption should succeed, iteration {}", i));

        assert_eq!(decrypted, plaintext, "Mismatch at iteration {}", i);
    }
}

/// Stress test with long strings - from C# SecurityStressFixture.StressLongStrings
/// 100 iterations, strings up to 1000 chars
#[test]
fn test_stress_long_strings() {
    use rand::Rng;
    let mut rng = rand::rng();

    for i in 0..100 {
        let password_len: usize = rng.random_range(1..100);
        let data_len: usize = rng.random_range(1..1000);

        let password = random_string(password_len);
        let plaintext = random_string(data_len);

        let encrypted = encrypt(&plaintext, &password, 0, None)
            .expect(&format!("Encryption should succeed, iteration {}", i));

        let decrypted = decrypt(&encrypted, &password, 0, None)
            .expect(&format!("Decryption should succeed, iteration {}", i));

        assert_eq!(decrypted, plaintext, "Mismatch at iteration {}", i);
    }
}

/// Stress test with huge strings - from C# SecurityStressFixture.StressHugeStrings
/// 10 iterations (reduced from 100), strings up to 60000 chars
#[test]
fn test_stress_huge_strings() {
    use rand::Rng;
    let mut rng = rand::rng();

    // Reduced iterations for huge strings (C# had 100, we use 10 for test speed)
    for i in 0..10 {
        let password_len: usize = rng.random_range(1..100);
        let data_len: usize = rng.random_range(1..60000);

        let password = random_string(password_len);
        let plaintext = random_string(data_len);

        let encrypted = encrypt(&plaintext, &password, 0, None)
            .expect(&format!("Encryption should succeed, iteration {}", i));

        let decrypted = decrypt(&encrypted, &password, 0, None)
            .expect(&format!("Decryption should succeed, iteration {}", i));

        assert_eq!(decrypted, plaintext, "Mismatch at iteration {}", i);
    }
}

/// Test with special characters
#[test]
fn test_special_characters() {
    let password = "P@ssw0rd!#$%";
    let plaintext = "Test Item 123 !@#$%'\"";

    let encrypted = encrypt(plaintext, password, 0, None).unwrap();
    let decrypted = decrypt(&encrypted, password, 0, None).unwrap();

    assert_eq!(decrypted, plaintext);
}

/// Test with Cyrillic characters
#[test]
fn test_cyrillic_data() {
    let password = "Password123";
    let plaintext = "аиыфьиафывр78ыфвафы23 !@#$%'\"";

    let encrypted = encrypt(plaintext, password, 0, None).unwrap();
    let decrypted = decrypt(&encrypted, password, 0, None).unwrap();

    assert_eq!(decrypted, plaintext);
}

/// Test iOS workaround for legacy data
#[test]
fn test_ios_workaround() {
    // This test verifies that the iOS workaround is attempted on decryption failure
    // The actual iOS-encrypted data would have key[0] = 0

    let password = "TestPass";
    let plaintext = "Test data";

    // Create key with first byte zeroed (simulating iOS bug)
    let mut ios_key = key::prepare_key(password, None, 0);
    ios_key[0] = 0;

    // Encrypt with iOS-style key directly using raw crate references
    use ::aes::Aes256;
    use ::cbc::Encryptor;
    use ::cbc::cipher::{BlockModeEncrypt, KeyIvInit};
    use ::block_padding::Pkcs7;

    let md5_checksum = md5_hex(plaintext);
    let full_text = format!("{}{}", md5_checksum, plaintext);
    let data = full_text.as_bytes();

    let block_size = 16;
    let padded_len = ((data.len() / block_size) + 1) * block_size;
    let mut buffer = vec![0u8; padded_len];
    buffer[..data.len()].copy_from_slice(data);

    let encryptor = Encryptor::<Aes256>::new(&ios_key.into(), &[0u8; 16].into());
    let encrypted = encryptor
        .encrypt_padded::<Pkcs7>(&mut buffer, data.len())
        .unwrap();

    // Normal decryption should work due to iOS fallback
    let decrypted = decrypt(encrypted, password, 0, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Test encryption output size
#[test]
fn test_encryption_output_size() {
    let password = "Test";

    // Input: 32 (MD5) + 9 (plaintext) = 41 bytes
    // Padded to next 16-byte block = 48 bytes
    let plaintext = "Test Item"; // 9 chars

    let encrypted = encrypt(plaintext, password, 0, None).unwrap();
    assert_eq!(encrypted.len(), 48);

    // Longer input
    let long_plaintext = "A".repeat(100);
    // Input: 32 + 100 = 132 bytes
    // Padded to 144 bytes (9 * 16)
    let encrypted_long = encrypt(&long_plaintext, password, 0, None).unwrap();
    assert_eq!(encrypted_long.len(), 144);
}

/// Test block-aligned plaintext (16 chars → MD5+plaintext = 48 bytes = 3 blocks)
/// PKCS7 adds a full 16-byte padding block → 64 bytes output.
/// This edge case is the most likely to break across padding library upgrades.
#[test]
fn test_block_aligned_16_char() {
    let password = "TestVector2025!";
    let plaintext = "ABCDEFGHIJKLMNOP"; // exactly 16 chars

    let expected: [u8; 64] = [
        0xbf, 0x6b, 0xfd, 0x7f, 0xbc, 0x59, 0x71, 0x79,
        0x4a, 0x76, 0x48, 0x31, 0xc9, 0x2f, 0x1f, 0x8d,
        0x36, 0xe3, 0x08, 0x12, 0x20, 0xa9, 0xaa, 0xeb,
        0x47, 0x4a, 0x98, 0xf1, 0x49, 0xff, 0xe3, 0x22,
        0x51, 0x11, 0x5e, 0x76, 0x5a, 0x81, 0x71, 0xa0,
        0x2c, 0x1f, 0x33, 0xee, 0xb1, 0xdd, 0x8a, 0x3a,
        0x40, 0xae, 0x85, 0x43, 0xcc, 0xa7, 0xff, 0x85,
        0x5f, 0x1f, 0x96, 0xed, 0x84, 0x15, 0x8b, 0x5a,
    ];

    let encrypted = encrypt(plaintext, password, 0, None).unwrap();
    assert_eq!(encrypted.len(), 64); // 3 data blocks + 1 padding block
    assert_eq!(encrypted, expected.to_vec());

    let decrypted = decrypt(&encrypted, password, 0, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Test block-aligned plaintext (32 chars → MD5+plaintext = 64 bytes = 4 blocks)
/// PKCS7 adds a full 16-byte padding block → 80 bytes output.
#[test]
fn test_block_aligned_32_char() {
    let password = "TestVector2025!";
    let plaintext = "ABCDEFGHIJKLMNOPabcdefghijklmnop"; // exactly 32 chars

    let expected: [u8; 80] = [
        0x29, 0x2d, 0xde, 0xd7, 0x8a, 0x88, 0x47, 0x6a,
        0xa6, 0xa9, 0xc8, 0xe9, 0xea, 0x60, 0xe9, 0x68,
        0x7c, 0xfd, 0x70, 0x7c, 0xc0, 0x6e, 0xe9, 0x1c,
        0x9f, 0xc8, 0x27, 0x21, 0xee, 0x15, 0xf0, 0x89,
        0xce, 0x94, 0x94, 0xe6, 0x7a, 0xb7, 0x28, 0x02,
        0x67, 0xa2, 0x9b, 0xe3, 0xf8, 0x6a, 0x67, 0xda,
        0xa6, 0x4d, 0x6e, 0xa9, 0xeb, 0x56, 0x0e, 0x4f,
        0x78, 0xec, 0xa4, 0xde, 0xab, 0x2e, 0x5b, 0xaa,
        0xc9, 0xba, 0xec, 0xdc, 0x66, 0xd8, 0x0e, 0x63,
        0xd1, 0xf9, 0xff, 0x2c, 0xb3, 0x4b, 0x4d, 0xfc,
    ];

    let encrypted = encrypt(plaintext, password, 0, None).unwrap();
    assert_eq!(encrypted.len(), 80); // 4 data blocks + 1 padding block
    assert_eq!(encrypted, expected.to_vec());

    let decrypted = decrypt(&encrypted, password, 0, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Regression vector: re_encryption_count=200 (app default)
/// Hardcoded ciphertext ensures any future crypto library upgrade doesn't
/// silently change encryption output for the most common app configuration.
#[test]
fn test_regression_vector_count_200() {
    let password = "MyWallet#99";
    let plaintext = "SecretPassword123";

    let expected: [u8; 64] = [
        0x87, 0xd0, 0x84, 0x88, 0x87, 0x6d, 0xb8, 0x4a,
        0xab, 0x61, 0x56, 0xe8, 0x76, 0x7f, 0x8e, 0x9a,
        0xf9, 0x71, 0xa6, 0x7a, 0xea, 0xb7, 0xf9, 0xc6,
        0x8c, 0x6a, 0x40, 0x38, 0x1a, 0xae, 0xa3, 0x94,
        0x66, 0x09, 0xf6, 0x46, 0x50, 0x48, 0x3a, 0xf4,
        0xa9, 0x7a, 0xd7, 0x9a, 0xb6, 0xcf, 0x67, 0xb5,
        0xb9, 0x34, 0x09, 0x50, 0xfa, 0x7e, 0x12, 0xe4,
        0x6b, 0xe9, 0x61, 0x73, 0x74, 0xe1, 0xc5, 0x50,
    ];

    // Verify encryption produces exact same bytes
    let encrypted = encrypt(plaintext, password, 200, None).unwrap();
    assert_eq!(encrypted, expected.to_vec());

    // Verify decryption of hardcoded bytes works
    let decrypted = decrypt(&expected, password, 200, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Regression vector: Cyrillic password + plaintext with re_encryption_count=200
/// Guards against encoding-related regressions in key derivation and encryption.
#[test]
fn test_regression_vector_cyrillic_count_200() {
    let password = "Пароль123";
    let plaintext = "Привет мир!";

    let expected: [u8; 64] = [
        0x14, 0x7b, 0xea, 0x9b, 0xfa, 0x2d, 0xb6, 0x7a,
        0xff, 0x0b, 0x35, 0x62, 0x33, 0xa4, 0x58, 0x4e,
        0x2a, 0x87, 0x25, 0x31, 0x5e, 0x50, 0xf4, 0x20,
        0xf9, 0x9c, 0xea, 0x73, 0xeb, 0x98, 0x7e, 0x02,
        0xfa, 0x84, 0xd4, 0x65, 0xe6, 0xfd, 0x61, 0x6c,
        0xd4, 0x3a, 0xb7, 0xc4, 0xa5, 0xbf, 0xb7, 0x62,
        0xa1, 0xcd, 0x3e, 0xc5, 0x3e, 0xab, 0x8b, 0x89,
        0xc6, 0x63, 0xd9, 0x8f, 0x63, 0x40, 0x14, 0x8d,
    ];

    // Verify encryption produces exact same bytes
    let encrypted = encrypt(plaintext, password, 200, None).unwrap();
    assert_eq!(encrypted, expected.to_vec());

    // Verify decryption of hardcoded bytes works
    let decrypted = decrypt(&expected, password, 200, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Test with hash parameter
#[test]
fn test_with_hash_parameter() {
    let password = "ignored_password";
    let hash = "12345678901234567890123456789012"; // 32 chars
    let plaintext = "Test data";

    // When hash is provided with re_encryption_count > 0, hash is used as key
    let encrypted = encrypt(plaintext, password, 1, Some(hash)).unwrap();
    let decrypted = decrypt(&encrypted, password, 1, Some(hash)).unwrap();

    assert_eq!(decrypted, plaintext);
}
