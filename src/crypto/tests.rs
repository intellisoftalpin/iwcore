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
    use ::cbc::cipher::{BlockEncryptMut, KeyIvInit};
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
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
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
