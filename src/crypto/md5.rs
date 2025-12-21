//! MD5 hashing for data integrity verification
//!
//! The original NSWallet prepends an MD5 hash to plaintext before encryption
//! to verify data integrity on decryption.

use md5::{Md5, Digest};

/// Calculate MD5 hash of input string and return as lowercase hex string (32 chars)
///
/// # Example
///
/// ```
/// use iwcore::crypto::md5_hex;
///
/// assert_eq!(md5_hex("Test Item"), "e1c47101f7939099b633e61b3514c623");
/// ```
pub fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();

    // Convert to lowercase hex string
    result.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_ascii() {
        assert_eq!(
            md5_hex("Bsegge647TY.%22"),
            "7ee62f73f9c08a15f0472fa6c4b63361"
        );
    }

    #[test]
    fn test_md5_cyrillic() {
        assert_eq!(
            md5_hex("Проверка UTF8"),
            "c063c2eb08c2c0005e25e94d351ac44f"
        );
    }

    #[test]
    fn test_md5_simple() {
        assert_eq!(
            md5_hex("Test Item"),
            "e1c47101f7939099b633e61b3514c623"
        );
    }

    #[test]
    fn test_md5_empty() {
        assert_eq!(
            md5_hex(""),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }
}
