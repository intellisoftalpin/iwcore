//! XChaCha20-Poly1305 authenticated encryption for item names and field values
//! (the v6 scheme).
//!
//! Blob layout (stored verbatim in the existing `name` / `value` BLOB columns):
//!
//! ```text
//! byte 0        : format tag = 0x06
//! bytes 1..25   : 24-byte XChaCha20 nonce (random per seal, OS CSPRNG)
//! bytes 25..N   : ciphertext
//! bytes N..N+16 : Poly1305 tag
//! ```
//!
//! The leading 0x06 tag lets readers distinguish a v6 blob from a legacy
//! (v5 AES-CBC) blob, which has no such tag.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::Rng;

/// Leading byte that marks a v6 AEAD blob.
pub const FORMAT_TAG: u8 = 0x06;
/// XChaCha20 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Key length (32 bytes = 256 bits).
pub const KEY_LEN: usize = 32;

/// Minimum length of a well-formed blob: tag byte + nonce + auth tag (empty
/// ciphertext is valid, e.g. an empty field value).
const MIN_BLOB_LEN: usize = 1 + NONCE_LEN + TAG_LEN;

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("key is exactly 32 bytes")
}

/// Returns true if `blob` looks like a v6 AEAD blob (tag byte + minimum length).
pub fn is_v6_blob(blob: &[u8]) -> bool {
    blob.len() >= MIN_BLOB_LEN && blob[0] == FORMAT_TAG
}

/// Encrypt `plaintext` under `key`, producing the self-describing blob above.
/// A fresh random 24-byte nonce is drawn from the OS CSPRNG on every call.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let ct = cipher(key)
        .encrypt(&nonce, plaintext)
        .map_err(|_| "AEAD seal failed".to_string())?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(FORMAT_TAG);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a v6 blob produced by [`seal`]. Returns an error on a malformed blob,
/// a wrong key, or any tampering (authentication failure).
pub fn open(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < MIN_BLOB_LEN {
        return Err("AEAD blob too short".to_string());
    }
    if blob[0] != FORMAT_TAG {
        return Err("not a v6 AEAD blob".to_string());
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&blob[1..1 + NONCE_LEN]);
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = &blob[1 + NONCE_LEN..];

    cipher(key)
        .decrypt(&nonce, ciphertext)
        .map_err(|_| "AEAD open failed (authentication)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];

    #[test]
    fn roundtrip() {
        let blob = seal(&KEY, b"hello secret").unwrap();
        assert_eq!(open(&KEY, &blob).unwrap(), b"hello secret");
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let blob = seal(&KEY, b"").unwrap();
        assert!(is_v6_blob(&blob));
        assert_eq!(open(&KEY, &blob).unwrap(), b"");
    }

    #[test]
    fn roundtrip_unicode() {
        let msg = "Привет мир! 你好世界! مرحبا".as_bytes();
        let blob = seal(&KEY, msg).unwrap();
        assert_eq!(open(&KEY, &blob).unwrap(), msg);
    }

    #[test]
    fn blob_is_self_describing() {
        let blob = seal(&KEY, b"x").unwrap();
        assert_eq!(blob[0], FORMAT_TAG);
        assert!(is_v6_blob(&blob));
        // 1 tag + 24 nonce + 1 ciphertext + 16 tag = 42
        assert_eq!(blob.len(), 1 + NONCE_LEN + 1 + TAG_LEN);
    }

    #[test]
    fn two_seals_differ_distinct_nonces() {
        let a = seal(&KEY, b"same plaintext").unwrap();
        let b = seal(&KEY, b"same plaintext").unwrap();
        assert_ne!(a, b, "nonce reuse would make these equal");
        // both still decrypt to the same plaintext
        assert_eq!(open(&KEY, &a).unwrap(), open(&KEY, &b).unwrap());
    }

    #[test]
    fn wrong_key_fails() {
        let blob = seal(&KEY, b"secret").unwrap();
        let wrong = [9u8; KEY_LEN];
        assert!(open(&wrong, &blob).is_err());
    }

    #[test]
    fn single_bit_tamper_is_detected() {
        let mut blob = seal(&KEY, b"important value").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip a bit in the tag
        assert!(open(&KEY, &blob).is_err(), "tamper must be rejected, not returned as garbage");
    }

    #[test]
    fn ciphertext_tamper_is_detected() {
        let mut blob = seal(&KEY, b"important value").unwrap();
        blob[1 + NONCE_LEN] ^= 0x01; // flip a bit in the ciphertext
        assert!(open(&KEY, &blob).is_err());
    }

    #[test]
    fn truncated_blob_fails() {
        let blob = seal(&KEY, b"secret").unwrap();
        assert!(open(&KEY, &blob[..MIN_BLOB_LEN - 1]).is_err());
    }

    #[test]
    fn legacy_blob_rejected() {
        // A legacy AES-CBC blob has no 0x06 tag.
        let legacy = vec![0x53u8, 0xda, 0x92, 0xa5];
        assert!(!is_v6_blob(&legacy));
        assert!(open(&KEY, &legacy).is_err());
    }
}
