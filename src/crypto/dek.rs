//! Data Encryption Key (DEK) generation and password-wrapping for the v6 scheme.
//!
//! The DEK is a random 32-byte key generated once per vault. All item names and
//! field values are encrypted under it via [`super::aead`]. The DEK itself is
//! stored wrapped (encrypted) under the password-derived KEK, so:
//!
//! - changing the password only re-wraps the DEK (data is untouched);
//! - raising the Argon2id cost only re-wraps the DEK (data is untouched);
//! - password verification is "can we unwrap the DEK" (the AEAD tag is the
//!   verifier) - no separate verifier, no MD5.

use rand::Rng;

use super::aead::{self, KEY_LEN};

/// DEK length (32 bytes = 256 bits).
pub const DEK_LEN: usize = 32;

/// Generate a fresh random DEK from the OS CSPRNG.
pub fn generate_dek() -> [u8; DEK_LEN] {
    let mut dek = [0u8; DEK_LEN];
    rand::rng().fill_bytes(&mut dek);
    dek
}

/// Wrap (encrypt) the DEK under the KEK. The returned blob is a normal v6 AEAD
/// blob (`0x06` format) carrying its own nonce and tag, so it is fully
/// self-describing and stored as a single value.
pub fn wrap_dek(kek: &[u8; KEY_LEN], dek: &[u8; DEK_LEN]) -> Result<Vec<u8>, String> {
    aead::seal(kek, dek)
}

/// Unwrap the DEK. Returns an error if the KEK is wrong (the password is
/// incorrect) or the wrapped blob is malformed/tampered.
pub fn unwrap_dek(kek: &[u8; KEY_LEN], wrapped: &[u8]) -> Result<[u8; DEK_LEN], String> {
    let pt = aead::open(kek, wrapped)?;
    if pt.len() != DEK_LEN {
        return Err("unwrapped DEK has wrong length".to_string());
    }
    let mut dek = [0u8; DEK_LEN];
    dek.copy_from_slice(&pt);
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = [3u8; KEY_LEN];
        let dek = generate_dek();
        let wrapped = wrap_dek(&kek, &dek).unwrap();
        assert_eq!(unwrap_dek(&kek, &wrapped).unwrap(), dek);
    }

    #[test]
    fn wrong_kek_fails_to_unwrap() {
        let kek = [3u8; KEY_LEN];
        let dek = generate_dek();
        let wrapped = wrap_dek(&kek, &dek).unwrap();
        let wrong = [4u8; KEY_LEN];
        assert!(unwrap_dek(&wrong, &wrapped).is_err());
    }

    #[test]
    fn two_deks_differ() {
        assert_ne!(generate_dek(), generate_dek());
    }

    #[test]
    fn tampered_wrap_fails() {
        let kek = [3u8; KEY_LEN];
        let dek = generate_dek();
        let mut wrapped = wrap_dek(&kek, &dek).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        assert!(unwrap_dek(&kek, &wrapped).is_err());
    }

    #[test]
    fn unwrap_rejects_wrong_length_payload() {
        // A correctly-authenticated blob whose plaintext is NOT 32 bytes must be
        // rejected as a DEK (exercises the length guard, not the auth guard).
        let kek = [5u8; KEY_LEN];
        let blob = aead::seal(&kek, &[1u8; 10]).unwrap();
        assert!(unwrap_dek(&kek, &blob).is_err());
    }
}
