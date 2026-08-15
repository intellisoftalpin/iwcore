//! Crypto primitives shared by the autofill index and journal.
//!
//! Deliberately **not** the same construction as [`crate::crypto::aead`], which
//! uses XChaCha20-Poly1305 with a 24-byte nonce. Apple's CryptoKit exposes
//! `ChaChaPoly` (the IETF variant, 96-bit nonce) natively but has no XChaCha20,
//! so the autofill formats use the IETF variant throughout. That is what lets
//! the iOS AutoFill extension be pure Swift, with no Rust, no SQLite and no
//! third-party crypto of its own.
//!
//! Sealed blob layout, used for every sealed field in both formats:
//!
//! ```text
//! bytes 0..12   : 12-byte ChaCha20 nonce (random per seal, OS CSPRNG)
//! bytes 12..N   : ciphertext
//! bytes N..N+16 : Poly1305 tag
//! ```

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::Rng;
use zeroize::Zeroizing;

use crate::error::{Result, WalletError};

/// Symmetric key length for the index key and per-record keys.
pub const KEY_LEN: usize = 32;
/// IETF ChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 12;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Length of a SEC1 uncompressed P-256 public key.
pub const P256_PUBLIC_LEN: usize = 65;

/// Fill a buffer from the OS CSPRNG.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::rng().fill_bytes(&mut out);
    out
}

/// Generate a random symmetric key.
pub fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    rand::rng().fill_bytes(&mut key);
    Zeroizing::new(key)
}

/// Seal `plaintext` under `key`, binding `aad` into the authentication tag.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| WalletError::EncryptionError("autofill key is not 32 bytes".into()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| WalletError::EncryptionError("autofill seal failed".into()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`seal`]. Fails on a wrong key, a wrong `aad`, a
/// truncated blob, or any tampering.
pub fn open(key: &[u8; KEY_LEN], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(WalletError::DecryptionError("autofill blob too short".into()));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| WalletError::DecryptionError("autofill key is not 32 bytes".into()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&blob[..NONCE_LEN]);
    let nonce = Nonce::from(nonce_bytes);

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &blob[NONCE_LEN..],
                aad,
            },
        )
        .map_err(|_| WalletError::DecryptionError("autofill blob failed authentication".into()))
}

// ---------------------------------------------------------------------------
// P-256 ECDH, used to wrap journal record keys to the app's public key.
// ---------------------------------------------------------------------------

/// Generate a P-256 key pair. Returns `(secret_scalar_bytes, sec1_public_bytes)`.
///
/// The scalar is drawn as raw random bytes and rejected until it lands in the
/// valid range, rather than handing an RNG to the curve crate. That keeps this
/// independent of which `rand_core` version the curve crate happens to want.
pub fn generate_p256_keypair() -> Result<(Zeroizing<[u8; 32]>, Vec<u8>)> {
    for _ in 0..64 {
        let candidate = random_key();
        if let Ok(secret) = p256::SecretKey::from_slice(candidate.as_slice()) {
            let public = secret.public_key().to_sec1_bytes().to_vec();
            return Ok((candidate, public));
        }
    }
    Err(WalletError::EncryptionError(
        "could not generate a P-256 key pair".into(),
    ))
}

/// Derive the shared secret between a secret scalar and a peer public key,
/// then stretch it with HKDF-SHA256 into a symmetric key.
///
/// `info` domain-separates the output so a key derived for one purpose can
/// never be reused for another.
fn ecdh_derive(
    secret_bytes: &[u8; 32],
    peer_public: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let secret = p256::SecretKey::from_slice(secret_bytes)
        .map_err(|_| WalletError::DecryptionError("invalid P-256 secret key".into()))?;
    let peer = p256::PublicKey::from_sec1_bytes(peer_public)
        .map_err(|_| WalletError::DecryptionError("invalid P-256 public key".into()))?;

    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, shared.raw_secret_bytes());
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out)
        .map_err(|_| WalletError::EncryptionError("HKDF expand failed".into()))?;
    Ok(Zeroizing::new(out))
}

/// Seal `plaintext` to `recipient_public` using an ephemeral P-256 key.
///
/// Returns `(ephemeral_public_sec1, sealed)`. Only the holder of the matching
/// private key can open the result; the sender cannot, because the ephemeral
/// secret is dropped here and never stored.
pub fn ecies_seal(
    recipient_public: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    info: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (eph_secret, eph_public) = generate_p256_keypair()?;
    let key = ecdh_derive(&eph_secret, recipient_public, info)?;
    let sealed = seal(&key, plaintext, aad)?;
    Ok((eph_public, sealed))
}

/// Open a blob produced by [`ecies_seal`].
pub fn ecies_open(
    recipient_secret: &[u8; 32],
    ephemeral_public: &[u8],
    sealed: &[u8],
    aad: &[u8],
    info: &[u8],
) -> Result<Vec<u8>> {
    let key = ecdh_derive(recipient_secret, ephemeral_public, info)?;
    open(&key, sealed, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = random_key();
        let sealed = seal(&key, b"hello", b"aad").unwrap();
        assert_eq!(open(&key, &sealed, b"aad").unwrap(), b"hello");
    }

    #[test]
    fn wrong_key_fails() {
        let key = random_key();
        let other = random_key();
        let sealed = seal(&key, b"hello", b"").unwrap();
        assert!(open(&other, &sealed, b"").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = random_key();
        let sealed = seal(&key, b"hello", b"aad-a").unwrap();
        assert!(open(&key, &sealed, b"aad-b").is_err());
    }

    #[test]
    fn every_single_bit_flip_is_detected() {
        let key = random_key();
        let sealed = seal(&key, b"sensitive", b"aad").unwrap();
        for byte in 0..sealed.len() {
            for bit in 0..8u32 {
                let mut tampered = sealed.clone();
                tampered[byte] ^= 1 << bit;
                assert!(
                    open(&key, &tampered, b"aad").is_err(),
                    "flip at byte {byte} bit {bit} was not detected"
                );
            }
        }
    }

    #[test]
    fn truncation_at_every_length_is_detected() {
        let key = random_key();
        let sealed = seal(&key, b"sensitive", b"").unwrap();
        for len in 0..sealed.len() {
            assert!(open(&key, &sealed[..len], b"").is_err(), "length {len}");
        }
    }

    #[test]
    fn nonces_differ_between_seals() {
        let key = random_key();
        let a = seal(&key, b"same", b"").unwrap();
        let b = seal(&key, b"same", b"").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn p256_keypair_has_expected_shape() {
        let (secret, public) = generate_p256_keypair().unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(public.len(), P256_PUBLIC_LEN);
        assert_eq!(public[0], 0x04, "SEC1 uncompressed point");
    }

    #[test]
    fn ecies_round_trip() {
        let (secret, public) = generate_p256_keypair().unwrap();
        let (eph, sealed) = ecies_seal(&public, b"secret", b"aad", b"info").unwrap();
        let opened = ecies_open(&secret, &eph, &sealed, b"aad", b"info").unwrap();
        assert_eq!(opened, b"secret");
    }

    #[test]
    fn ecies_requires_the_matching_private_key() {
        let (_, public) = generate_p256_keypair().unwrap();
        let (other_secret, _) = generate_p256_keypair().unwrap();
        let (eph, sealed) = ecies_seal(&public, b"secret", b"", b"info").unwrap();
        assert!(ecies_open(&other_secret, &eph, &sealed, b"", b"info").is_err());
    }

    #[test]
    fn ecies_is_domain_separated_by_info() {
        let (secret, public) = generate_p256_keypair().unwrap();
        let (eph, sealed) = ecies_seal(&public, b"secret", b"", b"info-a").unwrap();
        assert!(ecies_open(&secret, &eph, &sealed, b"", b"info-b").is_err());
    }

    #[test]
    fn ecies_rejects_a_garbage_ephemeral_key() {
        let (secret, public) = generate_p256_keypair().unwrap();
        let (_, sealed) = ecies_seal(&public, b"secret", b"", b"info").unwrap();
        assert!(ecies_open(&secret, &[0u8; P256_PUBLIC_LEN], &sealed, b"", b"info").is_err());
        assert!(ecies_open(&secret, b"", &sealed, b"", b"info").is_err());
    }
}
