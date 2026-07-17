//! Cryptographic operations for IntelliWallet
//!
//! The current (v6) scheme is XChaCha20-Poly1305 authenticated encryption over a
//! per-vault Data Encryption Key (DEK), with the DEK wrapped by an
//! Argon2id-derived Key Encryption Key (KEK). See [`aead`], [`kdf`], [`dek`].
//!
//! The legacy (v5) scheme - zero-IV AES-256-CBC + unsalted MD5, matching the
//! original C# implementation - is retained under [`legacy`] solely for the
//! one-time v5->v6 migration and for verifying not-yet-migrated vaults.

mod aes;
mod md5;
mod key;
pub mod password;
mod wordlist;

// v6 scheme (current).
pub mod kdf;
pub mod aead;
pub mod dek;

pub use aes::{encrypt, decrypt};
pub use md5::md5_hex;
pub use key::prepare_key;

/// Legacy (v5) scheme: zero-IV AES-256-CBC + unsalted MD5. Retained for the
/// one-time v5->v6 migration path and for verifying not-yet-migrated vaults.
/// Do not use for new data.
pub mod legacy {
    pub use super::aes::{decrypt, encrypt, LegacyKeyChain, LegacyKeyMode};
    pub use super::key::prepare_key;
    pub use super::md5::md5_hex;
}
pub use password::{
    generate_password, generate_clever_password, generate_memorable_password,
    PasswordOptions, MemorableOptions, MemorableCaps,
};

#[cfg(test)]
mod tests;
