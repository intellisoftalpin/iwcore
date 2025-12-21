//! Cryptographic operations for IntelliWallet
//!
//! This module implements AES-256-CBC encryption with PKCS7 padding,
//! exactly matching the original C# implementation for backward compatibility.

mod aes;
mod md5;
mod key;
pub mod password;

pub use aes::{encrypt, decrypt};
pub use md5::md5_hex;
pub use key::prepare_key;
pub use password::{generate_password, generate_clever_password, PasswordOptions};

#[cfg(test)]
mod tests;
