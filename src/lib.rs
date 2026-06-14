//! # IntelliWallet Core
//!
//! A secure password manager library with authenticated encryption
//! (XChaCha20-Poly1305 + Argon2id).
//!
//! This is the storage and cryptography engine behind
//! [IntelliWallet](https://intelliwallet.io/).
//!
//! ## Features
//!
//! - Authenticated encryption: XChaCha20-Poly1305 over a per-vault Data
//!   Encryption Key, wrapped by an Argon2id-derived key
//! - Transparent, crash-safe migration of older vaults on first unlock
//! - SQLite database storage
//! - Hierarchical item organization (folders)
//! - Custom field types and labels
//! - Backup and restore functionality
//! - Multi-language support (11 languages)
//!
//! ## Example
//!
//! ```no_run
//! use iwcore::Wallet;
//! use std::path::Path;
//!
//! let mut wallet = Wallet::open(Path::new("/path/to/wallet")).unwrap();
//! wallet.unlock("my_password").unwrap();
//!
//! let items = wallet.get_items().unwrap();
//! for item in items {
//!     println!("{}: {}", item.item_id, item.name);
//! }
//! ```

pub mod crypto;
pub mod database;
pub mod business;
pub mod backup;
pub mod localization;
pub mod utils;
pub mod error;
pub mod export;

// Re-export main types
pub use error::{WalletError, Result};
pub use database::models::{IWItem, IWField, IWLabel, IWProperties, SearchResult, SearchMatchType, FieldValueUsage};
pub use business::Wallet;
pub use backup::{BackupManager, BackupType};
pub use localization::Translations;
pub use crypto::{
    generate_password, generate_clever_password, generate_memorable_password,
    PasswordOptions, MemorableOptions, MemorableCaps,
};
pub use export::{ExportItemType, PDFItemModel};
pub use database::queries::DatabaseStats;

/// Database version constant.
///
/// Version 6 = schema 5 plus the v6 crypto scheme (XChaCha20-Poly1305 over a
/// per-vault DEK wrapped by Argon2id). Password-free schema migrations on
/// `open()` only reach version 5 (see `migrations::CURRENT_VERSION`); the bump
/// to 6 happens inside `unlock()` after the one-time crypto re-encryption.
pub const DB_VERSION: &str = "6";

/// Root item ID
pub const ROOT_ID: &str = "__ROOT__";

/// Root parent ID placeholder
pub const ROOT_PARENT_ID: &str = "________";

/// Default encryption iteration count
pub const ENCRYPTION_COUNT_DEFAULT: u32 = 200;

/// Item ID length
pub const ITEM_ID_LENGTH: usize = 8;

/// Field ID length
pub const FIELD_ID_LENGTH: usize = 4;

/// Label ID length
pub const LABEL_ID_LENGTH: usize = 4;

/// Database filename
pub const DATABASE_FILENAME: &str = "nswallet.dat";

/// Minimum password length
pub const PASSWORD_MIN_LENGTH: usize = 3;

/// Maximum password length
pub const PASSWORD_MAX_LENGTH: usize = 32;

/// Minimum search phrase length
pub const SEARCH_MIN_LENGTH: usize = 2;
