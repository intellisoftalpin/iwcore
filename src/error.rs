//! Error types for IntelliWallet Core

use thiserror::Error;

/// Main error type for wallet operations
#[derive(Error, Debug)]
pub enum WalletError {
    /// Database file not found at the specified path
    #[error("Database not found: {0}")]
    DatabaseNotFound(String),

    /// Invalid password provided
    #[error("Invalid password")]
    InvalidPassword,

    /// Wallet is locked, unlock required before operation
    #[error("Wallet is locked")]
    Locked,

    /// Encryption or decryption failed
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Decryption failed - data may be corrupted
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Database operation failed
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// Backup operation failed
    #[error("Backup error: {0}")]
    BackupError(String),

    /// Item not found
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    /// Field not found
    #[error("Field not found: {0}")]
    FieldNotFound(String),

    /// Label not found
    #[error("Label not found: {0}")]
    LabelNotFound(String),

    /// Invalid database version
    #[error("Invalid database version: {0}")]
    InvalidVersion(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid operation
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    /// Localization error
    #[error("Localization error: {0}")]
    LocalizationError(String),
}

impl From<rusqlite::Error> for WalletError {
    fn from(err: rusqlite::Error) -> Self {
        WalletError::DatabaseError(err.to_string())
    }
}

impl From<zip::result::ZipError> for WalletError {
    fn from(err: zip::result::ZipError) -> Self {
        WalletError::BackupError(err.to_string())
    }
}

/// Result type alias for wallet operations
pub type Result<T> = std::result::Result<T, WalletError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = WalletError::DatabaseNotFound("/path/to/db".to_string());
        assert!(err.to_string().contains("/path/to/db"));

        let err = WalletError::InvalidPassword;
        assert_eq!(err.to_string(), "Invalid password");

        let err = WalletError::Locked;
        assert_eq!(err.to_string(), "Wallet is locked");

        let err = WalletError::EncryptionError("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let err = WalletError::ItemNotFound("item123".to_string());
        assert!(err.to_string().contains("item123"));

        let err = WalletError::InvalidVersion("999".to_string());
        assert!(err.to_string().contains("999"));
    }

    #[test]
    fn test_error_from_rusqlite() {
        let sqlite_err = rusqlite::Error::QueryReturnedNoRows;
        let wallet_err: WalletError = sqlite_err.into();
        match wallet_err {
            WalletError::DatabaseError(msg) => assert!(!msg.is_empty()),
            _ => panic!("Expected DatabaseError"),
        }
    }

    #[test]
    fn test_error_from_zip() {
        let zip_err = zip::result::ZipError::FileNotFound;
        let wallet_err: WalletError = zip_err.into();
        match wallet_err {
            WalletError::BackupError(msg) => assert!(!msg.is_empty()),
            _ => panic!("Expected BackupError"),
        }
    }
}
