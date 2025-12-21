//! Business logic layer for IntelliWallet
//!
//! This module provides the high-level Wallet API for managing
//! items, fields, labels, and other wallet operations.

pub mod wallet;
pub mod items;
pub mod fields;
pub mod labels;
pub mod search;

pub use wallet::Wallet;
