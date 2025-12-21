//! Database layer for IntelliWallet
//!
//! Handles SQLite database operations including:
//! - Schema creation and migrations
//! - CRUD operations for items, fields, labels
//! - Encrypted data storage and retrieval

pub mod models;
pub mod schema;
pub mod connection;
pub mod migrations;
pub mod queries;

pub use connection::Database;
pub use models::*;
