//! Utility functions

pub mod common;
pub mod id_gen;

/// Printed by `Debug` in place of a secret.
pub const REDACTED: &str = "[redacted]";

pub use common::*;
pub use id_gen::*;
