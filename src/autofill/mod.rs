//! Autofill support: the credential index and the write-back journal.
//!
//! The platform autofill provider (the iOS AutoFill extension today, the
//! Android `AutofillService` later) runs in a process that must never open the
//! vault. `Wallet::open` runs schema migrations and `unlock` writes system
//! labels, so both are writers; and unlocking costs an Argon2id derivation at
//! 64 MiB, which does not belong in a memory-capped extension.
//!
//! Instead the app exports two small files into storage shared with the
//! provider:
//!
//! - **the index** ([`index`]): a sealed snapshot of the login-shaped entries
//!   in the vault, rebuilt by the app whenever the vault changes;
//! - **the journal** ([`journal`]): logins created in the provider, appended
//!   there and drained into the vault by the app on its next unlock.
//!
//! Passkeys in either file are signed with through [`passkeys`], so a provider
//! never decodes a passkey record or holds its private key itself.
//!
//! Everything in this module is platform neutral. Nothing here touches the
//! filesystem, the Keychain, or the Android Keystore: callers supply keys and
//! receive bytes, so the same code serves both platforms.
//!
//! # Shape of a login
//!
//! A login carries exactly one identity field, one of `MAIL`, `USER` or `ACNT`,
//! plus `PASS`, plus `LINK`. [`identity`] decides which identity type a value
//! belongs in on the way in, and the same priority governs which one is chosen
//! on the way out, so an entry that round-trips out through the index and back
//! through the journal keeps its shape. There is a test asserting exactly that.
//!
//! # Untrusted input
//!
//! The index and the journal are files in storage another process can write,
//! so every parser here treats them as hostile: lengths are checked with
//! checked arithmetic and slices are taken with `get`, never by indexing. The
//! lints below hold the whole module to that, on 32-bit targets too, where a
//! `usize` sum of two file-supplied lengths can wrap.

#![cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

pub mod crypto;
pub mod domain;
pub mod identity;
pub mod index;
pub mod journal;
pub mod keys;
pub mod passkeys;
pub mod wallet;

pub use domain::{MatchTier, normalize_host, registrable_domain};
pub use identity::{IdentityKind, classify};
pub use index::{IndexEntry, IndexHeader, IndexOptions};
pub use journal::{DrainKeys, PendingOp, PendingRecord};
pub use keys::{AutofillKeys, generate_keys};
pub use passkeys::{HeldPasskeys, PasskeyCandidate, SignRequest, SignedAssertion, sign_from_index};
pub use wallet::{DrainSummary, PasskeyReplacement};

/// Field type holding a login password.
pub const FIELD_PASSWORD: &str = "PASS";
/// Field type holding the previous password, written when the provider reports
/// a password change for an entry that already exists.
pub const FIELD_OLD_PASSWORD: &str = "OLDP";
/// Field type holding the site a credential belongs to.
pub const FIELD_LINK: &str = "LINK";
/// Field type holding a TOTP secret. Indexed only from phase 4 onward.
pub const FIELD_TOTP: &str = "2FAC";

/// Name of the folder that drained journal entries are imported into.
///
/// Deliberately **not** localized. Item names live encrypted inside the vault,
/// so a translated name would freeze at whatever language was active when the
/// folder was first created and then read as stale if the user switched
/// languages. The literal also matches Apple's own feature name as it appears
/// in iOS Settings in every locale.
pub const AUTOFILL_FOLDER_NAME: &str = "AutoFill";
