//! Passkeys: IntelliWallet as a WebAuthn authenticator.
//!
//! A passkey is stored in the vault as a `PKEY` field on a login item. Its value
//! is a JSON record shaped after the FIDO Credential Exchange Format (CXF)
//! passkey, see [`record`]. Everything a platform provider needs to create a
//! passkey and sign in with it is here, platform neutral and without any
//! filesystem, OS or network access:
//!
//! - [`record`]: the stored record, validated, with its secrets redacted in `Debug`;
//! - [`webauthn`]: the exact WebAuthn bytes (authenticator data, COSE key,
//!   attestation object);
//! - [`sign`]: registration and assertion;
//! - [`prf`]: the WebAuthn PRF extension (`hmac-secret`);
//! - [`json`]: the WebAuthn JSON Android's Credential Manager speaks;
//! - [`origin`]: who may use which passkey (rpId, Android origins, asset links).
//!
//! Choices fixed for every passkey IntelliWallet creates: ES256 only, attestation
//! `none`, sign counter always 0, backup eligible and backed up (`BE`, `BS`).

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing))]

pub(crate) mod b64;
pub mod record;
pub mod webauthn;
pub mod sign;
pub mod prf;
pub mod origin;
pub mod json;
pub mod vault;

#[cfg(test)]
mod vectors;

pub use record::{PasskeyRecord, PasskeySummary, PrfSecrets};

/// Field type of a stored passkey.
pub const FIELD_PASSKEY: &str = "PKEY";

/// COSE algorithm identifier of ES256 (ECDSA over P-256 with SHA-256), the only
/// algorithm IntelliWallet creates or accepts.
pub const ALG_ES256: i64 = -7;
