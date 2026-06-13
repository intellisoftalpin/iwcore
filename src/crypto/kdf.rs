//! Argon2id key derivation for the v6 scheme.
//!
//! The master password is stretched with Argon2id into a 32-byte Key Encryption
//! Key (KEK). The KEK only ever wraps the Data Encryption Key (see [`super::dek`]);
//! it never touches user data directly.
//!
//! The cost parameters live in consts here AND are stored per-vault (see
//! `iwcore-hardening.md`). Unlock always derives using the vault's *stored*
//! params, so raising the consts below only affects newly created / freshly
//! migrated vaults; existing vaults keep opening with their own params. This is
//! what makes future hardening a cheap DEK re-wrap rather than a data re-encrypt.

use argon2::{Algorithm, Argon2, Params, Version};

/// KEK length (32 bytes = 256 bits).
pub const KEK_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Default Argon2id cost parameters.
//
// IMPORTANT: these MUST be validated on a low-end device before release
// (see iwcore-hardening.md, risk R7). They are the values stamped into a
// vault's crypto record on create() and on the v5->v6 migration.
// ---------------------------------------------------------------------------

/// Memory cost in KiB. 65536 KiB = 64 MiB.
pub const ARGON2_M_COST_KIB: u32 = 65_536;
/// Time cost (number of iterations).
pub const ARGON2_T_COST: u32 = 3;
/// Parallelism (number of lanes).
pub const ARGON2_P_COST: u32 = 1;

/// Argon2id cost parameters for a vault. Stored per-vault and used verbatim on
/// unlock, so older vaults remain decryptable after the consts are raised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// The current default parameters (from the consts above).
    pub const fn current() -> Self {
        Self {
            m_cost_kib: ARGON2_M_COST_KIB,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }
    }
}

/// Derive a 32-byte KEK from a password and salt using Argon2id with the given
/// parameters.
pub fn derive_kek(password: &[u8], salt: &[u8], params: KdfParams) -> Result<[u8; KEK_LEN], String> {
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEK_LEN))
        .map_err(|e| format!("Argon2 params invalid: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; KEK_LEN];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| format!("Argon2 derivation failed: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap params so the unit tests stay fast. Never used for real vaults.
    fn fast() -> KdfParams {
        KdfParams { m_cost_kib: 256, t_cost: 1, p_cost: 1 }
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let salt = b"0123456789abcdef";
        let a = derive_kek(b"correct horse", salt, fast()).unwrap();
        let b = derive_kek(b"correct horse", salt, fast()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_salt_changes_kek() {
        let a = derive_kek(b"pw", b"salt-aaaaaaaaaaa", fast()).unwrap();
        let b = derive_kek(b"pw", b"salt-bbbbbbbbbbb", fast()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_password_changes_kek() {
        let salt = b"0123456789abcdef";
        let a = derive_kek(b"pw-one", salt, fast()).unwrap();
        let b = derive_kek(b"pw-two", salt, fast()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_params_change_kek() {
        let salt = b"0123456789abcdef";
        let a = derive_kek(b"pw", salt, KdfParams { m_cost_kib: 256, t_cost: 1, p_cost: 1 }).unwrap();
        let b = derive_kek(b"pw", salt, KdfParams { m_cost_kib: 512, t_cost: 2, p_cost: 1 }).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn output_is_32_bytes() {
        let k = derive_kek(b"pw", b"0123456789abcdef", fast()).unwrap();
        assert_eq!(k.len(), KEK_LEN);
    }

    #[test]
    fn invalid_params_return_error() {
        // Argon2 requires m_cost >= 8 * p_cost; m_cost_kib = 1 is invalid and
        // must surface as an error rather than panic.
        let bad = KdfParams { m_cost_kib: 1, t_cost: 1, p_cost: 1 };
        assert!(derive_kek(b"pw", b"0123456789abcdef", bad).is_err());
    }
}
