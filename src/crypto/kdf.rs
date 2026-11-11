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
use zeroize::Zeroizing;

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

/// Largest memory cost accepted from a stored vault record: 1 GiB.
pub const KDF_MAX_M_COST_KIB: u32 = 1024 * 1024;
/// Largest time cost accepted from a stored vault record.
pub const KDF_MAX_T_COST: u32 = 100;
/// Largest parallelism accepted from a stored vault record.
pub const KDF_MAX_P_COST: u32 = 16;

/// Largest memory cost accepted from a backup before its password is
/// checked: four times the default, 256 MiB.
pub const BACKUP_KDF_MAX_M_COST_KIB: u32 = 4 * ARGON2_M_COST_KIB;
/// Largest time cost accepted from a backup: four times the default.
pub const BACKUP_KDF_MAX_T_COST: u32 = 4 * ARGON2_T_COST;
/// Largest parallelism accepted from a backup.
pub const BACKUP_KDF_MAX_P_COST: u32 = 4;

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

    /// Check parameters read from a vault or backup before deriving with them.
    ///
    /// Accepts everything iwcore has ever written ([`KdfParams::current`])
    /// and anything Argon2 accepts up to [`KDF_MAX_M_COST_KIB`],
    /// [`KDF_MAX_T_COST`] and [`KDF_MAX_P_COST`], so a damaged or crafted
    /// record fails with an error instead of a derivation that takes
    /// gigabytes or minutes.
    pub fn check_stored(&self) -> Result<(), String> {
        if self.p_cost == 0 || self.p_cost > KDF_MAX_P_COST {
            return Err(format!("KDF parallelism {} is outside 1..={KDF_MAX_P_COST}", self.p_cost));
        }
        if self.t_cost == 0 || self.t_cost > KDF_MAX_T_COST {
            return Err(format!("KDF time cost {} is outside 1..={KDF_MAX_T_COST}", self.t_cost));
        }
        let min_m = self.p_cost.saturating_mul(8);
        if self.m_cost_kib < min_m || self.m_cost_kib > KDF_MAX_M_COST_KIB {
            return Err(format!(
                "KDF memory cost {} KiB is outside {min_m}..={KDF_MAX_M_COST_KIB}",
                self.m_cost_kib
            ));
        }
        Ok(())
    }

    /// Check parameters read from a backup, which can come from anywhere,
    /// before deriving with them: [`KdfParams::check_stored`], and at most
    /// [`BACKUP_KDF_MAX_M_COST_KIB`], [`BACKUP_KDF_MAX_T_COST`] and
    /// [`BACKUP_KDF_MAX_P_COST`], so one password attempt on a backup stays
    /// within a few times the cost of a default vault.
    pub fn check_backup(&self) -> Result<(), String> {
        self.check_stored()?;
        if self.m_cost_kib > BACKUP_KDF_MAX_M_COST_KIB {
            return Err(format!(
                "KDF memory cost {} KiB is above {BACKUP_KDF_MAX_M_COST_KIB} for a backup",
                self.m_cost_kib
            ));
        }
        if self.t_cost > BACKUP_KDF_MAX_T_COST {
            return Err(format!("KDF time cost {} is above {BACKUP_KDF_MAX_T_COST} for a backup", self.t_cost));
        }
        if self.p_cost > BACKUP_KDF_MAX_P_COST {
            return Err(format!("KDF parallelism {} is above {BACKUP_KDF_MAX_P_COST} for a backup", self.p_cost));
        }
        Ok(())
    }
}

/// Derive a 32-byte KEK from a password and salt using Argon2id with the given
/// parameters. The KEK is wiped when the returned value is dropped.
pub fn derive_kek(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; KEK_LEN]>, String> {
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEK_LEN))
        .map_err(|e| format!("Argon2 params invalid: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEK_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut_slice())
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
    fn kek_is_returned_in_a_wiping_wrapper() {
        let k: Zeroizing<[u8; KEK_LEN]> = derive_kek(b"pw", b"0123456789abcdef", fast()).unwrap();
        assert_ne!(*k, [0u8; KEK_LEN]);
    }

    #[test]
    fn output_is_32_bytes() {
        let k = derive_kek(b"pw", b"0123456789abcdef", fast()).unwrap();
        assert_eq!(k.len(), KEK_LEN);
    }

    #[test]
    fn current_params_are_within_the_stored_bounds() {
        KdfParams::current().check_stored().unwrap();
        fast().check_stored().unwrap();
    }

    #[test]
    fn stored_bounds_accept_the_edges() {
        let ok = |m, t, p| KdfParams { m_cost_kib: m, t_cost: t, p_cost: p }.check_stored();
        ok(8, 1, 1).unwrap();
        ok(KDF_MAX_M_COST_KIB, KDF_MAX_T_COST, KDF_MAX_P_COST).unwrap();
        ok(8 * KDF_MAX_P_COST, 1, KDF_MAX_P_COST).unwrap();
    }

    #[test]
    fn stored_bounds_reject_absurd_values() {
        let bad = |m, t, p| KdfParams { m_cost_kib: m, t_cost: t, p_cost: p }.check_stored().is_err();
        assert!(bad(KDF_MAX_M_COST_KIB + 1, 3, 1));
        assert!(bad(u32::MAX, 3, 1));
        assert!(bad(7, 1, 1));
        assert!(bad(15, 1, 2));
        assert!(bad(65_536, 0, 1));
        assert!(bad(65_536, KDF_MAX_T_COST + 1, 1));
        assert!(bad(65_536, u32::MAX, 1));
        assert!(bad(65_536, 3, 0));
        assert!(bad(u32::MAX, 3, KDF_MAX_P_COST + 1));
        assert!(bad(u32::MAX, 3, u32::MAX));
    }

    #[test]
    fn backup_bounds_accept_the_edges_and_the_defaults() {
        let ok = |m, t, p| KdfParams { m_cost_kib: m, t_cost: t, p_cost: p }.check_backup();
        KdfParams::current().check_backup().unwrap();
        fast().check_backup().unwrap();
        ok(BACKUP_KDF_MAX_M_COST_KIB, BACKUP_KDF_MAX_T_COST, BACKUP_KDF_MAX_P_COST).unwrap();
        assert_eq!(BACKUP_KDF_MAX_M_COST_KIB, 256 * 1024);
        assert_eq!(BACKUP_KDF_MAX_T_COST, 12);
    }

    #[test]
    fn backup_bounds_are_tighter_than_the_stored_bounds() {
        let bad = |m, t, p| KdfParams { m_cost_kib: m, t_cost: t, p_cost: p }.check_backup().is_err();
        assert!(bad(BACKUP_KDF_MAX_M_COST_KIB + 1, 3, 1));
        assert!(bad(65_536, BACKUP_KDF_MAX_T_COST + 1, 1));
        assert!(bad(65_536, 3, BACKUP_KDF_MAX_P_COST + 1));
        assert!(bad(KDF_MAX_M_COST_KIB, KDF_MAX_T_COST, KDF_MAX_P_COST));
        // Whatever the stored check refuses, the backup check refuses too.
        assert!(bad(7, 1, 1));
        assert!(bad(65_536, 0, 1));
        assert!(bad(65_536, 3, 0));
    }

    #[test]
    fn invalid_params_return_error() {
        // Argon2 requires m_cost >= 8 * p_cost; m_cost_kib = 1 is invalid and
        // must surface as an error rather than panic.
        let bad = KdfParams { m_cost_kib: 1, t_cost: 1, p_cost: 1 };
        assert!(derive_kek(b"pw", b"0123456789abcdef", bad).is_err());
    }
}
