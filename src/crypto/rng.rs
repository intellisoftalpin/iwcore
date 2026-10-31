//! Randomness for long-lived secrets: data encryption keys, KDF salts,
//! AutoFill keys, and (from 0.5.2) passkey keys, credential ids and PRF
//! secrets.
//!
//! These are drawn straight from the operating system's generator
//! (`getrandom` through [`rand::rngs::SysRng`]) rather than from the
//! thread-local generator, so a key never depends on a userspace generator's
//! seeding. Per-message nonces may keep using [`rand::rng`]: it is a CSPRNG
//! seeded and reseeded from the same source, and much faster.
//!
//! The OS generator can, in principle, fail (no entropy source in a sandbox).
//! That is reported as an error instead of a panic, so a library caller can
//! surface it.

use rand::TryRng;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

use crate::error::{Result, WalletError};

/// Fill `buf` from the operating system's random number generator.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    SysRng.try_fill_bytes(buf).map_err(|e| {
        WalletError::EncryptionError(format!("operating system random number generator failed: {e}"))
    })
}

/// `len` random bytes from the operating system.
pub fn bytes(len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    fill(&mut out)?;
    Ok(out)
}

/// A random secret of `N` bytes from the operating system, wiped on drop.
pub fn secret<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0u8; N]);
    fill(out.as_mut_slice())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_differs() {
        let a = secret::<32>().unwrap();
        let b = secret::<32>().unwrap();
        assert_ne!(*a, *b);
        assert_ne!(*a, [0u8; 32]);
    }

    #[test]
    fn bytes_has_the_requested_length() {
        assert_eq!(bytes(0).unwrap().len(), 0);
        assert_eq!(bytes(17).unwrap().len(), 17);
        let mut empty: [u8; 0] = [];
        fill(&mut empty).unwrap();
    }
}
