//! Key material for autofill.
//!
//! Three keys, with deliberately different reach:
//!
//! | Key | Who holds it | Purpose |
//! |---|---|---|
//! | index key | app **and** provider (shared Keychain / Keystore, behind biometrics) | seals the index; also the provider's read-back wrap on journal records |
//! | journal secret | **app only** (app-private Keychain / Keystore) | opens journal records |
//! | journal public | app and provider, not secret | seals journal records to the app |
//!
//! The split is what makes the drain path independent of the index key. If the
//! index key is rotated, or invalidated by a biometric re-enrollment, the
//! provider loses read-back on staged records but the app can still drain every
//! one of them. Losing read-back costs convenience; losing the drain would cost
//! data, so the two are deliberately not the same key.

use zeroize::Zeroizing;

use crate::error::Result;

use super::crypto;

/// A freshly generated set of autofill keys.
///
/// Produced when the user enables autofill, and again on every rotation (a
/// master password change, most importantly, since `change_password` keeps the
/// same DEK and would otherwise leave an old index perfectly valid).
pub struct AutofillKeys {
    /// Symmetric key sealing the index. Goes to storage shared with the
    /// provider, gated on biometrics or the device passcode.
    pub index_key: Zeroizing<[u8; crypto::KEY_LEN]>,
    /// P-256 secret scalar that opens journal records. App-private.
    pub journal_secret: Zeroizing<[u8; 32]>,
    /// SEC1 uncompressed P-256 public key. Not secret; the provider needs it
    /// in order to seal.
    pub journal_public: Vec<u8>,
}

/// Generate a complete, independent set of autofill keys.
pub fn generate_keys() -> Result<AutofillKeys> {
    let index_key = crypto::random_key();
    let (journal_secret, journal_public) = crypto::generate_p256_keypair()?;
    Ok(AutofillKeys {
        index_key,
        journal_secret,
        journal_public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_have_the_expected_shape() {
        let keys = generate_keys().unwrap();
        assert_eq!(keys.index_key.len(), crypto::KEY_LEN);
        assert_eq!(keys.journal_secret.len(), 32);
        assert_eq!(keys.journal_public.len(), crypto::P256_PUBLIC_LEN);
    }

    #[test]
    fn every_generation_is_independent() {
        let a = generate_keys().unwrap();
        let b = generate_keys().unwrap();
        assert_ne!(a.index_key.as_slice(), b.index_key.as_slice());
        assert_ne!(a.journal_secret.as_slice(), b.journal_secret.as_slice());
        assert_ne!(a.journal_public, b.journal_public);
    }
}
