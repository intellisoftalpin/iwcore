//! Key material for autofill.
//!
//! Four keys, with deliberately different reach:
//!
//! | Key | Who holds it | Purpose |
//! |---|---|---|
//! | index key | app **and** provider (shared Keychain / Keystore, behind biometrics) | seals the index; also the provider's read-back wrap on journal records |
//! | journal auth key | app **and** provider (shared Keychain / Keystore) | authenticates every journal record the provider writes |
//! | journal secret | **app only** (app-private Keychain / Keystore) | opens journal records |
//! | journal public | app and provider, not secret | seals journal records to the app |
//!
//! The split is what makes the drain path independent of the index key. If the
//! index key is rotated, or invalidated by a biometric re-enrollment, the
//! provider loses read-back on staged records but the app can still drain every
//! one of them. Losing read-back costs convenience; losing the drain would cost
//! data, so the two are deliberately not the same key.
//!
//! The journal public key is not secret, so sealing to it proves nothing about
//! who wrote a record. The journal auth key does: the drain applies only
//! records whose MAC verifies under it (see [`super::journal`]). It must be
//! readable wherever the provider stages a record, which on Android includes
//! the unauthenticated save path, so it is typically stored next to the
//! staging key rather than behind biometrics. What it keeps out is any writer
//! that cannot read the app's own Keychain group or Keystore entries.

use zeroize::Zeroizing;

use crate::error::Result;

use super::crypto;

/// A freshly generated set of autofill keys.
///
/// Produced when the user enables autofill, and again on every rotation (a
/// master password change, most importantly, since `change_password` keeps the
/// same DEK and would otherwise leave an old index perfectly valid). Drain the
/// journal before rotating: records written under the previous auth key no
/// longer verify afterwards.
pub struct AutofillKeys {
    /// Symmetric key sealing the index. Goes to storage shared with the
    /// provider, gated on biometrics or the device passcode.
    pub index_key: Zeroizing<[u8; crypto::KEY_LEN]>,
    /// Symmetric key the provider MACs every journal record with. Goes to
    /// storage shared with the provider and the app, never to a file.
    pub journal_auth_key: Zeroizing<[u8; crypto::KEY_LEN]>,
    /// P-256 secret scalar that opens journal records. App-private.
    pub journal_secret: Zeroizing<[u8; 32]>,
    /// SEC1 uncompressed P-256 public key. Not secret; the provider needs it
    /// in order to seal.
    pub journal_public: Vec<u8>,
}

/// Generate a complete, independent set of autofill keys.
pub fn generate_keys() -> Result<AutofillKeys> {
    let index_key = crypto::random_key()?;
    let journal_auth_key = crypto::random_key()?;
    let (journal_secret, journal_public) = crypto::generate_p256_keypair()?;
    Ok(AutofillKeys {
        index_key,
        journal_auth_key,
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
        assert_eq!(keys.journal_auth_key.len(), crypto::KEY_LEN);
        assert_eq!(keys.journal_secret.len(), 32);
        assert_eq!(keys.journal_public.len(), crypto::P256_PUBLIC_LEN);
    }

    #[test]
    fn every_generation_is_independent() {
        let a = generate_keys().unwrap();
        let b = generate_keys().unwrap();
        assert_ne!(a.index_key.as_slice(), b.index_key.as_slice());
        assert_ne!(a.journal_auth_key.as_slice(), b.journal_auth_key.as_slice());
        assert_ne!(a.journal_secret.as_slice(), b.journal_secret.as_slice());
        assert_ne!(a.journal_public, b.journal_public);
    }

    #[test]
    fn the_auth_key_is_not_the_index_key() {
        let keys = generate_keys().unwrap();
        assert_ne!(keys.index_key.as_slice(), keys.journal_auth_key.as_slice());
    }
}
