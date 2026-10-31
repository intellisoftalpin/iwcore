//! The WebAuthn PRF extension, built on CTAP `hmac-secret`.
//!
//! A site sends one or two inputs; the passkey answers with
//! `HMAC-SHA256(secret, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input))`, a 32-byte
//! value that is the same every time for the same passkey and input and that
//! nobody can compute without the passkey. Sites use it as an encryption key.
//!
//! `secret` is `credWithUV` when the user was verified, `credWithoutUV`
//! otherwise (CXF `hmacCredentials`). The secrets belong to the passkey and can
//! never be recreated: this calculation is frozen by golden vectors
//! (`testdata/passkey-vectors.json`) and must never change.
//!
//! Two entry points, because platforms differ in what they hand the provider:
//! [`evaluate_inputs`] takes the site's raw inputs and hashes them;
//! [`evaluate_salts`] takes salts a platform has already hashed.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::record::{PasskeyRecord, PrfSecrets};
use crate::error::{Result, WalletError};

/// Prefix the WebAuthn specification puts before every PRF input.
pub const SALT_CONTEXT: &[u8] = b"WebAuthn PRF\x00";
/// Largest PRF input accepted, in bytes.
pub const INPUT_MAX: usize = 1024;

/// One or two PRF inputs, as the site sent them.
#[derive(Clone, PartialEq, Eq)]
pub struct PrfInputs {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

impl std::fmt::Debug for PrfInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrfInputs")
            .field("first_len", &self.first.len())
            .field("second_len", &self.second.as_ref().map(Vec::len))
            .finish()
    }
}

/// The PRF results, one per input. These are a site's encryption keys.
#[derive(Clone, PartialEq, Eq)]
pub struct PrfOutputs {
    pub first: Zeroizing<[u8; 32]>,
    pub second: Option<Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for PrfOutputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(crate::utils::REDACTED)
    }
}

/// `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`.
pub fn salt(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SALT_CONTEXT);
    h.update(input);
    h.finalize().into()
}

/// `HMAC-SHA256(secret, salt)` with the secret chosen by `user_verified`.
pub fn hmac_secret(secrets: &PrfSecrets, salt: &[u8; 32], user_verified: bool) -> Zeroizing<[u8; 32]> {
    let key: &[u8; 32] = if user_verified { &secrets.with_uv } else { &secrets.without_uv };
    // HMAC accepts keys of any length, so this cannot fail.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
    mac.update(salt);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// PRF results from the site's raw inputs. `Ok(None)` when the passkey has no
/// PRF secrets.
pub fn evaluate_inputs(
    record: &PasskeyRecord,
    inputs: &PrfInputs,
    user_verified: bool,
) -> Result<Option<PrfOutputs>> {
    check_input(&inputs.first)?;
    if let Some(second) = &inputs.second {
        check_input(second)?;
    }
    let second = inputs.second.as_deref().map(salt);
    Ok(evaluate_salts(record, &salt(&inputs.first), second.as_ref(), user_verified))
}

/// PRF results from salts the platform has already hashed. `None` when the
/// passkey has no PRF secrets.
pub fn evaluate_salts(
    record: &PasskeyRecord,
    first: &[u8; 32],
    second: Option<&[u8; 32]>,
    user_verified: bool,
) -> Option<PrfOutputs> {
    let secrets = record.prf()?;
    Some(PrfOutputs {
        first: hmac_secret(secrets, first, user_verified),
        second: second.map(|s| hmac_secret(secrets, s, user_verified)),
    })
}

fn check_input(input: &[u8]) -> Result<()> {
    if input.len() > INPUT_MAX {
        return Err(WalletError::InvalidInput("PRF input is larger than 1 KiB".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::record::tests::sample;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn salt_is_the_spec_construction() {
        // Independent computation: SHA-256 over the concatenated bytes.
        for input in [&b""[..], b"a", &[0u8; 32], &[0xAB; 1024]] {
            let mut joined = b"WebAuthn PRF".to_vec();
            joined.push(0);
            joined.extend_from_slice(input);
            let expected: [u8; 32] = Sha256::digest(&joined).into();
            assert_eq!(salt(input), expected);
        }
    }

    #[test]
    fn hmac_matches_an_independent_computation() {
        // RFC 4231 test case 2 checks the HMAC itself: key "Jefe".
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn uv_selects_the_secret_and_inputs_are_independent() {
        let r = sample(true);
        let inputs = PrfInputs { first: b"one".to_vec(), second: Some(b"two".to_vec()) };
        let uv = evaluate_inputs(&r, &inputs, true).unwrap().unwrap();
        let no_uv = evaluate_inputs(&r, &inputs, false).unwrap().unwrap();
        assert_ne!(*uv.first, *no_uv.first);
        assert_ne!(*uv.first, **uv.second.as_ref().unwrap());
        // Same inputs, same outputs: the property sites rely on.
        assert_eq!(evaluate_inputs(&r, &inputs, true).unwrap().unwrap(), uv);
        // Raw and pre-hashed paths agree.
        let pre = evaluate_salts(&r, &salt(b"one"), Some(&salt(b"two")), true).unwrap();
        assert_eq!(pre, uv);
        // Equals HMAC(credWithUV = [7; 32], salt).
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[7u8; 32]).unwrap();
        mac.update(&salt(b"one"));
        assert_eq!(uv.first.as_slice(), mac.finalize().into_bytes().as_slice());
    }

    #[test]
    fn single_input_gives_a_single_output() {
        let r = sample(true);
        let out = evaluate_inputs(&r, &PrfInputs { first: vec![], second: None }, true).unwrap().unwrap();
        assert!(out.second.is_none());
    }

    #[test]
    fn no_secrets_means_no_prf() {
        let r = sample(false);
        assert!(evaluate_inputs(&r, &PrfInputs { first: vec![1], second: None }, true).unwrap().is_none());
        assert!(evaluate_salts(&r, &[0; 32], None, true).is_none());
    }

    #[test]
    fn oversized_inputs_are_refused() {
        let r = sample(true);
        let big = vec![0u8; INPUT_MAX + 1];
        assert!(evaluate_inputs(&r, &PrfInputs { first: big.clone(), second: None }, true).is_err());
        assert!(evaluate_inputs(&r, &PrfInputs { first: vec![], second: Some(big) }, true).is_err());
        let edge = vec![0u8; INPUT_MAX];
        assert!(evaluate_inputs(&r, &PrfInputs { first: edge, second: None }, true).is_ok());
    }

    #[test]
    fn debug_shows_neither_inputs_nor_outputs() {
        let r = sample(true);
        let inputs = PrfInputs { first: b"secret-input".to_vec(), second: None };
        let out = evaluate_inputs(&r, &inputs, true).unwrap().unwrap();
        assert!(!format!("{inputs:?}").contains("secret-input"));
        assert!(!format!("{out:?}").contains(&hex(out.first.as_slice())));
    }
}
