//! Creating a passkey and signing in with it.
//!
//! Registration with attestation `none` signs nothing: it produces a key pair,
//! a credential id and the attestation object. Assertion signs
//! `authenticatorData ‖ clientDataHash` with ECDSA P-256 / SHA-256, encoded as
//! DER. Signatures are deterministic (RFC 6979), so test vectors reproduce
//! byte for byte.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use zeroize::Zeroizing;

use super::record::{PasskeyRecord, PrfSecrets};
use super::webauthn;
use crate::error::{Result, WalletError};

/// Length of the credential ids IntelliWallet creates.
pub const CREDENTIAL_ID_LEN: usize = 16;

/// What a site asks for when it creates a passkey.
#[derive(Debug, Clone)]
pub struct RegisterInput<'a> {
    pub rp_id: &'a str,
    pub user_name: &'a str,
    pub user_display_name: &'a str,
    pub user_handle: &'a [u8],
    /// The site's `excludeCredentials`: if the vault holds any of these, the
    /// account already has a passkey here.
    pub exclude_credentials: &'a [Vec<u8>],
    /// Credential ids the vault (and the AutoFill journal) already holds.
    pub held_credential_ids: &'a [Vec<u8>],
    /// The provider checked the user with a biometric or device passcode.
    pub user_verified: bool,
    /// Unix seconds, stored as `createdAt`.
    pub now: i64,
}

/// A new passkey and everything the platform must return to the site.
#[derive(Debug, Clone)]
pub struct Registration {
    /// To be stored (through the journal, then the vault).
    pub record: PasskeyRecord,
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    /// SubjectPublicKeyInfo DER, which Android's response JSON carries.
    pub public_key_spki: Vec<u8>,
}

/// A sign-in response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// ECDSA signature, DER.
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

/// Create a passkey: a fresh P-256 key and credential id from the operating
/// system's generator, and PRF secrets so the passkey can answer PRF.
pub fn register(input: &RegisterInput<'_>) -> Result<Registration> {
    let credential_id = crate::crypto::rng::bytes(CREDENTIAL_ID_LEN)?;
    // A random 32-byte string is a valid P-256 scalar with overwhelming
    // probability; retry the rare value that is not.
    for _ in 0..64 {
        let scalar = crate::crypto::rng::secret::<32>()?;
        if SigningKey::from_slice(scalar.as_slice()).is_ok() {
            return register_with(input, &scalar, credential_id, Some(PrfSecrets::generate()?));
        }
    }
    Err(WalletError::EncryptionError("could not generate a P-256 key".into()))
}

/// Registration from given key material. Public to the crate so tests and the
/// golden vectors are reproducible; never call it with anything but fresh
/// random values outside tests.
pub(crate) fn register_with(
    input: &RegisterInput<'_>,
    scalar: &[u8; 32],
    credential_id: Vec<u8>,
    prf: Option<PrfSecrets>,
) -> Result<Registration> {
    if input
        .exclude_credentials
        .iter()
        .any(|excluded| input.held_credential_ids.iter().any(|held| held == excluded))
    {
        return Err(WalletError::PasskeyExcluded);
    }

    let secret = p256::SecretKey::from_slice(scalar)
        .map_err(|_| WalletError::EncryptionError("invalid P-256 scalar".into()))?;
    let pkcs8 = secret
        .to_pkcs8_der()
        .map_err(|_| WalletError::EncryptionError("PKCS#8 encoding failed".into()))?;
    let signing = SigningKey::from(&secret);
    let verifying = *signing.verifying_key();

    let record = PasskeyRecord::new(
        credential_id.clone(),
        input.rp_id,
        input.user_name,
        input.user_display_name,
        input.user_handle.to_vec(),
        Zeroizing::new(pkcs8.as_bytes().to_vec()),
        input.now,
        prf,
    )?;

    let cose = webauthn::cose_public_key(&verifying);
    let authenticator_data =
        webauthn::authenticator_data_create(&record.rp_id, input.user_verified, &credential_id, &cose);
    let attestation_object = webauthn::attestation_object_none(&authenticator_data);
    let public_key_spki = verifying
        .to_public_key_der()
        .map_err(|_| WalletError::EncryptionError("SPKI encoding failed".into()))?
        .as_bytes()
        .to_vec();

    Ok(Registration {
        record,
        credential_id,
        authenticator_data,
        attestation_object,
        public_key_cose: cose.to_vec(),
        public_key_spki,
    })
}

/// Sign in with `record` for `rp_id`. Refuses when the rpId is not the
/// record's (the platform already matched it; this is defence in depth).
pub fn assert(
    record: &PasskeyRecord,
    rp_id: &str,
    client_data_hash: &[u8; 32],
    user_verified: bool,
) -> Result<Assertion> {
    if !rp_id.eq_ignore_ascii_case(&record.rp_id) {
        return Err(WalletError::InvalidInput("rpId does not match the passkey".into()));
    }
    let authenticator_data = webauthn::authenticator_data_assert(&record.rp_id, user_verified);
    let mut message = Vec::with_capacity(authenticator_data.len() + 32);
    message.extend_from_slice(&authenticator_data);
    message.extend_from_slice(client_data_hash);
    let signature: Signature = record.signing_key()?.sign(&message);

    Ok(Assertion {
        credential_id: record.credential_id.clone(),
        authenticator_data,
        signature: signature.to_der().as_bytes().to_vec(),
        user_handle: record.user_handle.clone(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;
    use p256::pkcs8::DecodePublicKey;

    pub(crate) const SCALAR: [u8; 32] = [
        0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
    ];

    pub(crate) fn input<'a>(exclude: &'a [Vec<u8>], held: &'a [Vec<u8>]) -> RegisterInput<'a> {
        RegisterInput {
            rp_id: "webauthn.example",
            user_name: "bkv",
            user_display_name: "B K V",
            user_handle: b"handle-01",
            exclude_credentials: exclude,
            held_credential_ids: held,
            user_verified: true,
            now: 1_793_433_600,
        }
    }

    fn verify(reg: &Registration, a: &Assertion, client_data_hash: &[u8; 32]) -> bool {
        let key = VerifyingKey::from_public_key_der(&reg.public_key_spki).unwrap();
        let sig = Signature::from_der(&a.signature).unwrap();
        let mut msg = a.authenticator_data.clone();
        msg.extend_from_slice(client_data_hash);
        key.verify(&msg, &sig).is_ok()
    }

    #[test]
    fn register_then_assert_verifies() {
        let reg = register(&input(&[], &[])).unwrap();
        assert_eq!(reg.credential_id.len(), CREDENTIAL_ID_LEN);
        assert!(reg.record.prf().is_some(), "new passkeys carry PRF secrets");
        let hash = [0x42u8; 32];
        let a = assert(&reg.record, "webauthn.example", &hash, true).unwrap();
        assert!(verify(&reg, &a, &hash));
        assert_eq!(a.user_handle, b"handle-01");
        assert_eq!(a.credential_id, reg.credential_id);
    }

    #[test]
    fn every_registration_is_new() {
        let a = register(&input(&[], &[])).unwrap();
        let b = register(&input(&[], &[])).unwrap();
        assert_ne!(a.credential_id, b.credential_id);
        assert_ne!(a.public_key_cose, b.public_key_cose);
    }

    #[test]
    fn spki_and_cose_describe_the_same_key() {
        let reg = register_with(&input(&[], &[]), &SCALAR, vec![1; 16], None).unwrap();
        let key = VerifyingKey::from_public_key_der(&reg.public_key_spki).unwrap();
        assert_eq!(webauthn::cose_public_key(&key).to_vec(), reg.public_key_cose);
        assert_eq!(&reg.authenticator_data[55 + 16..], reg.public_key_cose.as_slice());
    }

    #[test]
    fn signatures_are_deterministic_and_bound_to_their_inputs() {
        let reg = register_with(&input(&[], &[]), &SCALAR, vec![1; 16], None).unwrap();
        let h1 = [1u8; 32];
        let a1 = assert(&reg.record, "webauthn.example", &h1, true).unwrap();
        assert_eq!(a1, assert(&reg.record, "webauthn.example", &h1, true).unwrap());
        // Another client data hash, or another UV flag, is another signature.
        let a2 = assert(&reg.record, "webauthn.example", &[2u8; 32], true).unwrap();
        let a3 = assert(&reg.record, "webauthn.example", &h1, false).unwrap();
        assert_ne!(a1.signature, a2.signature);
        assert_ne!(a1.signature, a3.signature);
        assert!(verify(&reg, &a3, &h1));
        assert!(!verify(&reg, &a1, &[2u8; 32]), "a signature must not verify for another hash");
    }

    #[test]
    fn uv_false_clears_the_uv_flag() {
        let reg = register_with(&input(&[], &[]), &SCALAR, vec![1; 16], None).unwrap();
        let a = assert(&reg.record, "webauthn.example", &[0; 32], false).unwrap();
        assert_eq!(a.authenticator_data[32] & webauthn::FLAG_UV, 0);
        let mut no_uv = input(&[], &[]);
        no_uv.user_verified = false;
        let r = register_with(&no_uv, &SCALAR, vec![1; 16], None).unwrap();
        assert_eq!(r.authenticator_data[32] & webauthn::FLAG_UV, 0);
    }

    #[test]
    fn excluded_credentials_refuse_registration() {
        let held = vec![vec![9u8; 16], vec![8u8; 16]];
        let exclude = vec![vec![1u8; 16], vec![8u8; 16]];
        assert!(matches!(register(&input(&exclude, &held)), Err(WalletError::PasskeyExcluded)));
        // No overlap: fine.
        assert!(register(&input(&[vec![1u8; 16]], &held)).is_ok());
    }

    #[test]
    fn assert_refuses_another_rp_id() {
        let reg = register_with(&input(&[], &[]), &SCALAR, vec![1; 16], None).unwrap();
        assert!(assert(&reg.record, "evil.example", &[0; 32], true).is_err());
        assert!(assert(&reg.record, "sub.webauthn.example", &[0; 32], true).is_err());
        // Case does not matter for a domain name.
        assert!(assert(&reg.record, "WebAuthn.Example", &[0; 32], true).is_ok());
    }

    #[test]
    fn register_refuses_invalid_input() {
        let mut bad = input(&[], &[]);
        bad.rp_id = "not a domain";
        assert!(register(&bad).is_err());
        let mut bad = input(&[], &[]);
        bad.user_handle = b"";
        assert!(register(&bad).is_err());
        assert!(register_with(&input(&[], &[]), &[0u8; 32], vec![1; 16], None).is_err(), "zero scalar");
        assert!(register_with(&input(&[], &[]), &SCALAR, vec![1; 15], None).is_err(), "short id");
    }

    #[test]
    fn der_signatures_are_minimal_even_with_short_r_or_s() {
        // About 1 in 128 signatures has r or s below 2^248; DER must then drop
        // the leading zero byte. Strict DER parsing rejects any other encoding,
        // and every signature must verify.
        let reg = register_with(&input(&[], &[]), &SCALAR, vec![1; 16], None).unwrap();
        let mut short = 0;
        for i in 0..2000u32 {
            let mut hash = [0u8; 32];
            hash[..4].copy_from_slice(&i.to_be_bytes());
            let a = assert(&reg.record, "webauthn.example", &hash, true).unwrap();
            let sig = Signature::from_der(&a.signature).expect("strict DER");
            assert_eq!(sig.to_der().as_bytes(), a.signature.as_slice());
            assert!(verify(&reg, &a, &hash));
            if a.signature.len() < 70 {
                short += 1;
            }
        }
        assert!(short > 0, "the sample must include short r or s values");
    }
}
