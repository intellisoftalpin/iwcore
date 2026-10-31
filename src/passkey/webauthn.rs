//! The WebAuthn bytes every relying party verifies.
//!
//! ```text
//! authenticatorData (sign-in)   = SHA-256(rpId) ‖ flags ‖ u32 BE counter
//! authenticatorData (creation)  = the above ‖ AAGUID ‖ u16 BE len ‖ credentialId ‖ COSE key
//!
//! COSE EC2 key, CTAP2 canonical order 1, 3, -1, -2, -3:
//!   A5 01 02 03 26 20 01 21 58 20 <x:32> 22 58 20 <y:32>
//!
//! attestationObject, fmt "none", canonical order fmt, attStmt, authData:
//!   A3 63 "fmt" 64 "none" 67 "attStmt" A0 68 "authData" <bstr authData>
//! ```
//!
//! Both shapes are fixed, so they are written by hand here rather than through
//! a CBOR library. The tests decode every output with independent libraries
//! (`ciborium`, `coset`) to make sure the hand-written bytes are what they claim.

use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};

/// IntelliWallet's authenticator id, `a2117fe2-e236-40fa-9481-ca437bd8b94e`.
/// Relying parties use it to show which manager holds a passkey. Never changes.
pub const AAGUID: [u8; 16] = [
    0xa2, 0x11, 0x7f, 0xe2, 0xe2, 0x36, 0x40, 0xfa, 0x94, 0x81, 0xca, 0x43, 0x7b, 0xd8, 0xb9, 0x4e,
];

/// User present.
pub const FLAG_UP: u8 = 0x01;
/// User verified (biometric or device passcode).
pub const FLAG_UV: u8 = 0x04;
/// Backup eligible: the credential may live in more than one place.
pub const FLAG_BE: u8 = 0x08;
/// Backed up: it currently does (vault backups, later sync).
pub const FLAG_BS: u8 = 0x10;
/// Attested credential data follows (creation only).
pub const FLAG_AT: u8 = 0x40;

/// Length of a COSE EC2 P-256 public key as written here.
pub const COSE_KEY_LEN: usize = 77;

/// The flags byte. UP, BE and BS are always set; UV only when the provider
/// actually verified the user; AT only on creation.
pub fn flags(user_verified: bool, attested: bool) -> u8 {
    let mut f = FLAG_UP | FLAG_BE | FLAG_BS;
    if user_verified {
        f |= FLAG_UV;
    }
    if attested {
        f |= FLAG_AT;
    }
    f
}

/// SHA-256 of the rpId, as authenticator data starts with it.
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// Authenticator data for a sign-in: 37 bytes, sign counter 0.
pub fn authenticator_data_assert(rp_id: &str, user_verified: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(flags(user_verified, false));
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

/// Authenticator data for a creation, carrying the new credential.
///
/// `credential_id` must be at most 1023 bytes (the caller validates it); the
/// length field is two bytes.
pub fn authenticator_data_create(
    rp_id: &str,
    user_verified: bool,
    credential_id: &[u8],
    cose_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(37 + 18 + credential_id.len() + cose_key.len());
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(flags(user_verified, true));
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&AAGUID);
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(cose_key);
    out
}

/// Uncompressed SEC1 encoding of a P-256 public key: `04 ‖ x ‖ y`, 65 bytes.
pub fn sec1_uncompressed(key: &VerifyingKey) -> [u8; 65] {
    let point = key.to_sec1_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(point.as_bytes());
    out
}

/// The COSE EC2 encoding of a P-256 public key, ES256.
pub fn cose_public_key(key: &VerifyingKey) -> [u8; COSE_KEY_LEN] {
    let sec1 = sec1_uncompressed(key);
    let mut out = [0u8; COSE_KEY_LEN];
    out[..10].copy_from_slice(&[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
    out[10..42].copy_from_slice(&sec1[1..33]);
    out[42..45].copy_from_slice(&[0x22, 0x58, 0x20]);
    out[45..77].copy_from_slice(&sec1[33..65]);
    out
}

/// The attestation object with format `none` around `auth_data`.
pub fn attestation_object_none(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(auth_data.len() + 32);
    out.push(0xA3);
    out.extend_from_slice(b"\x63fmt\x64none");
    out.extend_from_slice(b"\x67attStmt\xA0");
    out.extend_from_slice(b"\x68authData");
    push_cbor_bytes_header(&mut out, auth_data.len());
    out.extend_from_slice(auth_data);
    out
}

/// CBOR major type 2 (byte string) header for `len` bytes, shortest form.
fn push_cbor_bytes_header(out: &mut Vec<u8>, len: usize) {
    match len {
        0..=23 => out.push(0x40 | len as u8),
        24..=0xFF => out.extend_from_slice(&[0x58, len as u8]),
        0x100..=0xFFFF => {
            out.push(0x59);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(0x5A);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value as Cbor;
    use coset::{CborSerializable, CoseKey, KeyType, Label, iana};
    use p256::ecdsa::SigningKey;
    use proptest::prelude::*;

    fn key(seed: u8) -> VerifyingKey {
        let bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(seed) | 1);
        *SigningKey::from_slice(&bytes).unwrap().verifying_key()
    }

    #[test]
    fn flags_for_every_combination() {
        assert_eq!(flags(false, false), 0x19);
        assert_eq!(flags(true, false), 0x1D);
        assert_eq!(flags(false, true), 0x59);
        assert_eq!(flags(true, true), 0x5D);
    }

    #[test]
    fn assert_data_layout_is_exact() {
        let d = authenticator_data_assert("example.com", true);
        assert_eq!(d.len(), 37);
        assert_eq!(&d[..32], &rp_id_hash("example.com"));
        assert_eq!(d[32], FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS);
        assert_eq!(&d[33..], &[0, 0, 0, 0]);
        // SHA-256("example.com"), a published value.
        assert_eq!(
            hex(&rp_id_hash("example.com")),
            "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"
        );
    }

    #[test]
    fn create_data_layout_is_exact_for_every_id_length() {
        let k = key(3);
        let cose = cose_public_key(&k);
        for len in [16usize, 32, 255, 256, 1023] {
            let id = vec![0x5A; len];
            let d = authenticator_data_create("a.example", false, &id, &cose);
            assert_eq!(d.len(), 37 + 16 + 2 + len + COSE_KEY_LEN);
            assert_eq!(d[32], FLAG_UP | FLAG_BE | FLAG_BS | FLAG_AT);
            assert_eq!(&d[37..53], &AAGUID);
            assert_eq!(u16::from_be_bytes([d[53], d[54]]) as usize, len);
            assert_eq!(&d[55..55 + len], id.as_slice());
            assert_eq!(&d[55 + len..], &cose);
        }
    }

    #[test]
    fn cose_key_decodes_independently_and_matches_the_point() {
        for seed in 0..32 {
            let k = key(seed);
            let bytes = cose_public_key(&k);
            let decoded = CoseKey::from_slice(&bytes).unwrap();
            assert_eq!(decoded.kty, KeyType::Assigned(iana::KeyType::EC2));
            assert_eq!(decoded.alg, Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)));
            let param = |l: i64| {
                decoded.params.iter().find(|(k, _)| *k == Label::Int(l)).map(|(_, v)| v.clone()).unwrap()
            };
            let sec1 = k.to_sec1_bytes();
            assert_eq!(sec1.len(), 65);
            assert_eq!(sec1[0], 0x04);
            assert_eq!(param(-1), Cbor::Integer(1.into()), "crv P-256");
            assert_eq!(param(-2), Cbor::Bytes(sec1[1..33].to_vec()));
            assert_eq!(param(-3), Cbor::Bytes(sec1[33..65].to_vec()));
            // Re-encoding canonically gives the same bytes.
            assert_eq!(decoded.to_vec().unwrap(), bytes.to_vec());
        }
    }

    #[test]
    fn attestation_object_decodes_independently() {
        let cose = cose_public_key(&key(1));
        for len in [16usize, 300, 1023] {
            let auth = authenticator_data_create("x.example", true, &vec![1; len], &cose);
            let att = attestation_object_none(&auth);
            let v: Cbor = ciborium::from_reader(att.as_slice()).unwrap();
            let map = v.as_map().unwrap();
            assert_eq!(map.len(), 3);
            assert_eq!(map[0], (Cbor::Text("fmt".into()), Cbor::Text("none".into())));
            assert_eq!(map[1], (Cbor::Text("attStmt".into()), Cbor::Map(vec![])));
            assert_eq!(map[2], (Cbor::Text("authData".into()), Cbor::Bytes(auth.clone())));
        }
    }

    #[test]
    fn byte_string_headers_use_the_shortest_form() {
        let h = |n: usize| {
            let mut v = Vec::new();
            push_cbor_bytes_header(&mut v, n);
            v
        };
        assert_eq!(h(0), [0x40]);
        assert_eq!(h(23), [0x57]);
        assert_eq!(h(24), [0x58, 24]);
        assert_eq!(h(255), [0x58, 255]);
        assert_eq!(h(256), [0x59, 1, 0]);
        assert_eq!(h(65535), [0x59, 0xFF, 0xFF]);
        assert_eq!(h(65536), [0x5A, 0, 1, 0, 0]);
        for n in [0usize, 23, 24, 255, 256, 65535, 65536] {
            let mut enc = h(n);
            enc.extend(std::iter::repeat_n(0u8, n));
            let v: Cbor = ciborium::from_reader(enc.as_slice()).unwrap();
            assert_eq!(v.as_bytes().unwrap().len(), n);
        }
    }

    proptest! {
        #[test]
        fn any_credential_decodes_back_to_its_inputs(
            id in proptest::collection::vec(any::<u8>(), 16..=1023),
            rp in "[a-z]{1,20}\\.[a-z]{2,6}",
            uv in any::<bool>(),
            seed in any::<u8>(),
        ) {
            let k = key(seed);
            let cose = cose_public_key(&k);
            let auth = authenticator_data_create(&rp, uv, &id, &cose);
            let att = attestation_object_none(&auth);
            let v: Cbor = ciborium::from_reader(att.as_slice()).unwrap();
            let got = v.as_map().unwrap()[2].1.as_bytes().unwrap().clone();
            prop_assert_eq!(&got, &auth);
            prop_assert_eq!(&got[..32], &rp_id_hash(&rp)[..]);
            prop_assert_eq!(got[32] & FLAG_UV != 0, uv);
            let n = u16::from_be_bytes([got[53], got[54]]) as usize;
            prop_assert_eq!(&got[55..55 + n], id.as_slice());
            let decoded = CoseKey::from_slice(&got[55 + n..]).unwrap();
            prop_assert_eq!(decoded.to_vec().unwrap(), cose.to_vec());
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
