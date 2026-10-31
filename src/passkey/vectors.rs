//! Golden vectors: `testdata/passkey-vectors.json`.
//!
//! Fixed key, credential id, PRF secrets and inputs, and every byte string the
//! passkey code derives from them. The test regenerates the file and fails on
//! any difference, so a change to the WebAuthn bytes, the signatures or the PRF
//! output can never slip through unnoticed. The iOS extension's Swift tests read
//! the same file, so the two implementations cannot drift apart.
//!
//! Regenerate on purpose only: `IWCORE_WRITE_GOLDEN=1 cargo test --lib vectors`.

use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::b64;
use super::prf::{self, PrfInputs};
use super::record::PrfSecrets;
use super::sign::{self, tests::{input, SCALAR}};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn generate() -> Value {
    let secrets = PrfSecrets {
        with_uv: Zeroizing::new(core::array::from_fn(|i| i as u8)),
        without_uv: Zeroizing::new(core::array::from_fn(|i| 0xFF - i as u8)),
    };
    let credential_id: Vec<u8> = (0x10..0x20).collect();
    let reg = sign::register_with(&input(&[], &[]), &SCALAR, credential_id, Some(secrets)).unwrap();
    let record = &reg.record;

    let client_data_hash: [u8; 32] = core::array::from_fn(|i| 0xA0u8.wrapping_add(i as u8));
    let assertions: Vec<Value> = [true, false]
        .into_iter()
        .map(|uv| {
            let a = sign::assert(record, &record.rp_id, &client_data_hash, uv).unwrap();
            json!({
                "user_verified": uv,
                "authenticator_data": hex(&a.authenticator_data),
                "signature_der": hex(&a.signature),
            })
        })
        .collect();

    let prf_inputs: Vec<Vec<u8>> = vec![vec![], b"WebAuthn PRF test".to_vec(), vec![0x5A; 32], vec![0xC3; 1024]];
    let prf_cases: Vec<Value> = prf_inputs
        .iter()
        .map(|inp| {
            let out = |uv| {
                prf::evaluate_inputs(record, &PrfInputs { first: inp.clone(), second: None }, uv)
                    .unwrap()
                    .unwrap()
            };
            json!({
                "input": hex(inp),
                "salt": hex(&prf::salt(inp)),
                "output_uv": hex(out(true).first.as_slice()),
                "output_no_uv": hex(out(false).first.as_slice()),
            })
        })
        .collect();

    json!({
        "description": "iwcore passkey golden vectors. Never edit by hand; see src/passkey/vectors.rs.",
        "rp_id": record.rp_id,
        "user_name": record.user_name,
        "user_display_name": record.user_display_name,
        "user_handle": hex(&record.user_handle),
        "credential_id": hex(&record.credential_id),
        "aaguid": hex(&super::webauthn::AAGUID),
        "private_key_scalar": hex(&SCALAR),
        "private_key_pkcs8": hex(record.pkcs8()),
        "public_key_cose": hex(&reg.public_key_cose),
        "public_key_spki": hex(&reg.public_key_spki),
        "registration": {
            "user_verified": true,
            "authenticator_data": hex(&reg.authenticator_data),
            "attestation_object": hex(&reg.attestation_object),
        },
        "client_data_hash": hex(&client_data_hash),
        "assertions": assertions,
        "prf": {
            "cred_with_uv": hex(&record.prf().unwrap().with_uv[..]),
            "cred_without_uv": hex(&record.prf().unwrap().without_uv[..]),
            "cases": prf_cases,
        },
        "stored_record": serde_json::from_str::<Value>(&record.to_field_value().unwrap()).unwrap(),
        "stored_record_key_base64url": b64::encode(record.pkcs8()),
    })
}

#[test]
fn golden_vectors_are_unchanged() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/passkey-vectors.json");
    let actual = serde_json::to_string_pretty(&generate()).unwrap() + "\n";
    if std::env::var("IWCORE_WRITE_GOLDEN").is_ok() {
        std::fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).expect("testdata/passkey-vectors.json");
    assert_eq!(actual, expected, "passkey bytes changed; if intended, regenerate on purpose");
}
