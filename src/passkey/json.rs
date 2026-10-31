//! The WebAuthn JSON that Android's Credential Manager hands a provider, and
//! the JSON the provider hands back.
//!
//! Requests come from the **calling app** and are untrusted: everything is
//! bounded and validated here, and the origin never comes from the request (the
//! caller supplies it from the system, see [`super::origin`]).
//!
//! - [`CreationOptions::parse`] / [`RequestOptions::parse`]: the
//!   `PublicKeyCredentialCreationOptionsJSON` / `RequestOptionsJSON` documents;
//! - [`client_data_json`]: the exact `clientDataJSON` bytes and their SHA-256,
//!   for callers that do not supply a `clientDataHash` (native apps);
//! - [`registration_response_json`] / [`assertion_response_json`]: the
//!   `PublicKeyCredential` JSON returned to the system.

use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::b64;
use super::prf::{PrfInputs, PrfOutputs, INPUT_MAX};
use super::record::{validate_rp_id, CREDENTIAL_ID_MAX, USER_HANDLE_MAX, USER_NAME_MAX};
use super::sign::{Assertion, Registration};
use super::ALG_ES256;
use crate::error::{Result, WalletError};

/// Largest request JSON accepted, in bytes.
pub const REQUEST_MAX_BYTES: usize = 64 * 1024;
/// Challenge length limits, in bytes.
pub const CHALLENGE_MIN: usize = 16;
pub const CHALLENGE_MAX: usize = 1024;
/// Most entries read from `allowCredentials` / `excludeCredentials` /
/// `evalByCredential`.
pub const CREDENTIAL_LIST_MAX: usize = 64;

/// The site's user-verification preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserVerification {
    Required,
    Preferred,
    Discouraged,
}

/// PRF as asked for at creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfCreate {
    /// Inputs to evaluate right away, if the site sent any.
    pub eval: Option<PrfInputs>,
}

/// A passkey creation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreationOptions {
    /// `rp.id`, or `None` when the site left it to default to the origin.
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub challenge: Vec<u8>,
    pub exclude_credentials: Vec<Vec<u8>>,
    pub user_verification: UserVerification,
    /// `Some` when the site asked for the PRF extension.
    pub prf: Option<PrfCreate>,
}

/// PRF as asked for at sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrfRequest {
    pub eval: Option<PrfInputs>,
    /// Per-credential inputs; they win over `eval` for that credential.
    pub by_credential: Vec<(Vec<u8>, PrfInputs)>,
}

/// A sign-in request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOptions {
    pub rp_id: Option<String>,
    pub challenge: Vec<u8>,
    /// Empty means any passkey for the rpId (discoverable credentials).
    pub allow_credentials: Vec<Vec<u8>>,
    pub user_verification: UserVerification,
    pub prf: Option<PrfRequest>,
}

impl RequestOptions {
    /// PRF inputs for the credential the user picked.
    pub fn prf_inputs_for(&self, credential_id: &[u8]) -> Option<&PrfInputs> {
        let prf = self.prf.as_ref()?;
        prf.by_credential
            .iter()
            .find(|(id, _)| id == credential_id)
            .map(|(_, inputs)| inputs)
            .or(prf.eval.as_ref())
    }
}

impl CreationOptions {
    /// Parse a `PublicKeyCredentialCreationOptionsJSON` document.
    pub fn parse(json: &str) -> Result<Self> {
        let obj = parse_object(json)?;
        let rp = object(&obj, "rp")?;
        let user = object(&obj, "user")?;

        let rp_id = optional_rp_id(rp.get("id"))?;
        let rp_name = optional_string(rp.get("name"), "rp.name")?.unwrap_or_default();
        let user_id = bytes(user.get("id"), "user.id")?;
        if user_id.is_empty() || user_id.len() > USER_HANDLE_MAX {
            return Err(invalid("user.id must be 1 to 64 bytes"));
        }
        let user_name = optional_string(user.get("name"), "user.name")?.unwrap_or_default();
        let user_display_name =
            optional_string(user.get("displayName"), "user.displayName")?.unwrap_or_default();
        if user_name.len() > USER_NAME_MAX || user_display_name.len() > USER_NAME_MAX {
            return Err(invalid("user.name or user.displayName is too long"));
        }

        let params = match obj.get("pubKeyCredParams") {
            Some(Value::Array(a)) => a.clone(),
            None => Vec::new(),
            Some(_) => return Err(invalid("pubKeyCredParams is not an array")),
        };
        // An empty list means the platform defaults, which include ES256.
        let es256 = params.is_empty()
            || params.iter().any(|p| {
                p.get("type").and_then(Value::as_str) == Some("public-key")
                    && p.get("alg").and_then(Value::as_i64) == Some(ALG_ES256)
            });
        if !es256 {
            return Err(WalletError::NotSupported("the site does not accept ES256".into()));
        }

        let selection = obj.get("authenticatorSelection");
        let user_verification =
            user_verification(selection.and_then(|s| s.get("userVerification")))?;
        let extensions = obj.get("extensions");
        let prf = match extensions.and_then(|e| e.get("prf")) {
            None | Some(Value::Null) => None,
            Some(p) => Some(PrfCreate { eval: prf_inputs(p.get("eval"), "prf.eval")? }),
        };

        Ok(Self {
            rp_id,
            rp_name,
            user_id,
            user_name,
            user_display_name,
            challenge: challenge(&obj)?,
            exclude_credentials: credential_list(obj.get("excludeCredentials"), "excludeCredentials")?,
            user_verification,
            prf,
        })
    }
}

impl RequestOptions {
    /// Parse a `PublicKeyCredentialRequestOptionsJSON` document.
    pub fn parse(json: &str) -> Result<Self> {
        let obj = parse_object(json)?;
        let allow_credentials = credential_list(obj.get("allowCredentials"), "allowCredentials")?;

        let prf = match obj.get("extensions").and_then(|e| e.get("prf")) {
            None | Some(Value::Null) => None,
            Some(p) => {
                let eval = prf_inputs(p.get("eval"), "prf.eval")?;
                let by_credential = match p.get("evalByCredential") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Object(m)) => {
                        if m.len() > CREDENTIAL_LIST_MAX {
                            return Err(invalid("prf.evalByCredential has too many entries"));
                        }
                        // WebAuthn: only meaningful with a non-empty
                        // allowCredentials, and every key must be in it.
                        if !m.is_empty() && allow_credentials.is_empty() {
                            return Err(invalid("prf.evalByCredential needs allowCredentials"));
                        }
                        let mut out = Vec::with_capacity(m.len());
                        for (k, v) in m {
                            let id = b64::decode(k, "prf.evalByCredential key")?;
                            if !allow_credentials.contains(&id) {
                                return Err(invalid("prf.evalByCredential names a credential outside allowCredentials"));
                            }
                            let inputs = prf_inputs(Some(v), "prf.evalByCredential")?
                                .ok_or_else(|| invalid("prf.evalByCredential entry is empty"))?;
                            out.push((id, inputs));
                        }
                        out
                    }
                    Some(_) => return Err(invalid("prf.evalByCredential is not an object")),
                };
                Some(PrfRequest { eval, by_credential })
            }
        };

        Ok(Self {
            rp_id: optional_rp_id(obj.get("rpId"))?,
            challenge: challenge(&obj)?,
            allow_credentials,
            user_verification: user_verification(obj.get("userVerification"))?,
            prf,
        })
    }
}

/// Which ceremony a `clientDataJSON` is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    Create,
    Get,
}

/// Field order as WebAuthn's serialisation defines it: type, challenge, origin,
/// crossOrigin, then the Android extra.
#[derive(Serialize)]
struct ClientData<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    challenge: String,
    origin: &'a str,
    #[serde(rename = "crossOrigin")]
    cross_origin: bool,
    #[serde(rename = "androidPackageName", skip_serializing_if = "Option::is_none")]
    android_package_name: Option<&'a str>,
}

/// The exact `clientDataJSON` bytes and their SHA-256 (the `clientDataHash`
/// that gets signed). `origin` must come from the system, never the request.
pub fn client_data_json(
    ceremony: Ceremony,
    challenge: &[u8],
    origin: &str,
    android_package_name: Option<&str>,
) -> Result<(Vec<u8>, [u8; 32])> {
    let data = ClientData {
        kind: match ceremony {
            Ceremony::Create => "webauthn.create",
            Ceremony::Get => "webauthn.get",
        },
        challenge: b64::encode(challenge),
        origin,
        cross_origin: false,
        android_package_name,
    };
    let bytes = serde_json::to_vec(&data)
        .map_err(|e| WalletError::EncryptionError(format!("clientDataJSON encode failed: {e}")))?;
    let hash = Sha256::digest(&bytes).into();
    Ok((bytes, hash))
}

/// PRF result of a creation: whether the passkey supports PRF, and the outputs
/// when the site sent inputs.
#[derive(Debug, Clone)]
pub struct PrfCreateResult {
    pub enabled: bool,
    pub results: Option<PrfOutputs>,
}

/// The registration `PublicKeyCredential` JSON. `client_data_json` is `None`
/// when the caller (a privileged browser) built the client data itself.
pub fn registration_response_json(
    reg: &Registration,
    client_data_json: Option<&[u8]>,
    prf: Option<&PrfCreateResult>,
) -> String {
    let id = b64::encode(&reg.credential_id);
    let mut response = Map::new();
    if let Some(cd) = client_data_json {
        response.insert("clientDataJSON".into(), b64::encode(cd).into());
    }
    response.insert("attestationObject".into(), b64::encode(&reg.attestation_object).into());
    response.insert("authenticatorData".into(), b64::encode(&reg.authenticator_data).into());
    response.insert("publicKey".into(), b64::encode(&reg.public_key_spki).into());
    response.insert("publicKeyAlgorithm".into(), ALG_ES256.into());
    response.insert("transports".into(), json!(["internal", "hybrid"]));

    let mut ext = Map::new();
    ext.insert("credProps".into(), json!({ "rk": true }));
    if let Some(p) = prf {
        let mut prf_obj = Map::new();
        prf_obj.insert("enabled".into(), p.enabled.into());
        if let Some(results) = &p.results {
            prf_obj.insert("results".into(), prf_results(results));
        }
        ext.insert("prf".into(), Value::Object(prf_obj));
    }

    json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": Value::Object(response),
        "clientExtensionResults": Value::Object(ext),
    })
    .to_string()
}

/// The sign-in `PublicKeyCredential` JSON.
pub fn assertion_response_json(
    assertion: &Assertion,
    client_data_json: Option<&[u8]>,
    prf: Option<&PrfOutputs>,
) -> String {
    let id = b64::encode(&assertion.credential_id);
    let mut response = Map::new();
    if let Some(cd) = client_data_json {
        response.insert("clientDataJSON".into(), b64::encode(cd).into());
    }
    response.insert("authenticatorData".into(), b64::encode(&assertion.authenticator_data).into());
    response.insert("signature".into(), b64::encode(&assertion.signature).into());
    response.insert("userHandle".into(), b64::encode(&assertion.user_handle).into());

    let mut ext = Map::new();
    if let Some(results) = prf {
        ext.insert("prf".into(), json!({ "results": prf_results(results) }));
    }

    json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": Value::Object(response),
        "clientExtensionResults": Value::Object(ext),
    })
    .to_string()
}

fn prf_results(o: &PrfOutputs) -> Value {
    let mut m = Map::new();
    m.insert("first".into(), b64::encode(o.first.as_slice()).into());
    if let Some(second) = &o.second {
        m.insert("second".into(), b64::encode(second.as_slice()).into());
    }
    Value::Object(m)
}

// --- parsing helpers --------------------------------------------------------

fn invalid(msg: &str) -> WalletError {
    WalletError::InvalidInput(msg.to_string())
}

fn parse_object(json: &str) -> Result<Map<String, Value>> {
    if json.len() > REQUEST_MAX_BYTES {
        return Err(invalid("request is larger than 64 KiB"));
    }
    match serde_json::from_str(json) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(invalid("request is not a JSON object")),
    }
}

fn object<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a Map<String, Value>> {
    obj.get(key).and_then(Value::as_object).ok_or_else(|| invalid(&format!("{key} is missing or not an object")))
}

fn optional_string(v: Option<&Value>, what: &str) -> Result<Option<String>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(invalid(&format!("{what} is not a string"))),
    }
}

fn bytes(v: Option<&Value>, what: &str) -> Result<Vec<u8>> {
    let s = v.and_then(Value::as_str).ok_or_else(|| invalid(&format!("{what} is missing")))?;
    b64::decode(s, what)
}

fn optional_rp_id(v: Option<&Value>) -> Result<Option<String>> {
    match optional_string(v, "rpId")? {
        None => Ok(None),
        Some(id) => {
            let id = id.to_ascii_lowercase();
            validate_rp_id(&id)?;
            Ok(Some(id))
        }
    }
}

fn challenge(obj: &Map<String, Value>) -> Result<Vec<u8>> {
    let c = bytes(obj.get("challenge"), "challenge")?;
    if !(CHALLENGE_MIN..=CHALLENGE_MAX).contains(&c.len()) {
        return Err(invalid("challenge must be 16 to 1024 bytes"));
    }
    Ok(c)
}

fn credential_list(v: Option<&Value>, what: &str) -> Result<Vec<Vec<u8>>> {
    let list = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(_) => return Err(invalid(&format!("{what} is not an array"))),
    };
    if list.len() > CREDENTIAL_LIST_MAX {
        return Err(invalid(&format!("{what} has too many entries")));
    }
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        if entry.get("type").and_then(Value::as_str).is_some_and(|t| t != "public-key") {
            continue; // other credential types are not ours to match
        }
        let id = bytes(entry.get("id"), what)?;
        if id.is_empty() || id.len() > CREDENTIAL_ID_MAX {
            return Err(invalid(&format!("{what} has a credential id of invalid length")));
        }
        out.push(id);
    }
    Ok(out)
}

fn user_verification(v: Option<&Value>) -> Result<UserVerification> {
    match v.and_then(Value::as_str) {
        None | Some("preferred") => Ok(UserVerification::Preferred),
        Some("required") => Ok(UserVerification::Required),
        Some("discouraged") => Ok(UserVerification::Discouraged),
        // WebAuthn: an unknown value is treated as the default.
        Some(_) => Ok(UserVerification::Preferred),
    }
}

fn prf_inputs(v: Option<&Value>, what: &str) -> Result<Option<PrfInputs>> {
    let obj = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(o)) => o,
        Some(_) => return Err(invalid(&format!("{what} is not an object"))),
    };
    let first = bytes(obj.get("first"), &format!("{what}.first"))?;
    let second = match obj.get("second") {
        None | Some(Value::Null) => None,
        Some(v) => Some(bytes(Some(v), &format!("{what}.second"))?),
    };
    if first.len() > INPUT_MAX || second.as_ref().is_some_and(|s| s.len() > INPUT_MAX) {
        return Err(invalid(&format!("{what} input is larger than 1 KiB")));
    }
    Ok(Some(PrfInputs { first, second }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::prf;
    use crate::passkey::sign::{self, tests::{input, SCALAR}};
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    fn e(b: &[u8]) -> String {
        b64::encode(b)
    }

    /// Shaped like the creation options webauthn.io sends through Chrome on
    /// Android, with PRF requested.
    fn creation_fixture() -> Value {
        json!({
            "rp": {"name": "webauthn.io", "id": "webauthn.io"},
            "user": {"id": e(b"user-id-123"), "name": "bkv", "displayName": "bkv"},
            "challenge": e(&[7u8; 32]),
            "pubKeyCredParams": [{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
            "timeout": 60000,
            "excludeCredentials": [{"id": e(&[1u8; 16]), "type": "public-key", "transports": ["internal"]}],
            "authenticatorSelection": {"residentKey": "required", "requireResidentKey": true, "userVerification": "required"},
            "attestation": "none",
            "hints": [],
            "extensions": {"credProps": true, "prf": {"eval": {"first": e(b"salt-one")}}}
        })
    }

    fn request_fixture() -> Value {
        json!({
            "challenge": e(&[9u8; 32]),
            "timeout": 60000,
            "rpId": "webauthn.io",
            "allowCredentials": [{"id": e(&[1u8; 16]), "type": "public-key"}, {"id": e(&[2u8; 16]), "type": "public-key"}],
            "userVerification": "preferred",
            "extensions": {"prf": {"eval": {"first": e(b"a")}, "evalByCredential": {e(&[2u8; 16]): {"first": e(b"b"), "second": e(b"c")}}}}
        })
    }

    #[test]
    fn creation_options_parse() {
        let o = CreationOptions::parse(&creation_fixture().to_string()).unwrap();
        assert_eq!(o.rp_id.as_deref(), Some("webauthn.io"));
        assert_eq!(o.user_id, b"user-id-123");
        assert_eq!(o.challenge, vec![7u8; 32]);
        assert_eq!(o.exclude_credentials, vec![vec![1u8; 16]]);
        assert_eq!(o.user_verification, UserVerification::Required);
        assert_eq!(o.prf, Some(PrfCreate { eval: Some(PrfInputs { first: b"salt-one".to_vec(), second: None }) }));
    }

    #[test]
    fn minimal_creation_options_use_defaults() {
        let o = CreationOptions::parse(&json!({
            "rp": {"name": "x"}, "user": {"id": e(b"u")}, "challenge": e(&[0; 16])
        }).to_string()).unwrap();
        assert_eq!(o.rp_id, None);
        assert_eq!(o.user_name, "");
        assert_eq!(o.user_verification, UserVerification::Preferred);
        assert!(o.prf.is_none() && o.exclude_credentials.is_empty());
    }

    #[test]
    fn creation_without_es256_is_not_supported() {
        let mut f = creation_fixture();
        f["pubKeyCredParams"] = json!([{"type": "public-key", "alg": -257}]);
        assert!(matches!(CreationOptions::parse(&f.to_string()), Err(WalletError::NotSupported(_))));
    }

    #[test]
    fn request_options_parse_and_prf_selection() {
        let o = RequestOptions::parse(&request_fixture().to_string()).unwrap();
        assert_eq!(o.allow_credentials.len(), 2);
        assert_eq!(o.prf_inputs_for(&[2u8; 16]).unwrap().first, b"b");
        assert_eq!(o.prf_inputs_for(&[2u8; 16]).unwrap().second.as_deref(), Some(&b"c"[..]));
        assert_eq!(o.prf_inputs_for(&[1u8; 16]).unwrap().first, b"a", "falls back to eval");
        assert!(RequestOptions::parse(&json!({"challenge": e(&[0; 16])}).to_string()).unwrap().prf_inputs_for(&[1]).is_none());
    }

    #[test]
    fn eval_by_credential_rules() {
        let mut f = request_fixture();
        f["allowCredentials"] = json!([]);
        assert!(RequestOptions::parse(&f.to_string()).is_err(), "needs allowCredentials");
        let mut f = request_fixture();
        f["extensions"]["prf"]["evalByCredential"] = json!({ e(&[3u8; 16]): {"first": e(b"x")} });
        assert!(RequestOptions::parse(&f.to_string()).is_err(), "key outside allowCredentials");
    }

    #[test]
    fn every_bound_just_inside_and_just_outside() {
        let set = |path: &[&str], v: Value| {
            let mut f = creation_fixture();
            let mut cur = &mut f;
            for p in &path[..path.len() - 1] {
                cur = cur.get_mut(*p).unwrap();
            }
            cur[path[path.len() - 1]] = v;
            CreationOptions::parse(&f.to_string())
        };
        assert!(set(&["challenge"], e(&[0; 16]).into()).is_ok());
        assert!(set(&["challenge"], e(&[0; 15]).into()).is_err());
        assert!(set(&["challenge"], e(&[0; 1024]).into()).is_ok());
        assert!(set(&["challenge"], e(&[0; 1025]).into()).is_err());
        assert!(set(&["user", "id"], e(&[0; 64]).into()).is_ok());
        assert!(set(&["user", "id"], e(&[0; 65]).into()).is_err());
        assert!(set(&["user", "id"], "".into()).is_err());
        assert!(set(&["user", "name"], "n".repeat(USER_NAME_MAX).into()).is_ok());
        assert!(set(&["user", "name"], "n".repeat(USER_NAME_MAX + 1).into()).is_err());
        assert!(set(&["user", "displayName"], "n".repeat(USER_NAME_MAX).into()).is_ok());
        assert!(set(&["user", "displayName"], "n".repeat(USER_NAME_MAX + 1).into()).is_err());
        assert!(set(&["rp", "id"], "Not A Domain".into()).is_err());
        assert!(set(&["rp", "id"], "WebAuthn.IO".into()).unwrap().rp_id.as_deref() == Some("webauthn.io"));
        let creds = |n: usize| Value::Array((0..n).map(|i| json!({"type": "public-key", "id": e(&[i as u8; 16])})).collect());
        assert!(set(&["excludeCredentials"], creds(CREDENTIAL_LIST_MAX)).is_ok());
        assert!(set(&["excludeCredentials"], creds(CREDENTIAL_LIST_MAX + 1)).is_err());
        assert!(set(&["excludeCredentials"], json!([{"type": "public-key", "id": e(&[0; CREDENTIAL_ID_MAX])}])).is_ok());
        assert!(set(&["excludeCredentials"], json!([{"type": "public-key", "id": e(&[0; CREDENTIAL_ID_MAX + 1])}])).is_err());
        assert!(set(&["extensions", "prf", "eval"], json!({"first": e(&[0; 1024])})).is_ok());
        assert!(set(&["extensions", "prf", "eval"], json!({"first": e(&[0; 1025])})).is_err());
        assert!(set(&["extensions", "prf", "eval"], json!({"first": e(b"a"), "second": e(&[0; prf::INPUT_MAX])})).is_ok());
        assert!(set(&["extensions", "prf", "eval"], json!({"first": e(b"a"), "second": e(&[0; prf::INPUT_MAX + 1])})).is_err());
        assert!(CreationOptions::parse(&" ".repeat(REQUEST_MAX_BYTES + 1)).is_err());
        // Exactly the size limit, padded with JSON whitespace.
        let padded = |f: Value| {
            let s = f.to_string();
            format!("{s}{}", " ".repeat(REQUEST_MAX_BYTES - s.len()))
        };
        assert!(CreationOptions::parse(&padded(creation_fixture())).is_ok());
        assert!(RequestOptions::parse(&padded(request_fixture())).is_ok());
    }

    #[test]
    fn eval_by_credential_bounds() {
        let with = |n: usize, allow: usize| {
            let mut f = request_fixture();
            f["allowCredentials"] = Value::Array((0..allow).map(|i| json!({"type": "public-key", "id": e(&[i as u8; 16])})).collect());
            let by: Map<String, Value> = (0..n).map(|i| (e(&[i as u8; 16]), json!({"first": e(b"x")}))).collect();
            f["extensions"]["prf"]["evalByCredential"] = Value::Object(by);
            RequestOptions::parse(&f.to_string())
        };
        assert!(with(CREDENTIAL_LIST_MAX, CREDENTIAL_LIST_MAX).is_ok());
        assert!(with(CREDENTIAL_LIST_MAX + 1, CREDENTIAL_LIST_MAX).is_err());
        assert!(with(0, 0).is_ok(), "an empty evalByCredential needs no allowCredentials");
        assert!(with(1, 0).is_err());
    }

    #[test]
    fn malformed_requests_are_refused_without_panicking() {
        for bad in ["", "null", "[]", "{", "\"x\"", "{\"rp\": 5}", "{\"rp\": {}, \"user\": {}}"] {
            assert!(CreationOptions::parse(bad).is_err(), "{bad}");
            assert!(RequestOptions::parse(bad).is_err(), "{bad}");
        }
        let mut f = creation_fixture();
        f["challenge"] = "not+base64/".into();
        assert!(CreationOptions::parse(&f.to_string()).is_err());
        let mut f = request_fixture();
        f["allowCredentials"] = json!("x");
        assert!(RequestOptions::parse(&f.to_string()).is_err());
    }

    #[test]
    fn other_credential_types_in_lists_are_ignored() {
        let mut f = request_fixture();
        f["allowCredentials"] = json!([{"type": "password", "id": "!!"}, {"type": "public-key", "id": e(&[1; 16])}]);
        f["extensions"] = json!({});
        assert_eq!(RequestOptions::parse(&f.to_string()).unwrap().allow_credentials, vec![vec![1u8; 16]]);
    }

    #[test]
    fn client_data_json_is_exact_and_escaped() {
        let (bytes, hash) = client_data_json(Ceremony::Get, &[1, 2, 3], "https://example.com", None).unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            r#"{"type":"webauthn.get","challenge":"AQID","origin":"https://example.com","crossOrigin":false}"#
        );
        assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(&bytes)));
        let (bytes, _) = client_data_json(
            Ceremony::Create, &[0xFF], "android:apk-key-hash:abc\"},\"x\":\"", Some("com.example"),
        ).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["type"], "webauthn.create");
        assert_eq!(v["origin"], "android:apk-key-hash:abc\"},\"x\":\"", "quotes stay inside the value");
        assert_eq!(v["androidPackageName"], "com.example");
        assert!(v.get("x").is_none());
    }

    #[test]
    fn registration_response_round_trips_and_verifies() {
        let reg = sign::register_with(&input(&[], &[]), &SCALAR, vec![5; 16], Some(crate::passkey::PrfSecrets::generate().unwrap())).unwrap();
        let (cd, _) = client_data_json(Ceremony::Create, &[7; 32], "https://webauthn.example", None).unwrap();
        let outputs = prf::evaluate_inputs(&reg.record, &PrfInputs { first: b"x".to_vec(), second: None }, true).unwrap();
        let prf_result = PrfCreateResult { enabled: true, results: outputs };
        let v: Value = serde_json::from_str(&registration_response_json(&reg, Some(&cd), Some(&prf_result))).unwrap();
        assert_eq!(v["id"], e(&[5; 16]));
        assert_eq!(v["rawId"], v["id"]);
        assert_eq!(v["type"], "public-key");
        assert_eq!(v["authenticatorAttachment"], "platform");
        assert_eq!(v["response"]["publicKeyAlgorithm"], -7);
        assert_eq!(b64::decode(v["response"]["attestationObject"].as_str().unwrap(), "x").unwrap(), reg.attestation_object);
        assert_eq!(b64::decode(v["response"]["clientDataJSON"].as_str().unwrap(), "x").unwrap(), cd);
        assert!(VerifyingKey::from_public_key_der(&b64::decode(v["response"]["publicKey"].as_str().unwrap(), "x").unwrap()).is_ok());
        assert_eq!(v["clientExtensionResults"]["credProps"]["rk"], true);
        assert_eq!(v["clientExtensionResults"]["prf"]["enabled"], true);
        assert!(v["clientExtensionResults"]["prf"]["results"]["first"].is_string());
        for s in [&v["id"], &v["response"]["authenticatorData"], &v["response"]["publicKey"]] {
            assert!(!s.as_str().unwrap().contains('='));
        }
        // A privileged browser built the client data: no clientDataJSON.
        let v: Value = serde_json::from_str(&registration_response_json(&reg, None, None)).unwrap();
        assert!(v["response"].get("clientDataJSON").is_none());
        assert!(v["clientExtensionResults"].get("prf").is_none());
    }

    #[test]
    fn assertion_response_verifies_end_to_end() {
        let reg = sign::register_with(&input(&[], &[]), &SCALAR, vec![5; 16], None).unwrap();
        let (cd, hash) = client_data_json(Ceremony::Get, &[9; 32], "https://webauthn.example", None).unwrap();
        let a = sign::assert(&reg.record, "webauthn.example", &hash, true).unwrap();
        let v: Value = serde_json::from_str(&assertion_response_json(&a, Some(&cd), None)).unwrap();
        let auth = b64::decode(v["response"]["authenticatorData"].as_str().unwrap(), "x").unwrap();
        let sig = b64::decode(v["response"]["signature"].as_str().unwrap(), "x").unwrap();
        let cd_back = b64::decode(v["response"]["clientDataJSON"].as_str().unwrap(), "x").unwrap();
        // What a relying party does: hash the client data, verify the signature.
        let mut msg = auth.clone();
        msg.extend_from_slice(&Sha256::digest(&cd_back));
        let key = VerifyingKey::from_public_key_der(&reg.public_key_spki).unwrap();
        key.verify(&msg, &Signature::from_der(&sig).unwrap()).unwrap();
        assert_eq!(v["response"]["userHandle"], e(&reg.record.user_handle));
        assert!(v["clientExtensionResults"].as_object().unwrap().is_empty());
    }
}
