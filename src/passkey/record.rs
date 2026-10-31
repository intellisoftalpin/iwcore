//! The stored passkey: the value of a `PKEY` field.
//!
//! UTF-8 JSON shaped after the CXF passkey item, so moving passkeys in and out
//! with other managers is a mapping, not a migration:
//!
//! ```json
//! {
//!   "v": 1,
//!   "credentialId": "<base64url>",
//!   "rpId": "github.com",
//!   "userName": "bkv",
//!   "userDisplayName": "bkv",
//!   "userHandle": "<base64url>",
//!   "key": "<base64url PKCS#8 P-256 private key>",
//!   "alg": -7,
//!   "createdAt": 1793433600,
//!   "fido2Extensions": { "hmacCredentials": { … } }
//! }
//! ```
//!
//! Rules:
//!
//! - binary values are base64url, written without padding, read either way;
//! - every value is validated on read; a record that breaks a rule is refused
//!   as a whole, and the caller skips it rather than failing (one bad record
//!   must never take the rest of the vault with it);
//! - fields this version does not know, at the top level and inside
//!   `fido2Extensions`, are kept and written back unchanged;
//! - the private key and the PRF secrets have no public getter and are printed
//!   as `[redacted]` by `Debug`.

use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{b64, ALG_ES256};
use crate::error::{Result, WalletError};
use crate::utils::REDACTED;

/// Record format version written by this crate.
pub const RECORD_VERSION: u64 = 1;

/// Credential id length limits (WebAuthn: at least 16 bytes of entropy, at
/// most 1023 bytes).
pub const CREDENTIAL_ID_MIN: usize = 16;
pub const CREDENTIAL_ID_MAX: usize = 1023;
/// User handle length limits (WebAuthn: 1 to 64 bytes).
pub const USER_HANDLE_MAX: usize = 64;
/// Longest user name or display name kept, in bytes.
pub const USER_NAME_MAX: usize = 4096;
/// Longest stored record accepted, in bytes.
pub const RECORD_MAX: usize = 64 * 1024;
/// PRF secret length (CXF `hmacCredentials`: 32 bytes each).
pub const PRF_SECRET_LEN: usize = 32;

const K_VERSION: &str = "v";
const K_CREDENTIAL_ID: &str = "credentialId";
const K_RP_ID: &str = "rpId";
const K_USER_NAME: &str = "userName";
const K_USER_DISPLAY_NAME: &str = "userDisplayName";
const K_USER_HANDLE: &str = "userHandle";
const K_KEY: &str = "key";
const K_ALG: &str = "alg";
const K_CREATED_AT: &str = "createdAt";
const K_FIDO2: &str = "fido2Extensions";
const K_HMAC: &str = "hmacCredentials";
const HMAC_ALGORITHM: &str = "hmac-sha256";

const KNOWN: [&str; 10] = [
    K_VERSION, K_CREDENTIAL_ID, K_RP_ID, K_USER_NAME, K_USER_DISPLAY_NAME, K_USER_HANDLE, K_KEY,
    K_ALG, K_CREATED_AT, K_FIDO2,
];

/// The two secrets behind the WebAuthn PRF extension (CXF `hmacCredentials`).
/// One answers when the user was verified, the other when not.
#[derive(Clone, PartialEq, Eq)]
pub struct PrfSecrets {
    pub(crate) with_uv: Zeroizing<[u8; PRF_SECRET_LEN]>,
    pub(crate) without_uv: Zeroizing<[u8; PRF_SECRET_LEN]>,
}

impl std::fmt::Debug for PrfSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PrfSecrets {
    /// Two fresh secrets from the operating system's generator.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            with_uv: crate::crypto::rng::secret::<PRF_SECRET_LEN>()?,
            without_uv: crate::crypto::rng::secret::<PRF_SECRET_LEN>()?,
        })
    }

    fn to_json(&self) -> Value {
        serde_json::json!({
            "algorithm": HMAC_ALGORITHM,
            "credWithUV": b64::encode(self.with_uv.as_slice()),
            "credWithoutUV": b64::encode(self.without_uv.as_slice()),
        })
    }

    /// Read CXF `hmacCredentials`. `None` when the algorithm is unknown or a
    /// secret is not exactly 32 bytes: such a passkey simply has no PRF, as the
    /// CXF specification asks importers to ignore what they cannot use.
    fn from_json(value: &Value) -> Option<Self> {
        let obj = value.as_object()?;
        if obj.get("algorithm")?.as_str()? != HMAC_ALGORITHM {
            return None;
        }
        let read = |k: &str| -> Option<Zeroizing<[u8; PRF_SECRET_LEN]>> {
            let bytes = Zeroizing::new(b64::decode(obj.get(k)?.as_str()?, k).ok()?);
            let arr: [u8; PRF_SECRET_LEN] = bytes.as_slice().try_into().ok()?;
            Some(Zeroizing::new(arr))
        };
        Some(Self { with_uv: read("credWithUV")?, without_uv: read("credWithoutUV")? })
    }
}

/// A passkey with everything needed to sign with it.
#[derive(Clone)]
pub struct PasskeyRecord {
    pub credential_id: Vec<u8>,
    /// Lower case; passkeys are scoped to the exact rpId.
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_handle: Vec<u8>,
    /// PKCS#8 DER of the P-256 private key.
    key: Zeroizing<Vec<u8>>,
    pub created_at: i64,
    /// Parsed from `fido2Extensions.hmacCredentials`, when usable.
    prf: Option<PrfSecrets>,
    /// `fido2Extensions` exactly as stored, so unknown members survive.
    fido2_extensions: Option<Map<String, Value>>,
    /// Top-level members this version does not know, kept for round trips.
    extra: Map<String, Value>,
}

impl std::fmt::Debug for PasskeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyRecord")
            .field("credential_id", &b64::encode(&self.credential_id))
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("user_display_name", &self.user_display_name)
            .field("user_handle", &b64::encode(&self.user_handle))
            .field("key", &REDACTED)
            .field("created_at", &self.created_at)
            .field("prf", &self.prf.as_ref().map(|_| REDACTED))
            .field("fido2_extensions", &self.fido2_extensions.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// What may be shown about a passkey: never the key, never the PRF secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeySummary {
    /// Item holding the passkey, when it comes from the vault.
    pub item_id: String,
    /// `PKEY` field holding the passkey, when it comes from the vault.
    pub field_id: String,
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_handle: Vec<u8>,
    pub created_at: i64,
    /// True when the passkey carries PRF secrets.
    pub has_prf: bool,
}

impl PasskeyRecord {
    /// Build a validated record. Used by registration and by imports.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        credential_id: Vec<u8>,
        rp_id: &str,
        user_name: &str,
        user_display_name: &str,
        user_handle: Vec<u8>,
        pkcs8_key: Zeroizing<Vec<u8>>,
        created_at: i64,
        prf: Option<PrfSecrets>,
    ) -> Result<Self> {
        let fido2_extensions = prf.as_ref().map(|p| {
            let mut m = Map::new();
            m.insert(K_HMAC.into(), p.to_json());
            m
        });
        let record = Self {
            credential_id,
            rp_id: rp_id.to_ascii_lowercase(),
            user_name: user_name.to_string(),
            user_display_name: user_display_name.to_string(),
            user_handle,
            key: pkcs8_key,
            created_at,
            prf,
            fido2_extensions,
            extra: Map::new(),
        };
        record.validate()?;
        Ok(record)
    }

    /// Parse and validate a stored `PKEY` value.
    pub fn from_field_value(text: &str) -> Result<Self> {
        if text.len() > RECORD_MAX {
            return Err(invalid("passkey record is larger than 64 KiB"));
        }
        let mut obj: Map<String, Value> = match serde_json::from_str(text) {
            Ok(Value::Object(obj)) => obj,
            _ => return Err(invalid("passkey record is not a JSON object")),
        };

        match obj.get(K_VERSION).and_then(Value::as_u64) {
            Some(RECORD_VERSION) => {}
            Some(_) => return Err(WalletError::NotSupported("passkey record version".into())),
            None => return Err(invalid("passkey record has no version")),
        }
        let str_of = |obj: &Map<String, Value>, k: &str| -> Result<String> {
            obj.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| invalid(&format!("passkey record has no string {k}")))
        };

        let credential_id = b64::decode(&str_of(&obj, K_CREDENTIAL_ID)?, K_CREDENTIAL_ID)?;
        let rp_id = str_of(&obj, K_RP_ID)?.to_ascii_lowercase();
        let user_name = str_of(&obj, K_USER_NAME)?;
        let user_display_name = str_of(&obj, K_USER_DISPLAY_NAME)?;
        let user_handle = b64::decode(&str_of(&obj, K_USER_HANDLE)?, K_USER_HANDLE)?;
        let key = Zeroizing::new(b64::decode(&Zeroizing::new(str_of(&obj, K_KEY)?), K_KEY)?);
        match obj.get(K_ALG).and_then(Value::as_i64) {
            Some(ALG_ES256) => {}
            Some(_) => return Err(WalletError::NotSupported("passkey algorithm other than ES256".into())),
            None => return Err(invalid("passkey record has no alg")),
        }
        let created_at = obj.get(K_CREATED_AT).and_then(Value::as_i64).unwrap_or(0);
        let fido2_extensions = match obj.get(K_FIDO2) {
            None | Some(Value::Null) => None,
            Some(Value::Object(m)) => Some(m.clone()),
            Some(_) => return Err(invalid("fido2Extensions is not an object")),
        };
        let prf = fido2_extensions.as_ref().and_then(|m| m.get(K_HMAC)).and_then(PrfSecrets::from_json);

        for k in KNOWN {
            obj.remove(k);
        }
        let record = Self {
            credential_id,
            rp_id,
            user_name,
            user_display_name,
            user_handle,
            key,
            created_at,
            prf,
            fido2_extensions,
            extra: obj,
        };
        record.validate()?;
        Ok(record)
    }

    /// Serialise for storage in a `PKEY` field.
    pub fn to_field_value(&self) -> Result<Zeroizing<String>> {
        let mut obj = self.extra.clone();
        obj.insert(K_VERSION.into(), RECORD_VERSION.into());
        obj.insert(K_CREDENTIAL_ID.into(), b64::encode(&self.credential_id).into());
        obj.insert(K_RP_ID.into(), self.rp_id.clone().into());
        obj.insert(K_USER_NAME.into(), self.user_name.clone().into());
        obj.insert(K_USER_DISPLAY_NAME.into(), self.user_display_name.clone().into());
        obj.insert(K_USER_HANDLE.into(), b64::encode(&self.user_handle).into());
        obj.insert(K_KEY.into(), b64::encode(&self.key).into());
        obj.insert(K_ALG.into(), ALG_ES256.into());
        obj.insert(K_CREATED_AT.into(), self.created_at.into());
        if let Some(ext) = &self.fido2_extensions {
            obj.insert(K_FIDO2.into(), Value::Object(ext.clone()));
        }
        serde_json::to_string(&Value::Object(obj))
            .map(Zeroizing::new)
            .map_err(|e| WalletError::EncryptionError(format!("passkey record encode failed: {e}")))
    }

    /// What may be shown about this passkey.
    pub fn summary(&self, item_id: &str, field_id: &str) -> PasskeySummary {
        PasskeySummary {
            item_id: item_id.to_string(),
            field_id: field_id.to_string(),
            credential_id: self.credential_id.clone(),
            rp_id: self.rp_id.clone(),
            user_name: self.user_name.clone(),
            user_display_name: self.user_display_name.clone(),
            user_handle: self.user_handle.clone(),
            created_at: self.created_at,
            has_prf: self.prf.is_some(),
        }
    }

    /// The P-256 signing key.
    pub(crate) fn signing_key(&self) -> Result<p256::ecdsa::SigningKey> {
        use p256::pkcs8::DecodePrivateKey;
        p256::ecdsa::SigningKey::from_pkcs8_der(&self.key)
            .map_err(|_| invalid("passkey key is not a valid P-256 PKCS#8 private key"))
    }

    /// PRF secrets, when the passkey has usable ones.
    pub fn prf(&self) -> Option<&PrfSecrets> {
        self.prf.as_ref()
    }

    /// `fido2Extensions` as stored, for export.
    pub(crate) fn fido2_extensions(&self) -> Option<&Map<String, Value>> {
        self.fido2_extensions.as_ref()
    }

    /// PKCS#8 DER of the private key, for export only.
    pub(crate) fn pkcs8(&self) -> &[u8] {
        &self.key
    }

    fn validate(&self) -> Result<()> {
        let n = self.credential_id.len();
        if !(CREDENTIAL_ID_MIN..=CREDENTIAL_ID_MAX).contains(&n) {
            return Err(invalid("credentialId must be 16 to 1023 bytes"));
        }
        if self.user_handle.is_empty() || self.user_handle.len() > USER_HANDLE_MAX {
            return Err(invalid("userHandle must be 1 to 64 bytes"));
        }
        if self.user_name.len() > USER_NAME_MAX || self.user_display_name.len() > USER_NAME_MAX {
            return Err(invalid("userName or userDisplayName is too long"));
        }
        validate_rp_id(&self.rp_id)?;
        self.signing_key().map(|_| ())
    }
}

/// An rpId must be a domain name: lower-case ASCII letters, digits and
/// hyphens (punycode for international names), labels of 1 to 63 characters,
/// at most 253 characters in all, and not an IP address. `localhost` is
/// allowed, as browsers allow it for development.
pub(crate) fn validate_rp_id(rp_id: &str) -> Result<()> {
    let bad = || invalid("rpId is not a valid domain name");
    if rp_id.is_empty() || rp_id.len() > 253 || rp_id.starts_with('.') || rp_id.ends_with('.') {
        return Err(bad());
    }
    let labels: Vec<&str> = rp_id.split('.').collect();
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(bad());
        }
    }
    // A top-level label made of digits only means an IPv4 address, not a name.
    if labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return Err(bad());
    }
    Ok(())
}

fn invalid(msg: &str) -> WalletError {
    WalletError::InvalidInput(msg.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fixed, valid P-256 key in PKCS#8 DER (scalar 1…32), for tests only.
    pub(crate) fn test_key() -> Zeroizing<Vec<u8>> {
        use p256::pkcs8::EncodePrivateKey;
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        let secret = p256::SecretKey::from_slice(&bytes).unwrap();
        Zeroizing::new(secret.to_pkcs8_der().unwrap().as_bytes().to_vec())
    }

    pub(crate) fn sample(prf: bool) -> PasskeyRecord {
        let prf = prf.then(|| PrfSecrets {
            with_uv: Zeroizing::new([7u8; 32]),
            without_uv: Zeroizing::new([9u8; 32]),
        });
        PasskeyRecord::new(
            vec![0xAB; 16],
            "GitHub.com",
            "bkv",
            "B K V",
            b"user-1".to_vec(),
            test_key(),
            1_793_433_600,
            prf,
        )
        .unwrap()
    }

    fn json_of(r: &PasskeyRecord) -> Map<String, Value> {
        match serde_json::from_str(&r.to_field_value().unwrap()).unwrap() {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    }

    fn with(mut m: Map<String, Value>, k: &str, v: Value) -> String {
        m.insert(k.into(), v);
        Value::Object(m).to_string()
    }

    #[test]
    fn round_trip_keeps_every_value() {
        for prf in [false, true] {
            let r = sample(prf);
            let back = PasskeyRecord::from_field_value(&r.to_field_value().unwrap()).unwrap();
            assert_eq!(back.credential_id, r.credential_id);
            assert_eq!(back.rp_id, "github.com", "rpId is stored lower case");
            assert_eq!(back.user_name, "bkv");
            assert_eq!(back.user_display_name, "B K V");
            assert_eq!(back.user_handle, b"user-1");
            assert_eq!(back.pkcs8(), r.pkcs8());
            assert_eq!(back.created_at, 1_793_433_600);
            assert_eq!(back.prf().is_some(), prf);
            if prf {
                assert_eq!(back.prf(), r.prf());
            }
        }
    }

    #[test]
    fn written_json_has_the_documented_shape() {
        let m = json_of(&sample(true));
        assert_eq!(m["v"], 1);
        assert_eq!(m["alg"], -7);
        assert_eq!(m["rpId"], "github.com");
        assert_eq!(m["credentialId"], b64::encode(&[0xAB; 16]));
        assert_eq!(m["fido2Extensions"]["hmacCredentials"]["algorithm"], "hmac-sha256");
        assert!(!m["key"].as_str().unwrap().contains('='));
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        let mut m = json_of(&sample(true));
        m.insert("futureField".into(), serde_json::json!({"a": [1, 2]}));
        m.get_mut("fido2Extensions").unwrap().as_object_mut().unwrap()
            .insert("credBlob".into(), "AQID".into());
        let text = Value::Object(m).to_string();
        let back = PasskeyRecord::from_field_value(&text).unwrap();
        let again = json_of(&back);
        assert_eq!(again["futureField"], serde_json::json!({"a": [1, 2]}));
        assert_eq!(again["fido2Extensions"]["credBlob"], "AQID");
        assert!(back.prf().is_some());
    }

    #[test]
    fn unusable_prf_secrets_mean_no_prf_but_are_kept() {
        let base = json_of(&sample(false));
        for hmac in [
            serde_json::json!({"algorithm": "hmac-sha512", "credWithUV": b64::encode(&[1; 32]), "credWithoutUV": b64::encode(&[2; 32])}),
            serde_json::json!({"algorithm": "hmac-sha256", "credWithUV": b64::encode(&[1; 31]), "credWithoutUV": b64::encode(&[2; 32])}),
            serde_json::json!({"algorithm": "hmac-sha256", "credWithUV": "!!", "credWithoutUV": b64::encode(&[2; 32])}),
            serde_json::json!({"algorithm": "hmac-sha256"}),
            serde_json::json!("not an object"),
        ] {
            let text = with(base.clone(), "fido2Extensions", serde_json::json!({ "hmacCredentials": hmac.clone() }));
            let r = PasskeyRecord::from_field_value(&text).unwrap();
            assert!(r.prf().is_none());
            assert_eq!(json_of(&r)["fido2Extensions"]["hmacCredentials"], hmac, "kept verbatim");
        }
    }

    #[test]
    fn every_malformed_record_is_refused_without_panicking() {
        let base = json_of(&sample(false));
        let bad: Vec<String> = vec![
            "".into(),
            "[]".into(),
            "not json".into(),
            "x".repeat(RECORD_MAX + 1),
            with(base.clone(), "v", 2.into()),
            with(base.clone(), "v", "1".into()),
            with(base.clone(), "alg", (-8).into()),
            with(base.clone(), "credentialId", b64::encode(&[1; 15]).into()),
            with(base.clone(), "credentialId", b64::encode(&[1; 1024]).into()),
            with(base.clone(), "credentialId", "!!".into()),
            with(base.clone(), "userHandle", "".into()),
            with(base.clone(), "userHandle", b64::encode(&[1; 65]).into()),
            with(base.clone(), "userName", "n".repeat(USER_NAME_MAX + 1).into()),
            with(base.clone(), "rpId", "".into()),
            with(base.clone(), "rpId", 5.into()),
            with(base.clone(), "key", b64::encode(&[0; 40]).into()),
            with(base.clone(), "key", b64::encode(&[0xFF; 32]).into()),
            with(base.clone(), "fido2Extensions", "x".into()),
        ];
        for text in bad {
            assert!(PasskeyRecord::from_field_value(&text).is_err());
        }
        for missing in ["v", "credentialId", "rpId", "userName", "userDisplayName", "userHandle", "key", "alg"] {
            let mut m = base.clone();
            m.remove(missing);
            assert!(PasskeyRecord::from_field_value(&Value::Object(m).to_string()).is_err(), "{missing}");
        }
    }

    #[test]
    fn errors_never_contain_the_key() {
        let mut m = json_of(&sample(false));
        let key = m["key"].as_str().unwrap().to_string();
        m.insert("rpId".into(), "BAD DOMAIN".into());
        let err = PasskeyRecord::from_field_value(&Value::Object(m).to_string()).unwrap_err();
        assert!(!err.to_string().contains(&key));
    }

    #[test]
    fn debug_hides_key_and_prf() {
        let r = sample(true);
        let key = b64::encode(r.pkcs8());
        for text in [format!("{r:?}"), format!("{r:#?}"), format!("{:?}", r.prf())] {
            assert!(!text.contains(&key));
            assert!(!text.contains(&b64::encode(&[7u8; 32])));
            assert!(text.contains(REDACTED));
        }
    }

    #[test]
    fn summary_carries_no_secret() {
        let r = sample(true);
        let s = r.summary("item1", "fld1");
        assert_eq!((s.item_id.as_str(), s.field_id.as_str()), ("item1", "fld1"));
        assert!(s.has_prf);
        assert!(!format!("{s:?}").contains(&b64::encode(r.pkcs8())));
    }

    #[test]
    fn generated_prf_secrets_are_distinct() {
        let p = PrfSecrets::generate().unwrap();
        assert_ne!(*p.with_uv, *p.without_uv);
        assert_ne!(*p.with_uv, [0u8; 32]);
    }

    #[test]
    fn rp_id_rules() {
        for ok in ["github.com", "login.example.co.uk", "xn--bcher-kva.example", "localhost", "a-b.c1"] {
            assert!(validate_rp_id(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", ".com", "com.", "a..b", "Github.com", "-a.com", "a-.com", "a_b.com",
            "192.168.0.1", "1.2.3.4", "[::1]", "exa mple.com", "bücher.de", "https://a.com",
            "a.com:443", &"a".repeat(64), &format!("{}.com", "a.".repeat(130)),
        ] {
            assert!(validate_rp_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rp_id_length_limit_is_253() {
        let name = |last: usize| format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(last));
        assert_eq!(name(61).len(), 253);
        assert!(validate_rp_id(&name(61)).is_ok());
        assert!(validate_rp_id(&name(62)).is_err());
    }

    #[test]
    fn record_size_limit_is_64_kib() {
        assert_eq!(RECORD_MAX, 65_536);
        let base = json_of(&sample(false));
        let pad = |n: usize| with(base.clone(), "pad", "p".repeat(n).into());
        let fill = RECORD_MAX - pad(0).len();
        assert_eq!(pad(fill).len(), RECORD_MAX);
        assert!(PasskeyRecord::from_field_value(&pad(fill)).is_ok());
        assert!(PasskeyRecord::from_field_value(&pad(fill + 1)).is_err());
    }

    #[test]
    fn user_field_lengths_are_accepted_up_to_the_limit() {
        let base = json_of(&sample(false));
        let parse = |k: &str, v: Value| PasskeyRecord::from_field_value(&with(base.clone(), k, v));
        assert!(parse("userHandle", b64::encode(&[1; USER_HANDLE_MAX]).into()).is_ok());
        assert!(parse("userHandle", b64::encode(&[1; USER_HANDLE_MAX + 1]).into()).is_err());
        for k in ["userName", "userDisplayName"] {
            assert!(parse(k, "n".repeat(USER_NAME_MAX).into()).is_ok(), "{k}");
            assert!(parse(k, "n".repeat(USER_NAME_MAX + 1).into()).is_err(), "{k}");
        }
    }
}
