//! Who may use which passkey.
//!
//! On iOS the operating system binds every request to the real site or app. On
//! Android the provider shares that job, and the checks live here so they are
//! tested once, in Rust:
//!
//! - a **browser** on the privileged list supplies the page origin; the rpId
//!   must be that origin's host or a parent domain of it, and never a public
//!   suffix ([`rp_id_valid_for_origin`]);
//! - a **native app** gets the origin `android:apk-key-hash:<sha256 of its
//!   signing certificate>` ([`android_origin`]), and may use a site's passkeys
//!   only if the site's `/.well-known/assetlinks.json` grants that app
//!   `get_login_creds` ([`assetlinks_allows`]). Fetching the file is the app's
//!   job; parsing and deciding is done here.
//!
//! Public suffixes come from the full Public Suffix List (`psl` crate), not the
//! curated subset AutoFill ranking uses: accepting a public suffix such as
//! `github.io` as an rpId would make one passkey usable by every site under it.

use serde_json::Value;

use super::b64;
use super::record::validate_rp_id;
use crate::error::{Result, WalletError};

/// Largest `assetlinks.json` accepted, in bytes.
pub const ASSETLINKS_MAX_BYTES: usize = 256 * 1024;
/// Most statements read from one `assetlinks.json`.
pub const ASSETLINKS_MAX_STATEMENTS: usize = 100;
/// The relation that lets an app use a site's credentials.
pub const RELATION_GET_LOGIN_CREDS: &str = "delegate_permission/common.get_login_creds";

/// True when `domain` is itself a public suffix (`com`, `co.uk`, `github.io`).
pub fn is_public_suffix(domain: &str) -> bool {
    psl::suffix_str(domain).is_some_and(|s| s.eq_ignore_ascii_case(domain))
}

/// Check that a page at `origin` may use passkeys for `rp_id`.
///
/// `origin` is the browser-reported origin: `https://host[:port]`, or
/// `http://localhost[:port]` for development. The rpId must be the host or a
/// parent domain of it, must be a valid domain name, and must not be a public
/// suffix.
pub fn rp_id_valid_for_origin(rp_id: &str, origin: &str) -> Result<()> {
    let rp_id = rp_id.to_ascii_lowercase();
    validate_rp_id(&rp_id)?;
    let host = origin_host(origin)?;

    if rp_id != "localhost" && (is_public_suffix(&rp_id) || psl::domain_str(&rp_id).is_none()) {
        return Err(refused("rpId is a public suffix"));
    }
    let matches = host == rp_id || host.ends_with(&format!(".{rp_id}"));
    if !matches {
        return Err(refused("rpId is not the origin's host or a parent domain of it"));
    }
    Ok(())
}

/// The host of a browser origin, lower case. Refuses anything that is not a
/// bare `https` origin (or `http` on localhost), including paths, user info and
/// IP addresses.
fn origin_host(origin: &str) -> Result<String> {
    let (scheme, rest) = origin
        .split_once("://")
        .ok_or_else(|| refused("origin is not a URL origin"))?;
    let scheme = scheme.to_ascii_lowercase();
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', '\\']) {
        return Err(refused("origin must be scheme and host only"));
    }
    let host = match rest.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        Some(_) => return Err(refused("origin port is not a number")),
        None => rest,
    }
    .to_ascii_lowercase();
    validate_rp_id(&host).map_err(|_| refused("origin host is not a domain name"))?;
    match scheme.as_str() {
        "https" => Ok(host),
        "http" if host == "localhost" => Ok(host),
        _ => Err(refused("origin must be https")),
    }
}

/// The WebAuthn origin of a native Android app:
/// `android:apk-key-hash:<base64url of the SHA-256 of its signing certificate>`.
pub fn android_origin(cert_sha256: &[u8; 32]) -> String {
    format!("android:apk-key-hash:{}", b64::encode(cert_sha256))
}

/// Does this `assetlinks.json` let `package`, signed by `cert_sha256`, use the
/// site's credentials?
///
/// True only for a statement with the relation `get_login_creds`
/// (`handle_all_urls` alone is app-link handling, not credential sharing),
/// namespace `android_app`, exactly this package, and a matching SHA-256
/// fingerprint (colon-separated hex, any case). A file over the size or
/// statement limit, or not a JSON array, is an error.
pub fn assetlinks_allows(json: &[u8], package: &str, cert_sha256: &[u8; 32]) -> Result<bool> {
    if json.len() > ASSETLINKS_MAX_BYTES {
        return Err(WalletError::InvalidInput("assetlinks.json is larger than 256 KiB".into()));
    }
    let statements: Vec<Value> = match serde_json::from_slice(json) {
        Ok(Value::Array(a)) => a,
        _ => return Err(WalletError::InvalidInput("assetlinks.json is not a JSON array".into())),
    };
    if statements.len() > ASSETLINKS_MAX_STATEMENTS {
        return Err(WalletError::InvalidInput("assetlinks.json has too many statements".into()));
    }
    Ok(statements.iter().any(|s| statement_allows(s, package, cert_sha256)))
}

fn statement_allows(statement: &Value, package: &str, cert_sha256: &[u8; 32]) -> bool {
    let relation_ok = statement
        .get("relation")
        .and_then(Value::as_array)
        .is_some_and(|r| r.iter().any(|v| v.as_str() == Some(RELATION_GET_LOGIN_CREDS)));
    let Some(target) = statement.get("target") else { return false };
    let namespace_ok = target.get("namespace").and_then(Value::as_str) == Some("android_app");
    let package_ok = target.get("package_name").and_then(Value::as_str) == Some(package);
    let cert_ok = target
        .get("sha256_cert_fingerprints")
        .and_then(Value::as_array)
        .is_some_and(|fps| fps.iter().filter_map(Value::as_str).any(|fp| fingerprint_matches(fp, cert_sha256)));
    relation_ok && namespace_ok && package_ok && cert_ok
}

/// `AB:CD:…` (32 colon-separated hex pairs, any case) equals `cert`.
fn fingerprint_matches(text: &str, cert: &[u8; 32]) -> bool {
    let parts: Vec<&str> = text.split(':').collect();
    parts.len() == 32
        && parts
            .iter()
            .zip(cert)
            .all(|(p, b)| p.len() == 2 && u8::from_str_radix(p, 16).ok() == Some(*b))
}

fn refused(msg: &str) -> WalletError {
    WalletError::InvalidInput(msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_against_origin_table() {
        let ok = [
            ("example.com", "https://example.com"),
            ("example.com", "https://login.example.com"),
            ("example.com", "https://a.b.example.com:8443"),
            ("login.example.com", "https://login.example.com"),
            ("example.co.uk", "https://www.example.co.uk"),
            ("bkv.github.io", "https://bkv.github.io"),
            ("Example.COM", "HTTPS://WWW.EXAMPLE.COM"),
            ("localhost", "http://localhost:3000"),
            ("localhost", "https://localhost"),
            ("xn--bcher-kva.example", "https://xn--bcher-kva.example"),
        ];
        for (rp, origin) in ok {
            assert!(rp_id_valid_for_origin(rp, origin).is_ok(), "{rp} @ {origin}");
        }
        let bad = [
            ("login.example.com", "https://example.com"),  // child rpId of the origin
            ("example.com", "https://example.com.evil.net"),
            ("example.com", "https://notexample.com"),
            ("evil.com", "https://example.com"),
            ("com", "https://example.com"),                 // TLD
            ("co.uk", "https://example.co.uk"),             // multi-label suffix
            ("github.io", "https://bkv.github.io"),         // private suffix
            ("blogspot.com", "https://x.blogspot.com"),
            ("s3.amazonaws.com", "https://bucket.s3.amazonaws.com"),
            ("example.com", "http://example.com"),          // not https
            ("example.com", "ftp://example.com"),
            ("example.com", "https://example.com/path"),
            ("example.com", "https://user@example.com"),
            ("example.com", "https://example.com:port"),
            ("example.com", "example.com"),
            ("example.com", "https://"),
            ("1.2.3.4", "https://1.2.3.4"),
            ("example.com", "https://1.2.3.4"),
            ("example.com", "https://[::1]"),
            ("example.com", "android:apk-key-hash:abc"),
            ("", "https://example.com"),
            ("exa mple.com", "https://example.com"),
        ];
        for (rp, origin) in bad {
            assert!(rp_id_valid_for_origin(rp, origin).is_err(), "{rp} @ {origin}");
        }
    }

    #[test]
    fn origin_shape_is_checked_before_the_host() {
        let reason = |o: &str| match origin_host(o) {
            Err(WalletError::InvalidInput(m)) => m,
            other => panic!("{o}: {other:?}"),
        };
        for o in ["https://", "https://example.com/", "https://example.com?q", "https://example.com#f",
                  "https://u@example.com", "https://example.com\\x"] {
            assert_eq!(reason(o), "origin must be scheme and host only", "{o}");
        }
        assert_eq!(reason("https://exa mple.com"), "origin host is not a domain name");
    }

    #[test]
    fn public_suffixes_come_from_the_full_list() {
        for s in ["com", "co.uk", "github.io", "blogspot.com", "s3.amazonaws.com", "pages.dev", "vercel.app"] {
            assert!(is_public_suffix(s), "{s}");
        }
        for d in ["example.com", "bbc.co.uk", "bkv.github.io"] {
            assert!(!is_public_suffix(d), "{d}");
        }
    }

    #[test]
    fn android_origin_is_base64url_of_the_hash() {
        let cert: [u8; 32] = core::array::from_fn(|i| (i * 8) as u8);
        let o = android_origin(&cert);
        assert!(o.starts_with("android:apk-key-hash:"));
        assert_eq!(b64::decode(o.trim_start_matches("android:apk-key-hash:"), "x").unwrap(), cert);
        assert!(!o.contains('='));
    }

    fn cert() -> [u8; 32] {
        core::array::from_fn(|i| 0xA0 + i as u8)
    }

    fn fp(upper: bool) -> String {
        let s: Vec<String> = cert().iter().map(|b| format!("{b:02X}")).collect();
        let s = s.join(":");
        if upper { s } else { s.to_lowercase() }
    }

    fn statement(relation: &str, namespace: &str, package: &str, fingerprint: &str) -> Value {
        serde_json::json!({
            "relation": [relation],
            "target": {"namespace": namespace, "package_name": package, "sha256_cert_fingerprints": [fingerprint]}
        })
    }

    fn allows(statements: Vec<Value>) -> bool {
        assetlinks_allows(&serde_json::to_vec(&statements).unwrap(), "com.example.app", &cert()).unwrap()
    }

    #[test]
    fn assetlinks_grant_rules() {
        let rel = RELATION_GET_LOGIN_CREDS;
        assert!(allows(vec![statement(rel, "android_app", "com.example.app", &fp(true))]));
        assert!(allows(vec![statement(rel, "android_app", "com.example.app", &fp(false))]), "lower case");
        // Several statements, the matching one last.
        assert!(allows(vec![
            statement("delegate_permission/common.handle_all_urls", "android_app", "com.example.app", &fp(true)),
            statement(rel, "web", "com.example.app", &fp(true)),
            statement(rel, "android_app", "com.example.app", &fp(true)),
        ]));
        // Each condition on its own is not enough.
        assert!(!allows(vec![statement("delegate_permission/common.handle_all_urls", "android_app", "com.example.app", &fp(true))]));
        assert!(!allows(vec![statement(rel, "web", "com.example.app", &fp(true))]));
        assert!(!allows(vec![statement(rel, "android_app", "com.example.other", &fp(true))]));
        assert!(!allows(vec![statement(rel, "android_app", "com.example.app", "00:11")]));
        let mut wrong = cert();
        wrong[31] ^= 1;
        let s: Vec<String> = wrong.iter().map(|b| format!("{b:02X}")).collect();
        assert!(!allows(vec![statement(rel, "android_app", "com.example.app", &s.join(":"))]));
        assert!(!allows(vec![serde_json::json!({"relation": [rel]})]), "no target");
        assert!(!allows(vec![]));
    }

    #[test]
    fn assetlinks_limits_and_malformed_input() {
        let c = cert();
        for bad in [&b"{}"[..], b"not json", b"\"str\"", b""] {
            assert!(assetlinks_allows(bad, "p", &c).is_err());
        }
        assert_eq!(ASSETLINKS_MAX_BYTES, 262_144, "256 KiB");
        let big = vec![b' '; ASSETLINKS_MAX_BYTES + 1];
        assert!(assetlinks_allows(&big, "p", &c).is_err());
        let mut edge = vec![b' '; ASSETLINKS_MAX_BYTES];
        edge[0] = b'[';
        edge[ASSETLINKS_MAX_BYTES - 1] = b']';
        assert!(!assetlinks_allows(&edge, "p", &c).unwrap(), "exactly the limit is read");
        let many: Vec<Value> = (0..=ASSETLINKS_MAX_STATEMENTS).map(|_| serde_json::json!({})).collect();
        assert!(assetlinks_allows(&serde_json::to_vec(&many).unwrap(), "p", &c).is_err());
        let edge: Vec<Value> = (0..ASSETLINKS_MAX_STATEMENTS).map(|_| serde_json::json!({})).collect();
        assert!(!assetlinks_allows(&serde_json::to_vec(&edge).unwrap(), "p", &c).unwrap());
    }
}
