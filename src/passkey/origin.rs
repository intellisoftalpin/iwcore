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
//! The same checks decide password AutoFill on Android:
//!
//! - a **native app** may be offered the logins saved for a site only if the
//!   site's `assetlinks.json` (fetched from the registrable domain of the saved
//!   URL, [`login_assetlinks_url`]) grants that app `get_login_creds`
//!   ([`app_allowed_for_domain`]);
//! - a **privileged browser**'s `webDomain` must belong to the same site as
//!   the saved URL ([`web_domain_matches_url`]).
//!
//! Public suffixes come from the full Public Suffix List (`psl` crate), not the
//! curated subset AutoFill ranking uses: accepting a public suffix such as
//! `github.io` as an rpId would make one passkey usable by every site under it.

use serde_json::Value;

use crate::autofill::domain::normalize_host;

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

/// Prefix of the WebAuthn origin of a native Android app.
pub const ANDROID_ORIGIN_PREFIX: &str = "android:apk-key-hash:";

/// The WebAuthn origin of a native Android app:
/// `android:apk-key-hash:<base64url of the SHA-256 of its signing certificate>`.
pub fn android_origin(cert_sha256: &[u8; 32]) -> String {
    format!("{ANDROID_ORIGIN_PREFIX}{}", b64::encode(cert_sha256))
}

/// True for a native Android app's origin (`android:apk-key-hash:…`, any
/// case of the scheme), as opposed to a browser's web origin.
pub fn is_android_origin(origin: &str) -> bool {
    origin
        .get(..ANDROID_ORIGIN_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(ANDROID_ORIGIN_PREFIX))
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

/// The registrable domain (eTLD+1, full Public Suffix List) of a saved login
/// URL, a bare host or a browser's `webDomain`: `https://login.example.co.uk/x`
/// gives `example.co.uk`. `None` for IP addresses, single-label hosts, public
/// suffixes and anything that is not a host.
pub fn registrable_domain(url_or_host: &str) -> Option<String> {
    let host = normalize_host(url_or_host)?;
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let domain = psl::domain_str(&host)?;
    validate_rp_id(domain).ok()?;
    Some(domain.to_string())
}

/// Where to fetch the `assetlinks.json` that decides which apps may fill the
/// logins saved for `saved_url`: `https://<registrable domain>/.well-known/assetlinks.json`.
pub fn login_assetlinks_url(saved_url: &str) -> Option<String> {
    registrable_domain(saved_url).map(|d| format!("https://{d}/.well-known/assetlinks.json"))
}

/// May the native app `package`, signed by `cert_sha256`, be offered the
/// passwords saved for `domain`?
///
/// `domain` is the registrable domain of the saved login URL
/// ([`registrable_domain`]) and `assetlinks_json` the file the app fetched from
/// [`login_assetlinks_url`]. True only when that file grants exactly this
/// package and certificate `delegate_permission/common.get_login_creds`, the
/// same rule as for passkeys ([`assetlinks_allows`]). A `domain` that is not a
/// registrable domain (a subdomain, a URL, a public suffix, an IP address) is
/// an error, so a file from the wrong host is never consulted; so is a
/// malformed or oversized file.
pub fn app_allowed_for_domain(
    assetlinks_json: &[u8],
    package: &str,
    cert_sha256: &[u8; 32],
    domain: &str,
) -> Result<bool> {
    if registrable_domain(domain).as_deref() != Some(domain) {
        return Err(refused("domain is not a registrable domain"));
    }
    assetlinks_allows(assetlinks_json, package, cert_sha256)
}

/// Does a `webDomain` reported by a privileged browser belong to the site a
/// login was saved for?
///
/// True when both have the same registrable domain under the full Public
/// Suffix List: `login.example.co.uk` matches a login saved for
/// `https://example.co.uk/signin`, while `evil.co.uk` or `other.github.io`
/// match nothing of `example.co.uk` / `bkv.github.io`. Hosts without a
/// registrable domain (IP addresses, `localhost`, intranet names) must be
/// equal. Port, path and scheme are ignored.
pub fn web_domain_matches_url(web_domain: &str, saved_url: &str) -> bool {
    match (registrable_domain(web_domain), registrable_domain(saved_url)) {
        (Some(a), Some(b)) => a == b,
        (None, None) => match (normalize_host(web_domain), normalize_host(saved_url)) {
            (Some(web), Some(saved)) => web == saved,
            _ => false,
        },
        _ => false,
    }
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
    fn a_backslash_link_names_the_site_a_browser_opens() {
        let link = "https://bank.com\\@evil.com/login";
        assert_eq!(login_assetlinks_url(link).as_deref(), Some("https://bank.com/.well-known/assetlinks.json"));
        assert!(web_domain_matches_url("bank.com", link));
        assert!(!web_domain_matches_url("evil.com", link));
    }

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
    fn android_origins_are_recognised() {
        assert!(is_android_origin(&android_origin(&[1; 32])));
        assert!(is_android_origin("ANDROID:APK-KEY-HASH:abc"));
        assert!(is_android_origin(ANDROID_ORIGIN_PREFIX));
        for o in ["https://example.com", "android:apk-key-has", "", "android:", "xandroid:apk-key-hash:a", "жжжжжжжжжжжж"] {
            assert!(!is_android_origin(o), "{o}");
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
    fn registrable_domains_use_the_full_list() {
        let cases = [
            ("https://login.example.co.uk/signin?x=1", Some("example.co.uk")),
            ("example.com", Some("example.com")),
            ("WWW.Example.COM:8443", Some("example.com")),
            ("https://user@a.b.example.com/", Some("example.com")),
            ("bkv.github.io", Some("bkv.github.io")),
            ("x.y.vercel.app", Some("y.vercel.app")),
            ("https://пример.рф/", Some("xn--e1afmkfd.xn--p1ai")),
            ("github.io", None),
            ("co.uk", None),
            ("com", None),
            ("localhost", None),
            ("192.168.1.1", None),
            ("http://[::1]:8080/", None),
            ("javascript:alert(1)", None),
            ("", None),
            ("a_b.example.com", Some("example.com")),
            ("x.under_score", None),
        ];
        for (input, want) in cases {
            assert_eq!(registrable_domain(input).as_deref(), want, "{input}");
        }
        assert_eq!(
            login_assetlinks_url("https://accounts.example.co.uk/login").as_deref(),
            Some("https://example.co.uk/.well-known/assetlinks.json")
        );
        assert_eq!(login_assetlinks_url("https://github.io/"), None);
    }

    #[test]
    fn password_autofill_needs_get_login_creds_for_the_registrable_domain() {
        let rel = RELATION_GET_LOGIN_CREDS;
        let file = serde_json::to_vec(&vec![statement(rel, "android_app", "com.example.app", &fp(true))]).unwrap();
        let ok = |domain: &str| app_allowed_for_domain(&file, "com.example.app", &cert(), domain);
        assert!(ok("example.com").unwrap());
        assert!(!app_allowed_for_domain(&file, "com.example.other", &cert(), "example.com").unwrap());
        let mut other_cert = cert();
        other_cert[0] ^= 1;
        assert!(!app_allowed_for_domain(&file, "com.example.app", &other_cert, "example.com").unwrap());
        // handle_all_urls (app links) is not credential sharing.
        let links = serde_json::to_vec(&vec![statement(
            "delegate_permission/common.handle_all_urls", "android_app", "com.example.app", &fp(true),
        )]).unwrap();
        assert!(!app_allowed_for_domain(&links, "com.example.app", &cert(), "example.com").unwrap());
        // Only a registrable domain names the file to consult.
        for bad in ["login.example.com", "https://example.com", "co.uk", "github.io", "Example.com", "1.2.3.4", ""] {
            assert!(ok(bad).is_err(), "{bad}");
        }
        assert!(app_allowed_for_domain(b"not json", "com.example.app", &cert(), "example.com").is_err());
    }

    #[test]
    fn browser_web_domain_against_saved_url() {
        let matches = [
            ("example.com", "https://example.com/login"),
            ("login.example.com", "https://example.com"),
            ("example.com", "https://accounts.example.com/signin"),
            ("www.example.co.uk", "example.co.uk"),
            ("bkv.github.io", "https://bkv.github.io/app"),
            ("192.168.1.1", "http://192.168.1.1:8080/admin"),
            ("localhost", "http://localhost:3000"),
            ("EXAMPLE.com", "https://example.COM"),
        ];
        for (web, saved) in matches {
            assert!(web_domain_matches_url(web, saved), "{web} vs {saved}");
        }
        let different = [
            ("evil.co.uk", "https://example.co.uk"),
            ("other.github.io", "https://bkv.github.io"),
            ("example.com.evil.net", "https://example.com"),
            ("notexample.com", "https://example.com"),
            ("192.168.1.2", "http://192.168.1.1"),
            ("example.com", "http://192.168.1.1"),
            ("localhost", "https://example.com"),
            ("", "https://example.com"),
            ("example.com", ""),
            ("example.com", "javascript:alert(1)"),
            ("", ""),
            ("localhost", ""),
        ];
        for (web, saved) in different {
            assert!(!web_domain_matches_url(web, saved), "{web} vs {saved}");
        }
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
