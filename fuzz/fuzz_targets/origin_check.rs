//! Origins, rpIds, saved login URLs and browser webDomains all come from
//! outside the core (the system, a request, the vault, a browser). The origin
//! checks must never panic, and must agree with each other.
#![no_main]
use iwcore::passkey::{json, origin};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let mut parts = text.splitn(3, '\n');
    let a = parts.next().unwrap_or("");
    let b = parts.next().unwrap_or("https://example.com");
    let c = parts.next().unwrap_or("");

    // Passkeys: rpId against an origin, in both orders.
    let ok = origin::rp_id_valid_for_origin(a, b).is_ok();
    let _ = origin::rp_id_valid_for_origin(b, a);
    if ok {
        // An accepted rpId is never a public suffix and never an app origin.
        assert!(!origin::is_public_suffix(&a.to_ascii_lowercase()) || a.eq_ignore_ascii_case("localhost"));
        assert!(!origin::is_android_origin(b));
    }

    // What gets signed: an app origin never takes a supplied hash.
    for o in [a, b] {
        let cd = json::client_data(json::Ceremony::Get, c.as_bytes(), o, Some("com.example"), Some(&[7; 32]));
        if origin::is_android_origin(o) {
            assert!(cd.is_err());
        }
    }

    // Password AutoFill: registrable domains and webDomain matching.
    let ra = origin::registrable_domain(a);
    let rb = origin::registrable_domain(b);
    if let Some(d) = &ra {
        assert!(!origin::is_public_suffix(d));
        assert!(origin::login_assetlinks_url(a).is_some());
        let _ = origin::app_allowed_for_domain(c.as_bytes(), "com.example", &[0xAB; 32], d);
    }
    let m = origin::web_domain_matches_url(a, b);
    assert_eq!(m, origin::web_domain_matches_url(b, a), "symmetric");
    if let (Some(x), Some(y)) = (&ra, &rb) {
        assert_eq!(m, x == y);
    }
    let _ = origin::app_allowed_for_domain(c.as_bytes(), "com.example", &[0xAB; 32], a);
});
