//! assetlinks.json comes from the network: untrusted. Also fuzzes the origin
//! check with the same bytes split into an rpId and an origin.
#![no_main]
use iwcore::passkey::origin;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = origin::assetlinks_allows(data, "com.example.app", &[0xAB; 32]);
    if let Ok(text) = std::str::from_utf8(data) {
        let (rp, o) = text.split_once('\n').unwrap_or((text, "https://example.com"));
        let _ = origin::rp_id_valid_for_origin(rp, o);
    }
});
