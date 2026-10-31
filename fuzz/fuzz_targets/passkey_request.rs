//! WebAuthn options JSON comes from the calling app on Android: untrusted.
#![no_main]
use iwcore::passkey::json::{CreationOptions, RequestOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(json) = std::str::from_utf8(data) else { return };
    let _ = CreationOptions::parse(json);
    if let Ok(r) = RequestOptions::parse(json) {
        for id in &r.allow_credentials {
            let _ = r.prf_inputs_for(id);
        }
    }
});
