//! A stored PKEY value may come from an older app, a damaged vault or an
//! import: parsing it must never panic, and a parsed record must round-trip.
#![no_main]
use iwcore::passkey::PasskeyRecord;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(r) = PasskeyRecord::from_field_value(text) {
        let again = PasskeyRecord::from_field_value(&r.to_field_value().unwrap()).unwrap();
        assert_eq!(again.credential_id, r.credential_id);
        let _ = iwcore::passkey::sign::assert(&r, &r.rp_id, &[0; 32], true);
    }
    let _ = iwcore::passkey::vault::public_value(text);
});
