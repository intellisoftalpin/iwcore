//! A CXF payload from another app is untrusted: previewing any bytes must
//! return Ok or Err, never panic, hang or exhaust memory.
#![no_main]
use std::sync::{Mutex, OnceLock};

use iwcore::Wallet;
use libfuzzer_sys::fuzz_target;

static WALLET: OnceLock<(tempfile::TempDir, Mutex<Wallet>)> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let Ok(json) = std::str::from_utf8(data) else { return };
    let (_, wallet) = WALLET.get_or_init(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let mut w = Wallet::create(dir.path(), "fuzz-password", "en").unwrap();
        if !w.is_unlocked() {
            w.unlock("fuzz-password").unwrap();
        }
        (dir, Mutex::new(w))
    });
    let _ = wallet.lock().unwrap().preview_cxf(json);
});
