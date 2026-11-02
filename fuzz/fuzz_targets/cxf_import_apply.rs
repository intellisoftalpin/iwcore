//! A CXF payload from another app is untrusted: importing any bytes into a
//! vault must return Ok or Err, never panic, hang or exhaust memory, and an
//! import that fails leaves the vault as it was.
#![no_main]
use std::sync::{Mutex, OnceLock};

use iwcore::cxf::import::ImportOptions;
use iwcore::Wallet;
use libfuzzer_sys::fuzz_target;

/// Start again from an empty vault once imports have filled it this far, so
/// runs stay fast without paying for a new vault on every input.
const ITEMS_BEFORE_RESET: usize = 5_000;

struct Vault {
    _dir: tempfile::TempDir,
    backups: tempfile::TempDir,
    wallet: Wallet,
}

fn fresh() -> Vault {
    let dir = tempfile::TempDir::new().unwrap();
    let mut wallet = Wallet::create(dir.path(), "fuzz-password", "en").unwrap();
    if !wallet.is_unlocked() {
        wallet.unlock("fuzz-password").unwrap();
    }
    Vault { _dir: dir, backups: tempfile::TempDir::new().unwrap(), wallet }
}

static VAULT: OnceLock<Mutex<Vault>> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let Ok(json) = std::str::from_utf8(data) else { return };
    let mut guard = VAULT.get_or_init(|| Mutex::new(fresh())).lock().unwrap();
    if guard.wallet.get_items().unwrap().len() > ITEMS_BEFORE_RESET {
        *guard = fresh();
    }
    let v = &mut *guard;
    let before = v.wallet.get_items().unwrap().len();
    let options = ImportOptions { backup_folder: v.backups.path().to_path_buf() };
    match v.wallet.import_cxf(json, &options) {
        Ok(report) => {
            let _ = std::fs::remove_file(&report.backup_path);
            let items = v.wallet.get_items().unwrap();
            for id in report.folder_ids.iter().chain(&report.item_ids) {
                assert!(items.iter().any(|i| &i.item_id == id), "reported id {id} is missing");
            }
        }
        Err(_) => assert_eq!(v.wallet.get_items().unwrap().len(), before, "a failed import changed the vault"),
    }
});
