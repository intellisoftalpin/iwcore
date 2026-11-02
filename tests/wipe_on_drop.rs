//! Secrets are wiped before their memory goes back to the allocator.
//!
//! A scanning allocator looks at every block freed (or moved by a realloc)
//! while a check is armed and counts the ones that still hold the secret.
//! The checks share the allocator, so they run one after the other under a
//! lock.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::Mutex;

use iwcore::autofill::index::{build_with_passkeys, IndexHeader, PasskeyIndexEntry};
use iwcore::passkey::PasskeyRecord;
use serde_json::json;

struct Scanning;

static ARMED: AtomicBool = AtomicBool::new(false);
static NEEDLE_PTR: AtomicUsize = AtomicUsize::new(0);
static NEEDLE_LEN: AtomicUsize = AtomicUsize::new(0);
static HITS: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

/// Count a block that is about to be released if it still holds the needle.
///
/// # Safety
/// `ptr` must point to `len` readable bytes.
unsafe fn scan(ptr: *const u8, len: usize) {
    if !ARMED.load(SeqCst) {
        return;
    }
    let (n_ptr, n_len) = (NEEDLE_PTR.load(SeqCst), NEEDLE_LEN.load(SeqCst));
    if n_len == 0 || len < n_len {
        return;
    }
    // SAFETY: the caller guarantees the block; the needle is a leaked,
    // never-freed buffer set before arming.
    let (block, needle) =
        unsafe { (std::slice::from_raw_parts(ptr, len), std::slice::from_raw_parts(n_ptr as *const u8, n_len)) };
    if block.windows(n_len).any(|w| w == needle) {
        HITS.fetch_add(1, SeqCst);
    }
}

// SAFETY: every call is forwarded unchanged to the system allocator; blocks
// are only read, before they are released.
unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            scan(ptr, layout.size());
            System.dealloc(ptr, layout)
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A realloc may move the block and free the old one unwiped.
        unsafe {
            scan(ptr, layout.size());
            System.realloc(ptr, layout, new_size)
        }
    }
}

#[global_allocator]
static ALLOC: Scanning = Scanning;

/// How many blocks released during `f` still held `needle`.
fn leaks_during(needle: &str, f: impl FnOnce()) -> usize {
    let leaked: &'static [u8] = Box::leak(needle.as_bytes().to_vec().into_boxed_slice());
    NEEDLE_PTR.store(leaked.as_ptr() as usize, SeqCst);
    NEEDLE_LEN.store(leaked.len(), SeqCst);
    HITS.store(0, SeqCst);
    ARMED.store(true, SeqCst);
    f();
    ARMED.store(false, SeqCst);
    HITS.load(SeqCst)
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// A stored passkey whose private key and PRF secret are `key_b64` and `prf_b64`.
fn stored_record(prf_b64: &str) -> (String, String) {
    use p256::pkcs8::EncodePrivateKey;
    let bytes: [u8; 32] = core::array::from_fn(|i| 0x40 + i as u8);
    let key = p256::SecretKey::from_slice(&bytes).unwrap();
    let key_b64 = b64(key.to_pkcs8_der().unwrap().as_bytes());
    let text = json!({
        "v": 1, "credentialId": b64(&[0xAB; 16]), "rpId": "example.com", "userName": "bkv",
        "userDisplayName": "B K V", "userHandle": b64(b"user-1"), "key": key_b64, "alg": -7,
        "createdAt": 0,
        "fido2Extensions": { "hmacCredentials": {
            "algorithm": "hmac-sha256", "credWithUV": prf_b64, "credWithoutUV": b64(&[9u8; 32]),
        }},
    })
    .to_string();
    (text, key_b64)
}

#[test]
fn dropping_a_record_wipes_its_prf_secrets() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let prf_b64 = b64(&[0x5Au8; 32]);
    let (text, _) = stored_record(&prf_b64);
    let record = PasskeyRecord::from_field_value(&text).unwrap();
    assert!(record.prf().is_some(), "the record carries PRF secrets");
    let hits = leaks_during(&prf_b64, || drop(record));
    assert_eq!(hits, 0, "a freed block still held a PRF secret");
}

#[test]
fn building_the_index_wipes_the_record_text() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (text, key_b64) = stored_record(&b64(&[0x5Au8; 32]));
    let record = PasskeyRecord::from_field_value(&text).unwrap();
    let entries = [PasskeyIndexEntry::new("item-1", "field-1", "Example", record)];
    let header = IndexHeader { format_version: 2, generation: 1, built_at: 0, database_id: "db".into() };
    let index_key = [7u8; 32];
    let mut sealed = Vec::new();
    let hits = leaks_during(&key_b64, || {
        sealed = build_with_passkeys(&[], &entries, &index_key, &header).unwrap();
    });
    assert!(!sealed.is_empty());
    assert_eq!(hits, 0, "a freed block still held the private key");
}
