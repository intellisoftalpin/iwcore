//! Memory a CXF preview needs for payloads at the size limit.
//!
//! A counting allocator records the peak heap use above what was allocated
//! before the preview. This file holds a single test, so no other test
//! allocates at the same time.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use iwcore::cxf::PAYLOAD_MAX;
use iwcore::Wallet;

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(n: usize) {
    let now = CURRENT.fetch_add(n, Relaxed) + n;
    PEAK.fetch_max(now, Relaxed);
}

// SAFETY: every call is forwarded unchanged to the system allocator; only
// sizes are counted.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > layout.size() {
            grow(new_size - layout.size());
        } else {
            CURRENT.fetch_sub(layout.size() - new_size, Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// `prefix`, then `unit` repeated (comma separated) while it fits, then
/// `suffix`: a payload of nearly [`PAYLOAD_MAX`] bytes.
fn near_cap(prefix: &str, unit: &str, suffix: &str) -> String {
    let mut s = String::with_capacity(PAYLOAD_MAX);
    s.push_str(prefix);
    s.push_str(unit);
    while s.len() + unit.len() + 1 + suffix.len() <= PAYLOAD_MAX {
        s.push(',');
        s.push_str(unit);
    }
    s.push_str(suffix);
    assert!(s.len() > PAYLOAD_MAX - 64 && s.len() <= PAYLOAD_MAX);
    s
}

/// Peak heap use of one preview above the use before it, and its outcome.
fn preview_peak(w: &mut Wallet, payload: &str) -> (usize, bool) {
    let base = CURRENT.load(Relaxed);
    PEAK.store(base, Relaxed);
    let ok = w.preview_cxf(payload).is_ok();
    (PEAK.load(Relaxed).saturating_sub(base), ok)
}

#[test]
fn previews_at_the_size_limit_stay_bounded() {
    let t = tempfile::TempDir::new().unwrap();
    let mut w = Wallet::create(&t.path().join("w"), "wallet-pass-1", "en").unwrap();
    if !w.is_unlocked() {
        w.unlock("wallet-pass-1").unwrap();
    }
    let head = r#"{"version": {"major": 1}, "accounts": [{"id": "a", "#;

    // Members nobody reads cost nothing, however large.
    let junk = near_cap(r#"{"version": {"major": 1}, "accounts": [], "padding": ["#, "0", "]}");
    let (peak, ok) = preview_peak(&mut w, &junk);
    assert!(ok);
    assert!(peak < 1024 * 1024, "junk: {peak} bytes");

    // What is kept costs a small multiple of the payload. Android apps are the
    // costliest shape that passes every limit.
    let apps = near_cap(&format!(r#"{head}"items": [{{"scope": {{"androidApps": ["#), r#"{"bundleId":"a"}"#, "]}}]}]}");
    let (peak, ok) = preview_peak(&mut w, &apps);
    assert!(ok);
    assert!(peak < 4 * apps.len(), "apps: {peak} bytes for {}", apps.len());

    // Tiny entries stop at the entry limit, long before memory grows.
    for (what, member, close) in [("urls", r#"{"scope": {"urls": ["#, "]}}]}]}"), ("tags", r#"{"tags": ["#, "]}]}]}")] {
        let payload = near_cap(&format!("{head}\"items\": [{member}"), r#""a""#, close);
        let (peak, ok) = preview_peak(&mut w, &payload);
        assert!(!ok, "{what}");
        assert!(peak < 3 * payload.len(), "{what}: {peak} bytes");
    }
}
