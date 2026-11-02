//! The journal is written by the provider process: authenticated, but its
//! framing must survive any bytes (a torn write, a damaged file).
#![no_main]
use iwcore::autofill::journal;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = journal::count_records(data);
    let _ = journal::open_with_index_key(data, &[7; 32]);
    let keys = journal::DrainKeys { journal_secret: &[9; 32], auth_key: &[5; 32], legacy_wrap_keys: &[[7; 32]] };
    let _ = journal::open_for_drain(data, &keys);
});
