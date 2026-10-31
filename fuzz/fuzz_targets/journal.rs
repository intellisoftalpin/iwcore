//! The journal is written by the provider process: authenticated, but its
//! framing must survive any bytes (a torn write, a damaged file).
#![no_main]
use iwcore::autofill::journal;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = journal::count_records(data);
    let _ = journal::open_with_index_key(data, &[7; 32]);
    let _ = journal::open_with_journal_key(data, &[9; 32]);
});
