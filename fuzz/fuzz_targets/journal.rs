//! The journal is written by the provider process: its framing must survive
//! any bytes (a torn write, a damaged file), and the drain must apply only
//! records whose tag verifies.
//!
//! Every input is used three ways:
//! - as a whole journal, for every reader;
//! - as edits (a cut, byte flips) to a fixed journal of correctly sealed
//!   current-format records: whatever the drain returns must be one of the
//!   records that were sealed, and an unedited journal returns all of them;
//! - as the fields of a record that is sealed and drained back unchanged, and
//!   refused under any other auth key.
#![no_main]
use std::sync::OnceLock;

use iwcore::autofill::journal::{self, DrainKeys, PendingOp, PendingRecord};
use iwcore::autofill::{generate_keys, AutofillKeys};
use libfuzzer_sys::fuzz_target;

struct Fixture {
    keys: AutofillKeys,
    records: Vec<PendingRecord>,
    journal: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let keys = generate_keys().unwrap();
        let login = PendingRecord::new_login("r1", "Example", "https://example.com", "bkv", "pw", 1);
        let mut update = PendingRecord::new_login("r2", "Example", "https://example.com", "bkv", "pw2", 2);
        update.op = PendingOp::UpdatePassword;
        update.item_id = Some("item".into());
        update.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
        update.identity_hint = Some("MAIL".into());
        let reg = iwcore::passkey::sign::register(&iwcore::passkey::sign::RegisterInput {
            rp_id: "example.com",
            user_name: "bkv",
            user_display_name: "bkv",
            user_handle: b"handle",
            exclude_credentials: &[],
            held_credential_ids: &[],
            user_verified: true,
            now: 3,
        })
        .unwrap();
        let passkey = PendingRecord::new_passkey("r3", "example.com", &reg.record, 3).unwrap();
        let records = vec![login, update, passkey];
        let mut journal = Vec::new();
        for r in &records {
            journal.extend(seal(r, &keys));
        }
        Fixture { keys, records, journal }
    })
}

fn seal(record: &PendingRecord, keys: &AutofillKeys) -> Vec<u8> {
    journal::seal_record(record, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap()
}

fn drain_keys(keys: &AutofillKeys) -> DrainKeys<'_> {
    // The index key doubles as a legacy wrap key, so the format-1 recovery
    // path is reached by edited records too.
    DrainKeys {
        journal_secret: &keys.journal_secret,
        auth_key: &keys.journal_auth_key,
        legacy_wrap_keys: std::slice::from_ref(&*keys.index_key),
    }
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();

    // 1. The input as a whole journal, under fixed and under real keys.
    let _ = journal::count_records(data);
    let _ = journal::open_with_index_key(data, &[7; 32]);
    let fixed = DrainKeys { journal_secret: &[9; 32], auth_key: &[5; 32], legacy_wrap_keys: &[[7; 32]] };
    let read = journal::open_for_drain(data, &fixed);
    assert!(read.records.len() + read.unauthenticated <= journal::count_records(data));
    let read = journal::open_for_drain(data, &drain_keys(&f.keys));
    assert!(read.records.is_empty(), "nothing verifies under keys the input was not sealed with");

    // 2. Edits to a journal of sealed records:
    //    [cut lo, cut hi, then (offset lo, offset hi, xor) triples].
    let mut edited = f.journal.clone();
    let mut changed = false;
    if let [cut_lo, cut_hi, flips @ ..] = data {
        let cut = usize::from(u16::from_le_bytes([*cut_lo, *cut_hi]));
        if cut < edited.len() {
            edited.truncate(cut);
            changed = true;
        }
        for flip in flips.chunks_exact(3) {
            let at = usize::from(u16::from_le_bytes([flip[0], flip[1]]));
            if let Some(b) = edited.get_mut(at) {
                *b ^= flip[2];
                changed |= flip[2] != 0;
            }
        }
    }
    let read = journal::open_for_drain(&edited, &drain_keys(&f.keys));
    for r in &read.records {
        assert!(f.records.contains(r), "only a sealed record is ever applied");
    }
    assert!(read.records.len() + read.unauthenticated <= journal::count_records(&edited));
    if !changed {
        assert_eq!(read.records, f.records);
        assert_eq!(read.unauthenticated, 0);
    }
    for r in journal::open_with_index_key(&edited, &f.keys.index_key) {
        assert!(f.records.contains(&r), "the read-back path opens only sealed records");
    }

    // 3. The input as the fields of a record: it seals and drains back as is.
    let mut fields = data.split(|&b| b == 0xff).map(|s| String::from_utf8_lossy(s).into_owned());
    let mut next = || fields.next().unwrap_or_default();
    let created_at = i64::try_from(data.len()).unwrap_or(i64::MAX);
    let mut record = PendingRecord::new_login(next(), next(), next(), next(), next(), created_at);
    let flags = data.first().copied().unwrap_or(0);
    if flags & 1 != 0 {
        record.op = PendingOp::UpdatePassword;
        record.item_id = Some(next());
    }
    if flags & 2 != 0 {
        record.totp_secret = Some(next());
        record.identity_hint = Some(next());
    }
    let sealed = seal(&record, &f.keys);
    let read = journal::open_for_drain(&sealed, &drain_keys(&f.keys));
    assert_eq!(read.records, vec![record.clone()]);
    assert_eq!(read.unauthenticated, 0);
    assert_eq!(journal::open_with_index_key(&sealed, &f.keys.index_key), vec![record]);
    let other_auth = DrainKeys { auth_key: &[5; 32], ..drain_keys(&f.keys) };
    let read = journal::open_for_drain(&sealed, &other_auth);
    assert!(read.records.is_empty());
    assert_eq!(read.unauthenticated, 1);
});
