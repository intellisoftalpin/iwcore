//! Passkeys through the AutoFill path, using only the public API: a provider
//! registers a passkey, stages it in the journal, signs with it before the app
//! ever opens, and the app drains it into the vault and rebuilds the index.

use iwcore::autofill::{generate_keys, index, journal, AutofillKeys, IndexOptions, PendingOp, PendingRecord};
use iwcore::backup::BackupManager;
use iwcore::passkey::sign::{self, RegisterInput};
use iwcore::passkey::{PasskeyRecord, FIELD_PASSKEY};
use iwcore::Wallet;
use tempfile::TempDir;

const PW: &str = "wallet-pass-1";

fn wallet() -> (TempDir, Wallet) {
    let t = TempDir::new().unwrap();
    let mut w = Wallet::create(t.path(), PW, "en").unwrap();
    if !w.is_unlocked() {
        w.unlock(PW).unwrap();
    }
    (t, w)
}

/// What a provider does on "create passkey": register, then stage a record.
fn stage(keys: &AutofillKeys, rp: &str, user: &str, handle: &[u8]) -> (Vec<u8>, PasskeyRecord) {
    let reg = sign::register(&RegisterInput {
        rp_id: rp,
        user_name: user,
        user_display_name: user,
        user_handle: handle,
        exclude_credentials: &[],
        held_credential_ids: &[],
        user_verified: true,
        now: 1_793_433_600,
    })
    .unwrap();
    let record = PendingRecord {
        record_id: format!("rec-{}", hex(&reg.credential_id)),
        op: PendingOp::CreatePasskey,
        item_id: None,
        title: rp.into(),
        url: format!("https://{rp}"),
        identity_value: user.into(),
        identity_hint: None,
        password: String::new(),
        totp_secret: None,
        created_at: 1_793_433_600,
        passkey: Some(reg.record.to_field_value().unwrap().to_string()),
    };
    let bytes = journal::seal_record(&record, &keys.journal_public, &keys.index_key).unwrap();
    (bytes, reg.record)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn drain(w: &mut Wallet, keys: &AutofillKeys, journal: &[u8]) -> iwcore::autofill::DrainSummary {
    w.drain_autofill_journal(journal, &keys.journal_secret, None).unwrap()
}

fn index_passkeys(w: &mut Wallet, keys: &AutofillKeys) -> Vec<index::PasskeyIndexEntry> {
    let sealed = w.build_autofill_index(&keys.index_key, 1, 0, IndexOptions::default()).unwrap();
    let (header, contents) = index::open_all(&sealed, &keys.index_key).unwrap();
    assert_eq!(header.format_version, 2);
    contents.passkeys
}

#[test]
fn a_staged_passkey_signs_before_the_app_opens() {
    let keys = generate_keys().unwrap();
    let (j, _) = stage(&keys, "example.com", "bkv", b"h1");
    // The provider reads its own staged records with the index key.
    let staged = journal::open_with_index_key(&j, &keys.index_key);
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].op, PendingOp::CreatePasskey);
    let record = PasskeyRecord::from_field_value(staged[0].passkey.as_deref().unwrap()).unwrap();
    sign::assert(&record, "example.com", &[3; 32], true).unwrap();
}

#[test]
fn no_matching_login_creates_an_item_in_autofill() {
    let (_t, mut w) = wallet();
    let keys = generate_keys().unwrap();
    let (j, staged) = stage(&keys, "example.com", "bkv@example.com", b"h1");
    let s = drain(&mut w, &keys, &j);
    assert_eq!((s.passkeys_added, s.passkeys_replaced, s.created.len()), (1, 0, 1));

    let item = w.get_item(&s.created[0]).unwrap().unwrap();
    assert_eq!(item.name, "example.com");
    assert_eq!(item.parent_id.as_deref(), Some(s.folder_id.as_str()));
    let fields = w.get_fields_by_item(&item.item_id).unwrap();
    assert!(fields.iter().any(|f| f.field_type == "LINK" && f.value == "https://example.com"));
    assert!(fields.iter().any(|f| f.field_type == "MAIL" && f.value == "bkv@example.com"), "identity classified");
    let list = w.list_passkeys().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].credential_id, staged.credential_id);
}

#[test]
fn a_matching_login_receives_the_passkey() {
    let (_t, mut w) = wallet();
    let login = w.add_item("Example", "web", false, None).unwrap();
    w.add_field(&login, "USER", "BKV", None).unwrap();
    w.add_field(&login, "PASS", "pw", None).unwrap();
    w.add_field(&login, "LINK", "https://www.example.com/login", None).unwrap();

    let keys = generate_keys().unwrap();
    let (j, _) = stage(&keys, "example.com", "bkv", b"h1");
    let s = drain(&mut w, &keys, &j);
    assert_eq!((s.passkeys_added, s.created.len()), (1, 0));
    assert_eq!(s.updated, vec![login.clone()]);
    assert!(w.get_fields_by_item(&login).unwrap().iter().any(|f| f.field_type == FIELD_PASSKEY));
}

#[test]
fn a_login_for_another_account_does_not_receive_it() {
    let (_t, mut w) = wallet();
    let login = w.add_item("Example", "web", false, None).unwrap();
    w.add_field(&login, "USER", "someone-else", None).unwrap();
    w.add_field(&login, "PASS", "pw", None).unwrap();
    w.add_field(&login, "LINK", "https://example.com", None).unwrap();
    let keys = generate_keys().unwrap();
    let (j, _) = stage(&keys, "example.com", "bkv", b"h1");
    let s = drain(&mut w, &keys, &j);
    assert_eq!(s.created.len(), 1, "a new item, never a guess");
    assert!(w.get_fields_by_item(&login).unwrap().iter().all(|f| f.field_type != FIELD_PASSKEY));
}

#[test]
fn re_registration_replaces_and_keeps_the_old_one_in_the_trash() {
    let (_t, mut w) = wallet();
    let keys = generate_keys().unwrap();
    let (j1, first) = stage(&keys, "example.com", "bkv", b"same-handle");
    drain(&mut w, &keys, &j1);
    let (j2, second) = stage(&keys, "example.com", "bkv", b"same-handle");
    let s = drain(&mut w, &keys, &j2);
    assert_eq!((s.passkeys_replaced, s.passkeys_added), (1, 0));

    let list = w.list_passkeys().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].credential_id, second.credential_id);
    // The replaced key is recoverable from the trash.
    let trashed: Vec<_> = w.get_deleted_fields().unwrap().into_iter().filter(|f| f.field_type == FIELD_PASSKEY).collect();
    assert_eq!(trashed.len(), 1);
    w.undelete_field(&trashed[0].item_id, &trashed[0].field_id).unwrap();
    let ids: Vec<_> = w.list_passkeys().unwrap().into_iter().map(|p| p.credential_id).collect();
    assert!(ids.contains(&first.credential_id));
}

#[test]
fn another_user_handle_on_the_same_site_is_kept_separately() {
    let (_t, mut w) = wallet();
    let keys = generate_keys().unwrap();
    let (j1, _) = stage(&keys, "example.com", "alice", b"h-alice");
    let (j2, _) = stage(&keys, "example.com", "bob", b"h-bob");
    let mut both = j1.clone();
    both.extend_from_slice(&j2);
    let s = drain(&mut w, &keys, &both);
    assert_eq!(s.passkeys_added, 2);
    assert_eq!(w.list_passkeys().unwrap().len(), 2);
}

#[test]
fn draining_twice_changes_nothing() {
    let (_t, mut w) = wallet();
    let keys = generate_keys().unwrap();
    let (j, _) = stage(&keys, "example.com", "bkv", b"h1");
    drain(&mut w, &keys, &j);
    let s = drain(&mut w, &keys, &j);
    assert_eq!((s.passkeys_added, s.passkeys_replaced, s.unchanged), (0, 0, 1));
    assert_eq!(w.list_passkeys().unwrap().len(), 1);
}

#[test]
fn an_invalid_staged_passkey_is_skipped_and_the_rest_drains() {
    let (_t, mut w) = wallet();
    let keys = generate_keys().unwrap();
    let bad = PendingRecord {
        record_id: "bad".into(),
        op: PendingOp::CreatePasskey,
        item_id: None,
        title: "x".into(),
        url: "https://x.example".into(),
        identity_value: "u".into(),
        identity_hint: None,
        password: String::new(),
        totp_secret: None,
        created_at: 0,
        passkey: Some("{\"v\":1,\"rpId\":\"x.example\"}".into()),
    };
    let mut j = journal::seal_record(&bad, &keys.journal_public, &keys.index_key).unwrap();
    let (good, _) = stage(&keys, "example.com", "bkv", b"h1");
    j.extend_from_slice(&good);
    // And a plain login in the same journal.
    let login = PendingRecord { record_id: "login".into(), op: PendingOp::Create, passkey: None,
        password: "pw".into(), url: "https://other.example".into(), identity_value: "me".into(), ..bad.clone() };
    j.extend_from_slice(&journal::seal_record(&login, &keys.journal_public, &keys.index_key).unwrap());

    let s = drain(&mut w, &keys, &j);
    assert_eq!((s.skipped, s.passkeys_added, s.created.len()), (1, 1, 2));
}

#[test]
fn the_index_carries_live_passkeys_only() {
    let (_t, mut w) = wallet();
    let keys = generate_keys().unwrap();
    let (j1, a) = stage(&keys, "a.example", "u", b"h1");
    let (j2, b) = stage(&keys, "b.example", "u", b"h2");
    let mut j = j1;
    j.extend_from_slice(&j2);
    let s = drain(&mut w, &keys, &j);

    let entries = index_passkeys(&mut w, &keys);
    assert_eq!(entries.len(), 2, "passkey-only items are included");
    for e in &entries {
        let r = PasskeyRecord::from_field_value(&e.record.to_string()).unwrap();
        sign::assert(&r, &r.rp_id, &[1; 32], true).unwrap();
        let key_b64 = e.record["key"].as_str().unwrap().to_string();
        assert!(!format!("{e:?}").contains(&key_b64), "Debug must not show the key");
    }
    // Trash one item: gone from the index.
    let gone = s.created.iter().find(|id| w.get_item(id).unwrap().unwrap().name == "a.example").unwrap().clone();
    w.delete_item(&gone).unwrap();
    let entries = index_passkeys(&mut w, &keys);
    assert_eq!(entries.len(), 1);
    let left = PasskeyRecord::from_field_value(&entries[0].record.to_string()).unwrap();
    assert_eq!(left.credential_id, b.credential_id);
    assert_ne!(left.credential_id, a.credential_id);
}

#[test]
fn passkeys_survive_backup_and_restore_and_still_sign_with_the_same_prf() {
    let (t, mut w) = wallet();
    let keys = generate_keys().unwrap();
    let (j, staged) = stage(&keys, "example.com", "bkv", b"h1");
    drain(&mut w, &keys, &j);
    let prf_before = iwcore::passkey::prf::evaluate_salts(&staged, &[9; 32], None, true).unwrap();

    let mgr = BackupManager::new(&t.path().join("b"));
    let zip = mgr.create_backup(w.database().unwrap(), true).unwrap();
    w.close();
    let target = t.path().join("restored");
    mgr.extract_backup(&zip, &target).unwrap();
    let mut r = Wallet::open(&target).unwrap();
    assert!(r.unlock(PW).unwrap());

    let entries = index_passkeys(&mut r, &keys);
    assert_eq!(entries.len(), 1);
    let back = PasskeyRecord::from_field_value(&entries[0].record.to_string()).unwrap();
    assert_eq!(back.credential_id, staged.credential_id);
    sign::assert(&back, "example.com", &[2; 32], true).unwrap();
    let prf_after = iwcore::passkey::prf::evaluate_salts(&back, &[9; 32], None, true).unwrap();
    assert_eq!(prf_before, prf_after, "PRF output must survive a restore");
}

#[test]
fn a_full_journal_still_reports_its_passkey_records() {
    let keys = generate_keys().unwrap();
    let mut j = Vec::new();
    for i in 0..3u8 {
        j.extend_from_slice(&stage(&keys, "example.com", "u", &[i + 1]).0);
    }
    assert_eq!(journal::count_records(&j), 3);
    assert!(journal::can_accept(j.len(), 3));
    assert!(j.len() < journal::MAX_BYTES);
}
