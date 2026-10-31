//! CXF import and export through the public API.
//!
//! The payload below is written from the CXF 1.0 specification's structure
//! (Proposed Standard, errata 2026-03-09) and carries every credential type.

use std::collections::BTreeSet;

use iwcore::cxf::export::ExportOptions;
use iwcore::cxf::import::{ImportOptions, KindCounts};
use iwcore::passkey::sign::{self, RegisterInput};
use iwcore::passkey::{prf, PasskeyRecord, FIELD_PASSKEY};
use iwcore::{WalletError, Wallet};
use serde_json::{json, Value};
use tempfile::TempDir;

const PW: &str = "wallet-pass-1";

fn wallet() -> (TempDir, Wallet) {
    let t = TempDir::new().unwrap();
    let mut w = Wallet::create(&t.path().join("w"), PW, "en").unwrap();
    if !w.is_unlocked() {
        w.unlock(PW).unwrap();
    }
    (t, w)
}

fn opts(t: &TempDir) -> ImportOptions {
    ImportOptions { backup_folder: t.path().join("backups") }
}

fn ef(kind: &str, value: &str) -> Value {
    json!({ "fieldType": kind, "value": value })
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// A passkey credential as another manager would export it.
fn cxf_passkey(rp: &str, handle: &[u8]) -> (Value, PasskeyRecord) {
    let reg = sign::register(&RegisterInput {
        rp_id: rp, user_name: "bkv", user_display_name: "B K V", user_handle: handle,
        exclude_credentials: &[], held_credential_ids: &[], user_verified: true, now: 0,
    }).unwrap();
    let stored: Value = serde_json::from_str(&reg.record.to_field_value().unwrap()).unwrap();
    let cred = json!({
        "type": "passkey",
        "credentialId": stored["credentialId"], "rpId": rp, "username": "bkv",
        "userDisplayName": "B K V", "userHandle": stored["userHandle"], "key": stored["key"],
        "fido2Extensions": stored["fido2Extensions"],
    });
    (cred, reg.record)
}

fn payload(items: Vec<Value>, collections: Vec<Value>) -> String {
    json!({
        "version": {"major": 1, "minor": 0},
        "exporterRpId": "other.example", "exporterDisplayName": "Other Manager",
        "timestamp": 1_790_000_000u64,
        "accounts": [{"id": "YWNj", "username": "me", "email": "me@example.com", "collections": collections, "items": items}],
    }).to_string()
}

fn rich_items() -> (Vec<Value>, PasskeyRecord) {
    let (pk, record) = cxf_passkey("github.com", b"gh-user");
    let items = vec![
        json!({"id": "aTE", "title": "GitHub", "creationAt": 1_700_000_000, "scope": {"urls": ["https://github.com/login"], "androidApps": [{"bundleId": "com.github.android"}]},
               "tags": ["dev", "work"], "subtitle": "personal",
               "credentials": [
                   {"type": "basic-auth", "username": ef("string", "bkv@example.com"), "password": ef("concealed-string", "gh-pass")},
                   pk,
                   {"type": "totp", "secret": "JBSWY3DPEHPK3PXP", "period": 30, "digits": 6, "algorithm": "sha1", "issuer": "GitHub", "username": "bkv"},
               ]}),
        json!({"id": "aTI", "title": "Note", "credentials": [{"type": "note", "content": ef("string", "line one\nline two")}]}),
        json!({"id": "aTM", "title": "Visa", "credentials": [{"type": "credit-card", "number": ef("concealed-string", "4111111111111111"),
               "fullName": ef("string", "B K V"), "cardType": ef("string", "Visa"), "verificationNumber": ef("concealed-string", "123"),
               "pin": ef("concealed-string", "9876"), "expiryDate": ef("year-month", "2029-02"), "validFrom": ef("year-month", "2024-02")}]}),
        json!({"id": "aTQ", "title": "Home Wi-Fi", "credentials": [{"type": "wifi", "ssid": ef("string", "Home; Net"),
               "networkSecurityType": ef("wifi-network-security-type", "wpa3-personal"), "passphrase": ef("concealed-string", "w,i:f\"i"), "hidden": ef("boolean", "true")}]}),
        json!({"id": "aTU", "title": "Address", "credentials": [{"type": "address", "streetAddress": ef("string", "Main St 1"),
               "postalCode": ef("string", "8000"), "city": ef("string", "Zürich"), "country": ef("country-code", "CH"), "tel": ef("string", "+41 44 000 00 00")}]}),
        json!({"id": "aTY", "title": "Me", "credentials": [{"type": "person-name", "given": ef("string", "B"), "surname": ef("string", "V"), "givenInformal": ef("string", "Bee")}]}),
        json!({"id": "aTc", "title": "API", "credentials": [{"type": "api-key", "key": ef("concealed-string", "sk-123"), "username": ef("string", "svc"),
               "keyType": ef("string", "bearer"), "url": ef("string", "https://api.example.com"), "validFrom": ef("date", "2026-01-01"), "expiryDate": ef("date", "2027-01-01")}]}),
        json!({"id": "aTg", "title": "Server", "credentials": [{"type": "ssh-key", "keyType": "ssh-ed25519", "privateKey": b64(&[1, 2, 3, 4]), "keyComment": "bkv@laptop"}]}),
        json!({"id": "aTk", "title": "Licence", "credentials": [{"type": "drivers-license", "fullName": ef("string", "B K V"), "licenseNumber": ef("string", "DL-1"),
               "issuingAuthority": ef("string", "Strassenverkehrsamt"), "birthDate": ef("date", "1990-05-17"), "expiryDate": ef("date", "2031-05-17")}]}),
        json!({"id": "aTEw", "title": "Passport", "credentials": [{"type": "passport", "passportNumber": ef("string", "X123"), "nationality": ef("string", "CH")}]}),
        json!({"id": "aTEx", "title": "ID card", "credentials": [{"type": "identity-document", "documentNumber": ef("string", "ID-9")}]}),
        json!({"id": "aTEy", "title": "Custom", "credentials": [{"type": "custom-fields", "id": "Y2Y", "label": "Extras", "fields": [
               {"fieldType": "string", "value": "blue", "label": "Favourite colour"},
               {"fieldType": "concealed-string", "value": "s3cr3t", "label": "Recovery code"},
               {"fieldType": "date", "value": "2026-12-24", "label": "Renewal"},
               {"fieldType": "something-new", "value": "kept as text", "label": "Future field"},
               {"fieldType": "string", "value": "no label"}]}]}),
        json!({"id": "aTEz", "title": "Generated", "credentials": [{"type": "generated-password", "password": "gen-pw-1"}]}),
        json!({"id": "aTE0", "title": "With a file", "credentials": [
               {"type": "file", "id": "Zg", "name": "x.pdf", "decryptedSize": 10, "integrityHash": "aGFzaA"},
               {"type": "item-reference", "reference": {"item": "aTE"}},
               {"type": "brand-new-type", "x": 1},
               {"type": "totp", "secret": "JBSWY3DPEHPK3PXP", "period": 30, "digits": 6, "algorithm": "md5"},
               {"type": "note", "content": ef("string", "the rest is kept")}]}),
    ];
    (items, record)
}

fn fields_of(w: &mut Wallet, title: &str) -> Vec<iwcore::IWField> {
    let id = w.get_items().unwrap().iter().find(|i| i.name == title && !i.folder).unwrap().item_id.clone();
    w.get_fields_by_item(&id).unwrap()
}

fn has(fields: &[iwcore::IWField], ty: &str, value: &str) -> bool {
    fields.iter().any(|f| f.field_type == ty && f.value == value)
}

fn has_label(fields: &[iwcore::IWField], label: &str, value: &str) -> bool {
    fields.iter().any(|f| f.label == label && f.value == value)
}

#[test]
fn every_credential_type_maps_as_documented() {
    let (t, mut w) = wallet();
    let (items, record) = rich_items();
    let report = w.import_cxf(&payload(items, vec![]), &opts(&t)).unwrap();
    assert!(report.backup_path.exists(), "backup taken first");
    assert_eq!(report.folder_ids.len(), 1);
    let top = w.get_item(&report.folder_ids[0]).unwrap().unwrap();
    assert_eq!(top.name, "Imported from Other Manager 2026-09-21");

    let gh = fields_of(&mut w, "GitHub");
    assert!(has(&gh, "LINK", "https://github.com/login"));
    assert!(has(&gh, "MAIL", "bkv@example.com"), "identity classified as e-mail");
    assert!(has(&gh, "PASS", "gh-pass"));
    assert!(gh.iter().any(|f| f.field_type == "2FAC" && f.value.starts_with("otpauth://totp/GitHub:bkv?secret=JBSWY3DPEHPK3PXP")));
    assert!(gh.iter().any(|f| f.label == "Imported details" && f.value.contains("Tags: dev, work") && f.value.contains("com.github.android") && f.value.contains("Subtitle: personal")));
    let pk = w.list_passkeys().unwrap();
    assert_eq!(pk.len(), 1);
    assert_eq!(pk[0].credential_id, record.credential_id);
    assert!(pk[0].has_prf, "fido2Extensions kept");

    assert!(has(&fields_of(&mut w, "Note"), "NOTE", "line one\nline two"));
    let visa = fields_of(&mut w, "Visa");
    for (ty, v) in [("CARD", "4111111111111111"), ("NAME", "B K V"), ("CVVC", "123"), ("PINC", "9876"), ("EXPD", "20290228")] {
        assert!(has(&visa, ty, v), "{ty}");
    }
    assert!(has_label(&visa, "Card type", "Visa") && has_label(&visa, "Valid from", "2024-02"));
    assert!(has(&fields_of(&mut w, "Home Wi-Fi"), "WIFI", "WIFI:T:WPA;S:Home\\; Net;P:w\\,i\\:f\\\"i;H:true;;"));
    let addr = fields_of(&mut w, "Address");
    assert!(has(&addr, "ADDR", "Main St 1\n8000 Zürich\nCH") && has(&addr, "PHON", "+41 44 000 00 00"));
    let me = fields_of(&mut w, "Me");
    assert!(has(&me, "NAME", "B V") && has_label(&me, "Informal name", "Bee"));
    let api = fields_of(&mut w, "API");
    assert!(has_label(&api, "API key", "sk-123") && has(&api, "USER", "svc") && has(&api, "LINK", "https://api.example.com")
        && has_label(&api, "Key type", "bearer") && has_label(&api, "Valid from", "20260101") && has(&api, "EXPD", "20270101"));
    let ssh = fields_of(&mut w, "Server");
    assert!(ssh.iter().any(|f| f.label == "SSH private key" && f.value.starts_with("-----BEGIN PRIVATE KEY-----") && f.value_type == "pass"));
    assert!(has_label(&ssh, "Key comment", "bkv@laptop"));
    let dl = fields_of(&mut w, "Licence");
    assert!(has(&dl, "NAME", "B K V") && has(&dl, "SNUM", "DL-1") && has(&dl, "EXPD", "20310517")
        && has_label(&dl, "Issuing authority", "Strassenverkehrsamt") && has_label(&dl, "Birth date", "19900517"));
    assert!(has(&fields_of(&mut w, "Passport"), "SNUM", "X123"));
    assert!(has(&fields_of(&mut w, "ID card"), "SNUM", "ID-9"));
    let custom = fields_of(&mut w, "Custom");
    assert!(has_label(&custom, "Favourite colour", "blue"));
    assert!(custom.iter().any(|f| f.label == "Recovery code" && f.value == "s3cr3t" && f.value_type == "pass"));
    assert!(custom.iter().any(|f| f.label == "Renewal" && f.value == "20261224" && f.value_type == "date"));
    assert!(has_label(&custom, "Future field", "kept as text"), "unknown fieldType read as text");
    assert!(has_label(&custom, "Extras", "no label"), "falls back to the credential label");
    assert!(has_label(&fields_of(&mut w, "Generated"), "Generated password", "gen-pw-1"));
    assert!(has(&fields_of(&mut w, "With a file"), "NOTE", "the rest is kept"));

    let skipped: BTreeSet<_> = report.preview.skipped.iter().map(|s| s.credential_type.clone()).collect();
    assert_eq!(skipped, ["brand-new-type", "file", "item-reference", "totp"].iter().map(|s| s.to_string()).collect());
    for s in &report.preview.skipped {
        assert_eq!(s.item_title, "With a file");
        assert!(!s.reason.is_empty());
    }
}

#[test]
fn preview_writes_nothing_and_matches_the_import() {
    let (t, mut w) = wallet();
    let (items, _) = rich_items();
    let doc = payload(items, vec![]);
    let before = w.get_items().unwrap().len();
    let preview = w.preview_cxf(&doc).unwrap();
    assert_eq!(w.get_items().unwrap().len(), before, "preview writes nothing");
    assert_eq!(preview.items, 14);
    assert_eq!(preview.counts.passkeys, 1);
    assert_eq!(preview.counts.logins, 2, "basic-auth + generated password");
    assert_eq!(preview.counts.totp, 1);
    assert_eq!(preview.counts.cards, 1);
    assert_eq!(preview.counts.wifi, 1);
    assert!(preview.new_labels.contains(&"Card type".to_string()));
    let report = w.import_cxf(&doc, &opts(&t)).unwrap();
    assert_eq!(report.preview, preview, "the import does exactly what the preview said");
    assert_eq!(report.item_ids.len(), preview.items);
}

#[test]
fn re_importing_adds_nothing_and_existing_items_are_never_touched() {
    let (t, mut w) = wallet();
    let mine = w.add_item("GitHub", "web", false, None).unwrap();
    w.add_field(&mine, "PASS", "my-own", None).unwrap();
    let snapshot = (w.get_items().unwrap().to_vec(), w.get_fields().unwrap().to_vec());

    let (items, _) = rich_items();
    let doc = payload(items, vec![]);
    w.import_cxf(&doc, &opts(&t)).unwrap();
    let after_first = w.get_items().unwrap().len();
    for (a, b) in snapshot.1.iter().zip(w.get_fields_by_item(&mine).unwrap()) {
        assert_eq!((a.field_id.as_str(), a.value.as_str()), (b.field_id.as_str(), b.value.as_str()), "existing fields unchanged");
    }
    assert!(w.get_item(&mine).unwrap().is_some());

    let again = w.import_cxf(&doc, &opts(&t)).unwrap();
    assert_eq!(again.preview.items, 0);
    assert_eq!(again.preview.duplicates, 14);
    assert!(again.folder_ids.is_empty(), "no empty folder is created");
    assert_eq!(w.get_items().unwrap().len(), after_first);
    assert_eq!(w.list_passkeys().unwrap().len(), 1);
    let _ = snapshot.0;
}

#[test]
fn a_passkey_already_in_the_vault_is_not_imported_twice() {
    let (t, mut w) = wallet();
    let (pk, _) = cxf_passkey("example.com", b"h");
    w.import_cxf(&payload(vec![json!({"id": "a", "title": "One", "credentials": [pk.clone()]})], vec![]), &opts(&t)).unwrap();
    // Same credential inside a different item.
    let r = w.import_cxf(&payload(vec![json!({"id": "b", "title": "Other title", "credentials": [pk, {"type": "note", "content": ef("string", "x")}]})], vec![]), &opts(&t)).unwrap();
    assert_eq!(r.preview.items, 1);
    assert!(r.preview.skipped.iter().any(|s| s.reason.contains("already in the vault")));
    assert_eq!(w.list_passkeys().unwrap().len(), 1);
}

#[test]
fn unusable_passkeys_are_skipped_with_a_reason_and_no_secret() {
    let (t, mut w) = wallet();
    // An Ed25519 key in PKCS#8 (OID 1.3.101.112) with a dummy scalar.
    let mut ed = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    ed.extend([7u8; 32]);
    let bad = [
        json!({"type": "passkey", "credentialId": b64(&[1; 16]), "rpId": "a.example", "username": "u", "userDisplayName": "u", "userHandle": b64(b"h"), "key": b64(&ed)}),
        json!({"type": "passkey", "credentialId": b64(&[1; 4]), "rpId": "a.example", "username": "u", "userDisplayName": "u", "userHandle": b64(b"h"), "key": b64(&ed)}),
        json!({"type": "passkey", "credentialId": b64(&[1; 16]), "rpId": "NOT A DOMAIN", "username": "u", "userDisplayName": "u", "userHandle": b64(b"h"), "key": b64(&ed)}),
        json!({"type": "passkey"}),
    ];
    let r = w.import_cxf(&payload(vec![json!({"id": "a", "title": "Bad", "credentials": bad})], vec![]), &opts(&t)).unwrap();
    assert_eq!(r.preview.skipped.len(), 4);
    assert!(r.preview.skipped[0].reason.contains("only P-256"));
    for s in &r.preview.skipped[1..3] {
        assert!(s.reason.starts_with("passkey is not usable: "), "{}", s.reason);
    }
    for s in &r.preview.skipped {
        assert!(!s.reason.contains(&b64(&ed)));
    }
    assert!(w.list_passkeys().unwrap().is_empty());
}

#[test]
fn collections_become_folders() {
    let (t, mut w) = wallet();
    let items = vec![
        json!({"id": "i1", "title": "Deep", "credentials": [{"type": "note", "content": ef("string", "1")}]}),
        json!({"id": "i2", "title": "Loose", "credentials": [{"type": "note", "content": ef("string", "2")}]}),
    ];
    let collections = vec![json!({"id": "c1", "title": "Work", "items": [], "subCollections": [
        {"id": "c2", "title": "Servers", "items": [{"item": "i1"}]}]}),
        json!({"id": "c3", "title": "Also has i1", "items": [{"item": "i1"}]}),
        json!({"id": "c4", "title": "Empty", "items": []})];
    let r = w.import_cxf(&payload(items, collections), &opts(&t)).unwrap();
    let all = w.get_items().unwrap().to_vec();
    let by_id = |id: &str| all.iter().find(|i| i.item_id == id).unwrap().clone();
    let deep = all.iter().find(|i| i.name == "Deep").unwrap();
    let servers = by_id(deep.parent_id.as_deref().unwrap());
    assert_eq!(servers.name, "Servers", "an item in two collections lands in the first");
    assert_eq!(by_id(servers.parent_id.as_deref().unwrap()).name, "Work");
    let loose = all.iter().find(|i| i.name == "Loose").unwrap();
    assert_eq!(loose.parent_id.as_deref(), Some(r.folder_ids[0].as_str()));
    assert!(all.iter().all(|i| i.name != "Empty" && i.name != "Also has i1"), "folders without content are not created");
}

#[test]
fn hostile_strings_are_stored_safely() {
    let (t, mut w) = wallet();
    let title = format!("{}\u{0}../../%s%n\u{1b}[2J{}", "x".repeat(10), "y".repeat(2000));
    let r = w.import_cxf(&payload(vec![json!({"id": "a", "title": title, "credentials": [
        {"type": "custom-fields", "fields": [{"fieldType": "string", "value": "v", "label": "lab\u{7}el"}]},
        {"type": "note", "content": ef("string", &"n".repeat(2 * 1024 * 1024))}]})], vec![]), &opts(&t)).unwrap();
    let item = w.get_item(&r.item_ids[0]).unwrap().unwrap();
    assert!(item.name.len() <= 1024 && !item.name.contains('\u{0}') && !item.name.contains('\u{1b}'));
    let f = w.get_fields_by_item(&item.item_id).unwrap();
    assert!(f.iter().any(|f| f.label == "label"));
    assert!(f.iter().any(|f| f.field_type == "NOTE" && f.value.len() == 1024 * 1024), "notes are capped at 1 MiB");
}

#[test]
fn more_than_200_new_labels_is_refused_before_anything_is_written() {
    let (t, mut w) = wallet();
    let fields: Vec<Value> = (0..201).map(|i| json!({"fieldType": "string", "value": "v", "label": format!("L{i}")})).collect();
    let doc = payload(vec![json!({"id": "a", "title": "Many", "credentials": [{"type": "custom-fields", "fields": fields}]})], vec![]);
    let before = w.get_items().unwrap().len();
    assert!(matches!(w.import_cxf(&doc, &opts(&t)), Err(WalletError::InvalidInput(_))));
    assert!(w.preview_cxf(&doc).is_err());
    assert_eq!(w.get_items().unwrap().len(), before);
}

#[test]
fn malformed_and_foreign_payloads_are_refused() {
    let (t, mut w) = wallet();
    for bad in ["", "{}", "[]", "{\"version\":{\"major\":2},\"accounts\":[]}"] {
        assert!(w.import_cxf(bad, &opts(&t)).is_err());
    }
    // An unwritable backup folder stops the import before any write.
    let file = t.path().join("a-file");
    std::fs::write(&file, b"x").unwrap();
    let (items, _) = rich_items();
    let before = w.get_items().unwrap().len();
    assert!(w.import_cxf(&payload(items, vec![]), &ImportOptions { backup_folder: file.join("sub") }).is_err());
    assert_eq!(w.get_items().unwrap().len(), before);
}

/// Everything IntelliWallet holds leaves through export and comes back the same.
#[test]
fn export_then_import_into_an_empty_vault_round_trips() {
    let (t, mut w) = wallet();
    let (items, record) = rich_items();
    w.import_cxf(&payload(items, vec![]), &opts(&t)).unwrap();
    // Plus vault-only data: old passwords, a secret question, seed phrase, trash.
    let extra = w.add_item("Extras", "document", false, None).unwrap();
    for (ty, v) in [("OLDP", "old-pw"), ("SQUE", "Pet?"), ("SANS", "Rex"), ("SEED", "abandon ability"), ("DATE", "20260101"), ("TIME", "1230"), ("PHON", "+1 555")] {
        w.add_field(&extra, ty, v, None).unwrap();
    }
    let gone = w.add_item("Trashed", "document", false, None).unwrap();
    w.add_field(&gone, "PASS", "trashed-secret", None).unwrap();
    w.delete_item(&gone).unwrap();

    let doc = w.export_cxf(&ExportOptions::default()).unwrap();
    assert!(!doc.contains("trashed-secret"), "trash is not exported");
    let v: Value = serde_json::from_str(&doc).unwrap();
    assert_eq!(v["version"]["major"], 1);
    assert_eq!(v["exporterRpId"], "intelliwallet.io");
    for item in v["accounts"][0]["items"].as_array().unwrap() {
        assert!(item["credentials"].is_array(), "required arrays are always present");
        if let Some(scope) = item.get("scope") {
            assert!(scope["urls"].is_array() && scope["androidApps"].is_array());
        }
    }

    let (t2, mut fresh) = wallet();
    let r = fresh.import_cxf(&doc, &opts(&t2)).unwrap();
    assert!(r.preview.skipped.is_empty(), "nothing IntelliWallet wrote is skipped: {:?}", r.preview.skipped);

    // Same titles and the same values (label names may differ for system fields).
    let values = |w: &mut Wallet| -> BTreeSet<(String, String)> {
        let items: Vec<_> = w.get_items().unwrap().iter().filter(|i| !i.folder && !i.deleted).cloned().collect();
        let mut out = BTreeSet::new();
        for i in items {
            for f in w.get_fields_by_item(&i.item_id).unwrap() {
                if f.field_type != FIELD_PASSKEY && f.label != "Imported details" {
                    out.insert((i.name.clone(), f.value.clone()));
                }
            }
        }
        out
    };
    let a = values(&mut w);
    let b = values(&mut fresh);
    let missing: Vec<_> = a.difference(&b).collect();
    assert!(missing.is_empty(), "lost in the round trip: {missing:?}");

    // The passkey comes back whole: signs, same PRF output.
    let list = fresh.list_passkeys().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].credential_id, record.credential_id);
    let sealed = fresh.build_autofill_index(&[5; 32], 1, 0, Default::default()).unwrap();
    let (_, contents) = iwcore::autofill::index::open_all(&sealed, &[5; 32]).unwrap();
    let back = PasskeyRecord::from_field_value(&contents.passkeys[0].record.to_string()).unwrap();
    sign::assert(&back, "github.com", &[1; 32], true).unwrap();
    assert_eq!(prf::evaluate_salts(&back, &[3; 32], None, true), prf::evaluate_salts(&record, &[3; 32], None, true));
}

#[test]
fn export_of_chosen_folders_only() {
    let (_t, mut w) = wallet();
    let a = w.add_item("A", "folder", true, None).unwrap();
    let a1 = w.add_item("A1", "folder", true, Some(&a)).unwrap();
    let inside = w.add_item("Inside", "document", false, Some(&a1)).unwrap();
    w.add_field(&inside, "NOTE", "in", None).unwrap();
    let outside = w.add_item("Outside", "document", false, None).unwrap();
    w.add_field(&outside, "NOTE", "out", None).unwrap();

    let doc = w.export_cxf(&ExportOptions { folder_ids: Some(vec![a.clone()]) }).unwrap();
    assert!(doc.contains("Inside") && !doc.contains("Outside"));
    let v: Value = serde_json::from_str(&doc).unwrap();
    assert_eq!(v["accounts"][0]["collections"][0]["title"], "A");
    assert_eq!(v["accounts"][0]["collections"][0]["subCollections"][0]["title"], "A1");
    assert!(w.export_cxf(&ExportOptions { folder_ids: Some(vec!["nope".into()]) }).is_err());
}

/// The CXF credential each vault field type is written as.
#[test]
fn export_writes_each_field_type_as_its_credential() {
    let (_t, mut w) = wallet();
    let login = w.add_item("Login", "web", false, None).unwrap();
    for (ty, v) in [("USER", "u1"), ("USER", "u2"), ("PASS", "p1"), ("LINK", "https://a.example")] {
        w.add_field(&login, ty, v, None).unwrap();
    }
    let pw_only = w.add_item("Password only", "web", false, None).unwrap();
    w.add_field(&pw_only, "PASS", "p2", None).unwrap();
    let misc = w.add_item("Misc", "document", false, None).unwrap();
    for (ty, v) in [
        ("2FAC", "JBSWY3DPEHPK3PXP"), ("2FAC", "not a secret!"), ("NOTE", "a note"),
        ("WIFI", "WIFI:S:open;T:nopass;P:;;"), ("WIFI", "WIFI:S:old;T:WEP;P:wep-key;H:true;;"),
        ("WIFI", "WIFI:S:home;T:WPA;P:wpa-key;;"), ("ADDR", "Main St 1"),
        ("OLDP", "old-pw"), ("SQUE", "Pet?"), ("DATE", "20260101"), ("DATE", "someday"),
    ] {
        w.add_field(&misc, ty, v, None).unwrap();
    }

    let doc = w.export_cxf(&ExportOptions::default()).unwrap();
    let v: Value = serde_json::from_str(&doc).unwrap();
    let items = v["accounts"][0]["items"].as_array().unwrap().clone();
    let item = |title: &str| items.iter().find(|i| i["title"] == title).unwrap().clone();
    let creds = |title: &str, ty: &str| -> Vec<Value> {
        item(title)["credentials"].as_array().unwrap().iter().filter(|c| c["type"] == ty).cloned().collect()
    };
    let custom = |title: &str| creds(title, "custom-fields").first().map(|c| c["fields"].as_array().unwrap().clone()).unwrap_or_default();
    let has_custom = |title: &str, kind: &str, value: &str| custom(title).iter().any(|f| f["fieldType"] == kind && f["value"] == value);

    let basic = creds("Login", "basic-auth");
    assert_eq!(basic.len(), 1);
    assert_eq!(basic[0]["username"], json!({"fieldType": "string", "value": "u1"}), "the first identity");
    assert_eq!(basic[0]["password"], json!({"fieldType": "concealed-string", "value": "p1"}));
    assert!(has_custom("Login", "string", "u2"), "the second identity is kept");
    assert_eq!(item("Login")["scope"]["urls"], json!(["https://a.example"]));
    assert!(custom("Login").iter().all(|f| f["value"] != "https://a.example"));

    let basic = creds("Password only", "basic-auth");
    assert_eq!(basic.len(), 1, "a password alone is a login");
    assert!(basic[0].get("username").is_none());

    let totp = creds("Misc", "totp");
    assert_eq!(totp.len(), 1);
    assert_eq!((totp[0]["secret"].as_str(), totp[0]["digits"].as_u64(), totp[0]["algorithm"].as_str()), (Some("JBSWY3DPEHPK3PXP"), Some(6), Some("sha1")));
    assert!(has_custom("Misc", "concealed-string", "not a secret!"), "an unreadable 2FA value is kept, concealed");
    assert_eq!(creds("Misc", "note"), vec![json!({"type": "note", "content": {"fieldType": "string", "value": "a note"}})]);
    let wifi: Vec<(Value, Value, Value, Value)> = creds("Misc", "wifi").iter()
        .map(|c| (c["ssid"]["value"].clone(), c["networkSecurityType"]["value"].clone(), c["passphrase"]["value"].clone(), c["hidden"]["value"].clone()))
        .collect();
    assert_eq!(wifi, vec![
        (json!("open"), json!("unsecured"), json!(""), json!("false")),
        (json!("old"), json!("wep"), json!("wep-key"), json!("true")),
        (json!("home"), json!("wpa2-personal"), json!("wpa-key"), json!("false")),
    ]);
    assert_eq!(creds("Misc", "address"), vec![json!({"type": "address", "streetAddress": {"fieldType": "string", "value": "Main St 1"}})]);
    assert!(has_custom("Misc", "concealed-string", "old-pw"));
    assert!(has_custom("Misc", "string", "Pet?"));
    assert!(has_custom("Misc", "date", "2026-01-01"));
    assert!(has_custom("Misc", "string", "someday"), "a date that does not parse stays text");
    assert_eq!(custom("Misc").len(), 5);
}

/// Folders become collections: only real folders, nested to the CXF limit.
#[test]
fn export_collections_mirror_the_folder_tree() {
    let (_t, mut w) = wallet();
    let top = w.add_item("Top", "folder", true, None).unwrap();
    let inner = w.add_item("Inner", "folder", true, Some(&top)).unwrap();
    let note = w.add_item("Note", "document", false, Some(&top)).unwrap();
    w.add_field(&note, "NOTE", "x", None).unwrap();
    w.add_item("Loose", "document", false, None).unwrap();

    let doc = w.export_cxf(&ExportOptions::default()).unwrap();
    let v: Value = serde_json::from_str(&doc).unwrap();
    let cols = v["accounts"][0]["collections"].as_array().unwrap();
    assert_eq!(cols.len(), 1, "one collection per top-level folder, none for the root");
    assert_eq!(cols[0]["title"], "Top");
    assert_eq!(cols[0]["items"], json!([{"item": b64(note.as_bytes())}]), "subfolders are not linked as items");
    assert_eq!(cols[0]["subCollections"][0]["id"], b64(inner.as_bytes()));

    // A chain one deeper than CXF allows is cut at the limit.
    let (_t, mut w) = wallet();
    let mut parent: Option<String> = None;
    for n in 0..=iwcore::cxf::COLLECTION_DEPTH_MAX {
        parent = Some(w.add_item(&format!("L{n}"), "folder", true, parent.as_deref()).unwrap());
    }
    let doc = w.export_cxf(&ExportOptions::default()).unwrap();
    let v: Value = serde_json::from_str(&doc).unwrap();
    let mut c = &v["accounts"][0]["collections"][0];
    let mut depth = 1;
    while let Some(sub) = c.get("subCollections") {
        c = &sub[0];
        depth += 1;
    }
    assert_eq!(depth, iwcore::cxf::COLLECTION_DEPTH_MAX);
    let (t2, mut fresh) = wallet();
    fresh.import_cxf(&doc, &opts(&t2)).unwrap();
}

/// A chosen folder takes everything below it, whatever the row order.
#[test]
fn export_scope_reaches_every_level() {
    let (_t, mut w) = wallet();
    // Rows are created child first, then moved under their parents.
    let deep = w.add_item("Deep", "document", false, None).unwrap();
    w.add_field(&deep, "NOTE", "deep", None).unwrap();
    let mid = w.add_item("Mid", "folder", true, None).unwrap();
    let top = w.add_item("Top", "folder", true, None).unwrap();
    w.move_item(&deep, &mid).unwrap();
    w.move_item(&mid, &top).unwrap();

    let doc = w.export_cxf(&ExportOptions { folder_ids: Some(vec![top]) }).unwrap();
    assert!(doc.contains("Deep"), "two levels below the chosen folder");
}

/// The import folder is named after the exporter, the export date and, when
/// there are several, the account.
#[test]
fn import_folder_names() {
    let names = |doc: Value| -> Vec<String> {
        let (t, mut w) = wallet();
        w.import_cxf(&doc.to_string(), &opts(&t)).unwrap();
        let mut n: Vec<String> = w.get_items().unwrap().iter().filter(|i| i.name.starts_with("Imported from")).map(|i| i.name.clone()).collect();
        n.sort();
        n
    };
    let note = |id: &str| json!({"id": id, "title": id, "credentials": [{"type": "note", "content": ef("string", id)}]});
    let account = |user: &str, email: &str, item: &str| json!({"id": item, "username": user, "email": email, "collections": [], "items": [note(item)]});
    let doc = |ts: u64, accounts: Vec<Value>| json!({"version": {"major": 1, "minor": 0}, "exporterRpId": "o.example",
        "exporterDisplayName": "Other", "timestamp": ts, "accounts": accounts});

    assert_eq!(names(doc(1_790_000_000, vec![account("me", "", "aQ")])), vec!["Imported from Other 2026-09-21".to_string()]);
    assert_eq!(names(doc(1_790_000_000, vec![account("me", "", "aQ"), account("", "you@example.com", "aR"), account("", "", "aS")])), vec![
        "Imported from Other 2026-09-21 (account 3)".to_string(),
        "Imported from Other 2026-09-21 (me)".to_string(),
        "Imported from Other 2026-09-21 (you@example.com)".to_string(),
    ]);
    // No timestamp: the date of the import.
    let undated = names(doc(0, vec![account("me", "", "aQ")]));
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    assert_eq!(undated, vec![format!("Imported from Other {today}")]);
}

/// The preview names the exporter and the folder the import lands in, and
/// counts every credential by kind.
#[test]
fn preview_reports_exporter_destination_and_exact_counts() {
    let (_t, mut w) = wallet();
    let (items, _) = rich_items();
    let preview = w.preview_cxf(&payload(items, vec![])).unwrap();
    assert_eq!(preview.exporter, "Other Manager");
    assert_eq!(preview.destination_folders, vec!["Imported from Other Manager 2026-09-21".to_string()]);
    assert_eq!(preview.counts, KindCounts { logins: 2, passkeys: 1, totp: 1, notes: 2, cards: 1, wifi: 1, other: 8 });

    let twice: Vec<Value> = rich_items().0.into_iter().chain(rich_items().0.into_iter().map(|mut i| {
        i["title"] = json!(format!("{} 2", i["title"].as_str().unwrap()));
        i
    })).collect();
    let preview = w.preview_cxf(&payload(twice, vec![])).unwrap();
    assert_eq!(preview.counts, KindCounts { logins: 4, passkeys: 2, totp: 2, notes: 4, cards: 2, wifi: 2, other: 16 });
}

/// Each Wi-Fi security type maps to its own `WIFI:` type.
#[test]
fn wifi_security_types_map_one_to_one() {
    let (t, mut w) = wallet();
    let wifi = |title: &str, sec: &str| json!({"id": title, "title": title, "credentials": [{"type": "wifi", "ssid": ef("string", title),
        "networkSecurityType": ef("wifi-network-security-type", sec), "passphrase": ef("concealed-string", "k")}]});
    w.import_cxf(&payload(vec![wifi("Open", "unsecured"), wifi("Old", "wep"), wifi("Home", "wpa2-personal")], vec![]), &opts(&t)).unwrap();
    assert!(has(&fields_of(&mut w, "Open"), "WIFI", "WIFI:T:nopass;S:Open;P:k;H:false;;"));
    assert!(has(&fields_of(&mut w, "Old"), "WIFI", "WIFI:T:WEP;S:Old;P:k;H:false;;"));
    assert!(has(&fields_of(&mut w, "Home"), "WIFI", "WIFI:T:WPA;S:Home;P:k;H:false;;"));
}

/// A `custom-fields` credential of exactly 256 fields is read; one more is skipped.
#[test]
fn custom_fields_limit_is_inclusive() {
    let (_t, mut w) = wallet();
    let doc = |n: usize| {
        let fields: Vec<Value> = (0..n).map(|i| json!({"fieldType": "string", "value": format!("v{i}"), "label": "Same"})).collect();
        payload(vec![json!({"id": "a", "title": "Many", "credentials": [{"type": "custom-fields", "fields": fields}]})], vec![])
    };
    let p = w.preview_cxf(&doc(iwcore::cxf::CUSTOM_FIELDS_MAX)).unwrap();
    assert!(p.skipped.is_empty());
    assert_eq!(p.counts.other, 1);
    let p = w.preview_cxf(&doc(iwcore::cxf::CUSTOM_FIELDS_MAX + 1)).unwrap();
    assert_eq!(p.skipped.len(), 1);
    assert_eq!(p.counts.other, 0);
}

/// A generated-password credential without a password is skipped, not counted.
#[test]
fn empty_generated_password_is_skipped() {
    let (_t, mut w) = wallet();
    let p = w.preview_cxf(&payload(vec![json!({"id": "a", "title": "Gen", "credentials": [{"type": "generated-password", "password": ""}]})], vec![])).unwrap();
    assert_eq!(p.counts.logins, 0);
    assert_eq!(p.skipped.len(), 1);
    assert_eq!(p.skipped[0].reason, "no password");
}

/// Exactly 200 new labels are accepted.
#[test]
fn exactly_200_new_labels_are_accepted() {
    let (_t, mut w) = wallet();
    let fields: Vec<Value> = (0..200).map(|i| json!({"fieldType": "string", "value": "v", "label": format!("L{i}")})).collect();
    let p = w.preview_cxf(&payload(vec![json!({"id": "a", "title": "Many", "credentials": [{"type": "custom-fields", "fields": fields}]})], vec![])).unwrap();
    assert_eq!(p.new_labels.len(), 200);
}

/// Custom labels already in the vault are reused, with their value type, and
/// not announced as new.
#[test]
fn existing_custom_labels_are_reused() {
    let (t, mut w) = wallet();
    let custom = |title: &str, v: &str| json!({"id": title, "title": title, "credentials": [{"type": "custom-fields", "fields": [
        {"fieldType": "string", "value": v, "label": "Favourite colour"},
        {"fieldType": "concealed-string", "value": v, "label": "Recovery code"},
        {"fieldType": "date", "value": "2026-12-24", "label": "Renewal"}]}]});
    let first = w.import_cxf(&payload(vec![custom("One", "a")], vec![]), &opts(&t)).unwrap();
    assert_eq!(first.preview.new_labels, vec!["Favourite colour".to_string(), "Recovery code".to_string(), "Renewal".to_string()]);

    let doc = payload(vec![custom("Two", "b")], vec![]);
    assert!(w.preview_cxf(&doc).unwrap().new_labels.is_empty());
    w.import_cxf(&doc, &opts(&t)).unwrap();
    let labels: Vec<(String, String)> = w.get_labels().unwrap().into_iter().filter(|l| !l.system).map(|l| (l.name, l.value_type)).collect();
    assert_eq!(labels, vec![
        ("Favourite colour".to_string(), "text".to_string()),
        ("Recovery code".to_string(), "pass".to_string()),
        ("Renewal".to_string(), "date".to_string()),
    ]);
    let two = fields_of(&mut w, "Two");
    let one = fields_of(&mut w, "One");
    for f in &two {
        assert!(one.iter().any(|o| o.field_type == f.field_type), "{} reuses the label", f.label);
    }
}

/// Only live items count as duplicates: a folder of the same name does not.
#[test]
fn folders_are_not_duplicates_of_items() {
    let (_t, mut w) = wallet();
    w.add_item("Work", "folder", true, None).unwrap();
    let p = w.preview_cxf(&payload(vec![json!({"id": "a", "title": "Work", "credentials": []})], vec![])).unwrap();
    assert_eq!((p.items, p.duplicates), (1, 0));
}

/// Fields keep the payload's order, 100 apart.
#[test]
fn imported_fields_are_weighted_in_order() {
    let (t, mut w) = wallet();
    w.import_cxf(&payload(vec![json!({"id": "a", "title": "Ordered", "credentials": [
        {"type": "basic-auth", "username": ef("string", "user"), "password": ef("concealed-string", "pw")},
        {"type": "note", "content": ef("string", "n")}]})], vec![]), &opts(&t)).unwrap();
    let mut weights: Vec<(i32, String)> = fields_of(&mut w, "Ordered").into_iter().map(|f| (f.sort_weight, f.field_type)).collect();
    weights.sort();
    assert_eq!(weights, vec![(0, "USER".to_string()), (100, "PASS".to_string()), (200, "NOTE".to_string())]);
}

/// A document member that starts with a capital keeps it in the label.
#[test]
fn capitalised_document_member_keeps_its_label() {
    let (t, mut w) = wallet();
    w.import_cxf(&payload(vec![json!({"id": "a", "title": "Doc", "credentials": [
        {"type": "identity-document", "documentNumber": ef("string", "1"), "XRef": ef("string", "r")}]})], vec![]), &opts(&t)).unwrap();
    assert!(has_label(&fields_of(&mut w, "Doc"), "X ref", "r"));
}
