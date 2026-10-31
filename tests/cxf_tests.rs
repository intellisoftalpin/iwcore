//! CXF import and export through the public API.
//!
//! The payload below is written from the CXF 1.0 specification's structure
//! (Proposed Standard, errata 2026-03-09) and carries every credential type.

use std::collections::BTreeSet;

use iwcore::cxf::export::ExportOptions;
use iwcore::cxf::import::ImportOptions;
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
