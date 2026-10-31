//! Passkeys inside the vault.
//!
//! A `PKEY` field's stored value is the full [`PasskeyRecord`], private key and
//! PRF secrets included. That value never leaves through the public field API:
//! `get_fields`, `get_fields_by_item`, `get_deleted_fields` and `search` show a
//! `PKEY` field's **public value** instead, a JSON summary without any secret
//! ([`public_value`]). The full records sit in a separate cache that only the
//! crate's passkey, AutoFill and CXF code read.

use serde_json::json;
use zeroize::Zeroizing;

use super::record::{PasskeyRecord, PasskeySummary};
use super::{b64, FIELD_PASSKEY};
use crate::business::Wallet;
use crate::error::Result;

/// The secret-free JSON that stands in for a `PKEY` value in the public field
/// API. An unreadable record becomes `{"v":1,"type":"passkey","unreadable":true}`
/// rather than an error, so one damaged field never breaks a listing.
pub fn public_value(stored: &str) -> String {
    match PasskeyRecord::from_field_value(stored) {
        Ok(r) => json!({
            "v": 1,
            "type": "passkey",
            "credentialId": b64::encode(&r.credential_id),
            "rpId": r.rp_id,
            "userName": r.user_name,
            "userDisplayName": r.user_display_name,
            "userHandle": b64::encode(&r.user_handle),
            "createdAt": r.created_at,
            "hasPrf": r.prf().is_some(),
        })
        .to_string(),
        Err(_) => json!({ "v": 1, "type": "passkey", "unreadable": true }).to_string(),
    }
}

/// One line for exports and shared text: `Passkey · github.com · bkv`.
pub fn display_text(public: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(public).unwrap_or_default();
    match (v.get("rpId").and_then(|x| x.as_str()), v.get("userName").and_then(|x| x.as_str())) {
        (Some(rp), Some(user)) if !user.is_empty() => format!("Passkey · {rp} · {user}"),
        (Some(rp), _) => format!("Passkey · {rp}"),
        _ => "Passkey (unreadable)".to_string(),
    }
}

impl Wallet {
    /// Every passkey on a live item, without any secret.
    pub fn list_passkeys(&mut self) -> Result<Vec<PasskeySummary>> {
        Ok(self
            .live_passkeys()?
            .into_iter()
            .map(|(item, field, record)| record.summary(&item, &field))
            .collect())
    }

    /// One passkey's summary, `None` if the field is not a readable passkey.
    pub fn passkey_summary(&mut self, item_id: &str, field_id: &str) -> Result<Option<PasskeySummary>> {
        Ok(self.passkey_record(item_id, field_id)?.map(|r| r.summary(item_id, field_id)))
    }

    /// The full record of one `PKEY` field, live or trashed.
    pub(crate) fn passkey_record(&mut self, item_id: &str, field_id: &str) -> Result<Option<PasskeyRecord>> {
        self.load_fields_if_needed()?;
        Ok(self
            .passkey_values
            .get(&(item_id.to_string(), field_id.to_string()))
            .and_then(|stored| PasskeyRecord::from_field_value(stored).ok()))
    }

    /// The stored value of one `PKEY` field, for moving it verbatim.
    pub(crate) fn passkey_stored_value(&mut self, item_id: &str, field_id: &str) -> Result<Option<Zeroizing<String>>> {
        self.load_fields_if_needed()?;
        Ok(self.passkey_values.get(&(item_id.to_string(), field_id.to_string())).cloned())
    }

    /// `(item_id, field_id, record)` for every readable passkey on a live item.
    /// Unreadable records are skipped: one damaged field must not hide the rest.
    pub(crate) fn live_passkeys(&mut self) -> Result<Vec<(String, String, PasskeyRecord)>> {
        let live_items: std::collections::HashSet<String> = self
            .get_items()?
            .iter()
            .filter(|i| !i.deleted && !i.folder)
            .map(|i| i.item_id.clone())
            .collect();
        let pkey_fields: Vec<(String, String)> = self
            .get_fields()?
            .iter()
            .filter(|f| f.field_type == FIELD_PASSKEY && !f.deleted && live_items.contains(&f.item_id))
            .map(|f| (f.item_id.clone(), f.field_id.clone()))
            .collect();
        let mut out = Vec::with_capacity(pkey_fields.len());
        for (item, field) in pkey_fields {
            if let Some(record) = self.passkey_record(&item, &field)? {
                out.push((item, field, record));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::record::tests::sample;

    #[test]
    fn public_value_carries_no_secret() {
        let r = sample(true);
        let stored = r.to_field_value().unwrap();
        let public = public_value(&stored);
        let key = b64::encode(r.pkcs8());
        assert!(!public.contains(&key));
        assert!(!public.contains(&b64::encode(&[7u8; 32])), "no PRF secret");
        let v: serde_json::Value = serde_json::from_str(&public).unwrap();
        assert_eq!(v["rpId"], "github.com");
        assert_eq!(v["hasPrf"], true);
        assert_eq!(v["type"], "passkey");
    }

    #[test]
    fn unreadable_records_get_a_marker() {
        let public = public_value("{\"v\":1,\"key\":\"secretish\"}");
        assert!(!public.contains("secretish"));
        assert_eq!(display_text(&public), "Passkey (unreadable)");
    }

    #[test]
    fn display_text_forms() {
        let r = sample(false);
        assert_eq!(display_text(&public_value(&r.to_field_value().unwrap())), "Passkey · github.com · bkv");
        assert_eq!(display_text(r#"{"rpId":"a.example","userName":""}"#), "Passkey · a.example");
        assert_eq!(display_text("garbage"), "Passkey (unreadable)");
    }

    // --- the vault guards (catalog H1–H6) ------------------------------------

    use crate::business::wallet::tests::create_test_wallet;
    use crate::passkey::record::PasskeyRecord;

    const KEY_FRAGMENT_LEN: usize = 12;

    /// A wallet with one login holding a password and a passkey with PRF.
    fn wallet_with_passkey() -> (Wallet, tempfile::TempDir, String, String, PasskeyRecord) {
        let (mut w, t) = create_test_wallet();
        let item = w.add_item("GitHub", "web", false, None).unwrap();
        w.add_field(&item, "USER", "bkv", Some(0)).unwrap();
        w.add_field(&item, "PASS", "pw-123", Some(1)).unwrap();
        let record = sample(true);
        let field = w
            .add_field_unchecked(&item, FIELD_PASSKEY, &record.to_field_value().unwrap(), Some(2))
            .unwrap();
        (w, t, item, field, record)
    }

    /// Every encoding of every secret of `record` that could leak.
    fn secrets(record: &PasskeyRecord) -> Vec<String> {
        let key = b64::encode(record.pkcs8());
        let prf = record.prf().unwrap();
        vec![
            key[key.len() / 2..key.len() / 2 + KEY_FRAGMENT_LEN].to_string(),
            b64::encode(&prf.with_uv[..]),
            b64::encode(&prf.without_uv[..]),
            record.pkcs8().iter().map(|b| format!("{b:02x}")).collect(),
        ]
    }

    fn assert_no_secret(what: &str, text: &str, record: &PasskeyRecord) {
        for s in secrets(record) {
            assert!(!text.contains(&s), "{what} contains secret material");
        }
    }

    #[test]
    fn public_field_api_never_returns_the_key() {
        let (mut w, _t, item, field, record) = wallet_with_passkey();
        let all_fields = format!("{:?}", w.get_fields().unwrap());
        let by_item = format!("{:?}", w.get_fields_by_item(&item).unwrap());
        let all = all_fields + &by_item;
        let values: String = w.get_fields().unwrap().iter().map(|f| f.value.clone()).collect();
        assert_no_secret("get_fields", &(all + &values), &record);
        let pkey = w.get_fields_by_item(&item).unwrap().into_iter().find(|f| f.field_id == field).unwrap();
        assert_eq!(pkey.value_type, "pass", "older apps mask it");
        let v: serde_json::Value = serde_json::from_str(&pkey.value).unwrap();
        assert_eq!(v["rpId"], "github.com");
        // The full record is still there for the crate.
        let back = w.passkey_record(&item, &field).unwrap().unwrap();
        assert_eq!(back.pkcs8(), record.pkcs8());
    }

    #[test]
    fn list_and_summary() {
        let (mut w, _t, item, field, _record) = wallet_with_passkey();
        let list = w.list_passkeys().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].item_id.as_str(), list[0].field_id.as_str()), (item.as_str(), field.as_str()));
        assert_eq!(list[0].rp_id, "github.com");
        assert!(list[0].has_prf);
        assert_eq!(w.passkey_summary(&item, &field).unwrap().unwrap().user_name, "bkv");
        assert!(w.passkey_summary(&item, "none").unwrap().is_none());
        // Trashed field or item: not listed.
        w.delete_field(&item, &field).unwrap();
        assert!(w.list_passkeys().unwrap().is_empty());
        w.undelete_field(&item, &field).unwrap();
        assert_eq!(w.list_passkeys().unwrap().len(), 1, "undelete brings it back intact");
        w.delete_item(&item).unwrap();
        assert!(w.list_passkeys().unwrap().is_empty());
    }

    #[test]
    fn deleted_fields_do_not_return_the_key() {
        let (mut w, _t, item, field, record) = wallet_with_passkey();
        w.delete_field(&item, &field).unwrap();
        let deleted = w.get_deleted_fields().unwrap();
        let text: String = deleted.iter().map(|f| format!("{}{f:?}", f.value)).collect();
        assert!(deleted.iter().any(|f| f.field_type == FIELD_PASSKEY));
        assert_no_secret("get_deleted_fields", &text, &record);
    }

    #[test]
    fn search_matches_site_and_user_but_never_the_key() {
        let (mut w, _t, _item, _field, record) = wallet_with_passkey();
        let hits = |w: &mut Wallet, q: &str| {
            w.search(q).unwrap().iter().flat_map(|r| r.matching_fields.clone())
                .filter(|f| f.field_type == FIELD_PASSKEY).count()
        };
        assert_eq!(hits(&mut w, "github"), 1);
        assert_eq!(hits(&mut w, "B K V"), 1, "display name");
        for s in secrets(&record) {
            assert_eq!(hits(&mut w, &s[..8.min(s.len())]), 0);
        }
        assert_eq!(hits(&mut w, "credentialId"), 0, "JSON keys are not searchable");
        assert_eq!(hits(&mut w, "hasPrf"), 0);
    }

    #[test]
    fn public_writes_refuse_passkeys() {
        let (mut w, _t, item, field, record) = wallet_with_passkey();
        let stored = record.to_field_value().unwrap();
        assert!(w.add_field(&item, FIELD_PASSKEY, &stored, None).is_err());
        assert!(w.update_field(&field, "{}", None).is_err());
        assert!(w.copy_field(&item, &field, &item).is_err());
        assert_eq!(w.list_passkeys().unwrap().len(), 1, "nothing changed");
        // Other fields are unaffected by the guard.
        w.add_field(&item, "NOTE", "fine", None).unwrap();
    }

    #[test]
    fn copy_item_skips_passkeys_and_move_field_keeps_them_unique() {
        let (mut w, _t, item, field, record) = wallet_with_passkey();
        let copy = w.copy_item(&item).unwrap();
        let copied = w.get_fields_by_item(&copy).unwrap();
        assert!(copied.iter().all(|f| f.field_type != FIELD_PASSKEY));
        assert!(copied.iter().any(|f| f.field_type == "PASS"), "the rest is copied");
        assert_eq!(w.list_passkeys().unwrap().len(), 1);

        let target = w.add_item("Other", "web", false, None).unwrap();
        w.move_field(&item, &field, &target).unwrap();
        let list = w.list_passkeys().unwrap();
        assert_eq!(list.len(), 1, "moved, not duplicated");
        assert_eq!(list[0].item_id, target);
        let moved = w.passkey_record(&list[0].item_id, &list[0].field_id).unwrap().unwrap();
        assert_eq!(moved.pkcs8(), record.pkcs8(), "moved with its key");
    }

    #[test]
    fn top_values_never_offer_passkeys() {
        let (mut w, _t, ..) = wallet_with_passkey();
        assert!(w.get_top_field_values_by_type(FIELD_PASSKEY, 10).unwrap().is_empty());
    }

    #[test]
    fn exports_show_one_line_and_no_secret() {
        let (mut w, _t, _item, _field, record) = wallet_with_passkey();
        let outputs = [
            String::from_utf8(w.export_csv().unwrap()).unwrap(),
            String::from_utf8(w.export_json().unwrap()).unwrap(),
            String::from_utf8(w.export_xml().unwrap()).unwrap(),
        ];
        for out in &outputs {
            assert_no_secret("export", out, &record);
            assert!(out.contains("Passkey · github.com · bkv"));
        }
        // The PDF compresses its text; it is built from the same export fields.
        assert!(w.export_pdf().unwrap().starts_with(b"%PDF"));
    }

    #[test]
    fn passkeys_survive_a_password_change_and_still_sign() {
        let (mut w, _t, item, field, _record) = wallet_with_passkey();
        assert!(w.change_password("new-password-1").unwrap());
        w.lock();
        assert!(w.list_passkeys().is_err(), "locked");
        assert!(w.unlock("new-password-1").unwrap());
        let r = w.passkey_record(&item, &field).unwrap().unwrap();
        crate::passkey::sign::assert(&r, "github.com", &[1; 32], true).unwrap();
    }

    #[test]
    fn a_damaged_record_is_listed_as_unreadable_and_skipped() {
        let (mut w, _t, item, ..) = wallet_with_passkey();
        w.add_field_unchecked(&item, FIELD_PASSKEY, "{\"v\":1,\"broken\":true}", None).unwrap();
        assert_eq!(w.list_passkeys().unwrap().len(), 1, "the good one still lists");
        let unreadable = w.get_fields_by_item(&item).unwrap().into_iter()
            .filter(|f| f.value.contains("unreadable")).count();
        assert_eq!(unreadable, 1);
    }
}

