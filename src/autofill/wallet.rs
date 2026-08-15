//! Vault-facing autofill operations: building the index, draining the journal.
//!
//! Both run on the app side with the vault unlocked. Neither is reachable from
//! the autofill provider, which never opens the vault at all.
//!
//! Everything here is additive to the vault format. Drained records become
//! ordinary items with ordinary field types, indistinguishable from ones the
//! user typed by hand apart from the folder they land in, so an older build or
//! the CLI reads them without knowing autofill exists.

use crate::business::Wallet;
use crate::error::{Result, WalletError};

use super::index::{self, IndexHeader, IndexOptions};
use super::journal::{self, PendingOp, PendingRecord};
use super::{AUTOFILL_FOLDER_NAME, FIELD_LINK, FIELD_OLD_PASSWORD, FIELD_PASSWORD, FIELD_TOTP};

/// Outcome of one drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainSummary {
    /// Item id of the `AutoFill` folder used. The app stores this so the folder
    /// keeps working after the user renames it.
    pub folder_id: String,
    /// Items created, in import order.
    pub created: Vec<String>,
    /// Items whose password was updated.
    pub updated: Vec<String>,
    /// Records that could not be applied at all.
    pub skipped: usize,
}

impl Wallet {
    /// Build a sealed autofill index from the current vault contents.
    ///
    /// The plaintext credential set never leaves Rust: callers get sealed bytes
    /// and write them to disk, so no password or TOTP secret ever materializes
    /// as a Dart string.
    pub fn build_autofill_index(
        &mut self,
        index_key: &[u8; super::crypto::KEY_LEN],
        generation: u64,
        built_at: i64,
        options: IndexOptions,
    ) -> Result<Vec<u8>> {
        self.ensure_unlocked()?;

        let database_id = self
            .get_properties()?
            .database_id;

        let items = self.get_items()?.to_vec();
        let fields = self.get_fields()?.to_vec();
        let entries = index::entries_from_vault(&items, &fields, options);

        index::build(
            &entries,
            index_key,
            &IndexHeader {
                format_version: index::FORMAT_VERSION,
                generation,
                built_at,
                database_id,
            },
        )
    }

    /// Import staged logins from the journal into the vault.
    ///
    /// Uses the app-private journal key, so it works regardless of whether the
    /// index key has since been rotated or invalidated. Deduplicates by
    /// `record_id`, so a crash between writing an item and deleting the journal
    /// cannot double-import on the next attempt.
    ///
    /// `folder_id` is the previously recorded `AutoFill` folder. Pass `None` on
    /// the first drain, or when the recorded folder no longer exists; a fresh
    /// one is then created and returned.
    pub fn drain_autofill_journal(
        &mut self,
        journal_bytes: &[u8],
        journal_secret: &[u8; 32],
        folder_id: Option<&str>,
    ) -> Result<DrainSummary> {
        self.ensure_unlocked()?;

        let records = journal::dedupe(journal::open_with_journal_key(journal_bytes, journal_secret));
        let folder = self.resolve_autofill_folder(folder_id)?;

        let mut summary = DrainSummary {
            folder_id: folder.clone(),
            created: Vec::new(),
            updated: Vec::new(),
            skipped: 0,
        };

        for record in records {
            let applied = match record.op {
                PendingOp::UpdatePassword => self.apply_password_update(&record)?,
                PendingOp::Create => None,
            };

            match applied {
                Some(item_id) => summary.updated.push(item_id),
                // A create, or an update naming an item that no longer exists:
                // degrade to a create rather than dropping the record, since
                // the password itself is still the user's.
                None => match self.create_from_record(&record, &folder) {
                    Ok(item_id) => summary.created.push(item_id),
                    Err(_) => summary.skipped += 1,
                },
            }
        }

        Ok(summary)
    }

    /// Find the `AutoFill` folder, by recorded id first and by name second,
    /// creating it only when neither finds one.
    fn resolve_autofill_folder(&mut self, folder_id: Option<&str>) -> Result<String> {
        if let Some(id) = folder_id
            && let Some(item) = self.get_item(id)?
            && item.folder
            && !item.deleted
        {
            return Ok(item.item_id);
        }

        let existing = self
            .get_items()?
            .iter()
            .find(|i| i.folder && !i.deleted && i.name == AUTOFILL_FOLDER_NAME)
            .map(|i| i.item_id.clone());
        if let Some(id) = existing {
            return Ok(id);
        }

        self.add_item(AUTOFILL_FOLDER_NAME, "", true, Some(crate::ROOT_ID))
    }

    /// Apply a password change to an existing item. Returns `None` when the
    /// target item or its password field is gone, so the caller can fall back
    /// to creating a new entry.
    fn apply_password_update(&mut self, record: &PendingRecord) -> Result<Option<String>> {
        let Some(item_id) = record.item_id.as_deref() else {
            return Ok(None);
        };
        match self.get_item(item_id)? {
            Some(item) if !item.deleted && !item.folder => {}
            _ => return Ok(None),
        }

        let fields = self.get_fields_by_item(item_id)?;
        let Some(pass) = fields
            .iter()
            .filter(|f| !f.deleted && f.field_type == FIELD_PASSWORD)
            .min_by_key(|f| f.sort_weight)
        else {
            return Ok(None);
        };
        let (pass_field_id, old_value) = (pass.field_id.clone(), pass.value.clone());

        // `update_field` copies the outgoing PASS ciphertext into OLDP, but
        // only when an OLDP field already exists. Create one first so the
        // previous password is never silently lost.
        let has_oldp = fields
            .iter()
            .any(|f| !f.deleted && f.field_type == FIELD_OLD_PASSWORD);
        if !has_oldp {
            self.add_field(item_id, FIELD_OLD_PASSWORD, &old_value, None)?;
        }

        self.update_field(&pass_field_id, &record.password, None)?;
        Ok(Some(item_id.to_string()))
    }

    /// Create a new login item from a staged record.
    fn create_from_record(&mut self, record: &PendingRecord, folder_id: &str) -> Result<String> {
        if record.password.is_empty() {
            return Err(WalletError::InvalidOperation(
                "staged record has no password".into(),
            ));
        }

        let title = if record.title.trim().is_empty() {
            super::domain::normalize_host(&record.url).unwrap_or_else(|| "Login".to_string())
        } else {
            record.title.clone()
        };

        let item_id = self.add_item(&title, "", false, Some(folder_id))?;

        // Exactly one identity field, chosen by the hint when it names a real
        // identity type and by the classifier otherwise.
        if !record.identity_value.trim().is_empty() {
            let kind = record.identity_kind();
            self.add_field(&item_id, kind.field_type(), &record.identity_value, Some(0))?;
        }
        self.add_field(&item_id, FIELD_PASSWORD, &record.password, Some(100))?;
        if !record.url.trim().is_empty() {
            self.add_field(&item_id, FIELD_LINK, &record.url, Some(200))?;
        }
        if let Some(totp) = record.totp_secret.as_deref().filter(|s| !s.trim().is_empty()) {
            self.add_field(&item_id, FIELD_TOTP, totp, Some(300))?;
        }

        Ok(item_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autofill::identity::IdentityKind;
    use crate::autofill::keys::generate_keys;
    use tempfile::TempDir;

    fn wallet() -> (Wallet, TempDir) {
        let dir = TempDir::new().unwrap();
        let wallet = Wallet::create(dir.path(), "test-password", "en").unwrap();
        (wallet, dir)
    }

    fn record(id: &str, identity: &str) -> PendingRecord {
        PendingRecord {
            record_id: id.to_string(),
            op: PendingOp::Create,
            item_id: None,
            title: "Example".into(),
            url: "https://example.com/signup".into(),
            identity_value: identity.into(),
            identity_hint: None,
            password: "hunter2".into(),
            totp_secret: None,
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn index_of_a_real_vault_round_trips() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let item = w.add_item("GitHub", "", false, Some(crate::ROOT_ID)).unwrap();
        w.add_field(&item, "USER", "bkv", Some(0)).unwrap();
        w.add_field(&item, "PASS", "hunter2", Some(100)).unwrap();
        w.add_field(&item, "LINK", "https://github.com/login", Some(200)).unwrap();

        let sealed = w
            .build_autofill_index(&keys.index_key, 1, 1_700_000_000, IndexOptions::default())
            .unwrap();
        let (header, entries) = index::open(&sealed, &keys.index_key).unwrap();

        assert_eq!(header.generation, 1);
        assert_eq!(header.database_id, w.get_properties().unwrap().database_id);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(entries[0].identity_type, "USER");
        assert_eq!(entries[0].username, "bkv");
        assert_eq!(entries[0].password, "hunter2");
        assert_eq!(entries[0].hosts, vec!["github.com"]);
    }

    #[test]
    fn a_locked_wallet_cannot_build_an_index() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        w.lock();
        assert!(matches!(
            w.build_autofill_index(&keys.index_key, 1, 0, IndexOptions::default()),
            Err(WalletError::Locked)
        ));
    }

    #[test]
    fn drain_creates_items_in_the_autofill_folder() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let mut journal = Vec::new();
        for r in [record("r1", "bkv"), record("r2", "a@bkv.me")] {
            journal.extend_from_slice(
                &journal::seal_record(&r, &keys.journal_public, &keys.index_key).unwrap(),
            );
        }

        let summary = w
            .drain_autofill_journal(&journal, &keys.journal_secret, None)
            .unwrap();
        assert_eq!(summary.created.len(), 2);
        assert_eq!(summary.skipped, 0);

        let folder = w.get_item(&summary.folder_id).unwrap().unwrap();
        assert_eq!(folder.name, AUTOFILL_FOLDER_NAME);
        assert!(folder.folder);

        for item_id in &summary.created {
            let item = w.get_item(item_id).unwrap().unwrap();
            assert_eq!(item.parent_id.as_deref(), Some(summary.folder_id.as_str()));
        }
    }

    #[test]
    fn drained_items_carry_exactly_one_identity_field() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let cases = [
            ("bkv", IdentityKind::User),
            ("a@bkv.me", IdentityKind::Mail),
            ("1234567890", IdentityKind::Account),
        ];
        let mut journal = Vec::new();
        for (i, (value, _)) in cases.iter().enumerate() {
            journal.extend_from_slice(
                &journal::seal_record(
                    &record(&format!("r{i}"), value),
                    &keys.journal_public,
                    &keys.index_key,
                )
                .unwrap(),
            );
        }

        let summary = w
            .drain_autofill_journal(&journal, &keys.journal_secret, None)
            .unwrap();

        for (item_id, (_, expected)) in summary.created.iter().zip(cases.iter()) {
            let fields = w.get_fields_by_item(item_id).unwrap();
            let identity: Vec<&str> = fields
                .iter()
                .filter(|f| !f.deleted)
                .map(|f| f.field_type.as_str())
                .filter(|t| matches!(*t, "MAIL" | "USER" | "ACNT"))
                .collect();
            assert_eq!(identity.len(), 1, "exactly one identity field");
            assert_eq!(identity[0], expected.field_type());

            let types: Vec<&str> = fields
                .iter()
                .filter(|f| !f.deleted)
                .map(|f| f.field_type.as_str())
                .collect();
            assert_eq!(types.len(), 3, "identity + PASS + LINK, nothing else");
            assert!(types.contains(&"PASS"));
            assert!(types.contains(&"LINK"));
        }
    }

    #[test]
    fn drain_is_idempotent_across_a_simulated_crash() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let journal =
            journal::seal_record(&record("r1", "bkv"), &keys.journal_public, &keys.index_key)
                .unwrap();

        // First drain succeeds, then the process dies before the journal is
        // deleted, so the same bytes are drained again.
        let first = w
            .drain_autofill_journal(&journal, &keys.journal_secret, None)
            .unwrap();
        let mut doubled = journal.clone();
        doubled.extend_from_slice(&journal);
        let second = w
            .drain_autofill_journal(&doubled, &keys.journal_secret, Some(&first.folder_id))
            .unwrap();

        assert_eq!(first.created.len(), 1);
        assert_eq!(
            second.created.len(),
            1,
            "the repeated record_id must collapse to a single import"
        );
        assert_eq!(second.folder_id, first.folder_id, "folder is reused");
    }

    #[test]
    fn the_folder_is_reused_by_id_after_a_rename() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let journal =
            journal::seal_record(&record("r1", "bkv"), &keys.journal_public, &keys.index_key)
                .unwrap();

        let first = w
            .drain_autofill_journal(&journal, &keys.journal_secret, None)
            .unwrap();
        w.update_item_name(&first.folder_id, "My logins").unwrap();

        let journal2 =
            journal::seal_record(&record("r2", "bkv"), &keys.journal_public, &keys.index_key)
                .unwrap();
        let second = w
            .drain_autofill_journal(&journal2, &keys.journal_secret, Some(&first.folder_id))
            .unwrap();

        assert_eq!(second.folder_id, first.folder_id);
    }

    #[test]
    fn a_deleted_folder_is_recreated_without_duplicating() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let journal =
            journal::seal_record(&record("r1", "bkv"), &keys.journal_public, &keys.index_key)
                .unwrap();

        let first = w
            .drain_autofill_journal(&journal, &keys.journal_secret, None)
            .unwrap();
        w.delete_item(&first.folder_id).unwrap();

        let journal2 =
            journal::seal_record(&record("r2", "bkv"), &keys.journal_public, &keys.index_key)
                .unwrap();
        let second = w
            .drain_autofill_journal(&journal2, &keys.journal_secret, Some(&first.folder_id))
            .unwrap();

        assert_ne!(second.folder_id, first.folder_id);
        let folders: Vec<_> = w
            .get_items()
            .unwrap()
            .iter()
            .filter(|i| i.folder && !i.deleted && i.name == AUTOFILL_FOLDER_NAME)
            .collect();
        assert_eq!(folders.len(), 1);
    }

    #[test]
    fn password_update_preserves_the_old_password_in_oldp() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let item = w.add_item("GitHub", "", false, Some(crate::ROOT_ID)).unwrap();
        w.add_field(&item, "USER", "bkv", Some(0)).unwrap();
        w.add_field(&item, "PASS", "old-password", Some(100)).unwrap();

        let mut update = record("r1", "bkv");
        update.op = PendingOp::UpdatePassword;
        update.item_id = Some(item.clone());
        update.password = "new-password".into();
        let journal =
            journal::seal_record(&update, &keys.journal_public, &keys.index_key).unwrap();

        let summary = w
            .drain_autofill_journal(&journal, &keys.journal_secret, None)
            .unwrap();
        assert_eq!(summary.updated, vec![item.clone()]);
        assert!(summary.created.is_empty());

        let fields = w.get_fields_by_item(&item).unwrap();
        let pass = fields
            .iter()
            .find(|f| !f.deleted && f.field_type == "PASS")
            .unwrap();
        let oldp = fields
            .iter()
            .find(|f| !f.deleted && f.field_type == "OLDP")
            .unwrap();
        assert_eq!(pass.value, "new-password");
        assert_eq!(oldp.value, "old-password");
    }

    #[test]
    fn a_password_update_for_a_missing_item_degrades_to_a_create() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let mut update = record("r1", "bkv");
        update.op = PendingOp::UpdatePassword;
        update.item_id = Some("does-not-exist".into());
        let journal =
            journal::seal_record(&update, &keys.journal_public, &keys.index_key).unwrap();

        let summary = w
            .drain_autofill_journal(&journal, &keys.journal_secret, None)
            .unwrap();
        assert!(summary.updated.is_empty());
        assert_eq!(summary.created.len(), 1, "the password is not thrown away");
    }

    /// The invariant tying both halves together: an entry that leaves through
    /// the index and comes back through the journal keeps its shape.
    #[test]
    fn an_entry_round_trips_out_through_the_index_and_back_through_the_journal() {
        let (mut source, _a) = wallet();
        let (mut target, _b) = wallet();
        let keys = generate_keys().unwrap();

        let item = source.add_item("Example", "", false, Some(crate::ROOT_ID)).unwrap();
        source.add_field(&item, "MAIL", "a@bkv.me", Some(0)).unwrap();
        source.add_field(&item, "PASS", "hunter2", Some(100)).unwrap();
        source.add_field(&item, "LINK", "https://example.com/login", Some(200)).unwrap();

        // Out through the index.
        let sealed = source
            .build_autofill_index(&keys.index_key, 1, 0, IndexOptions::default())
            .unwrap();
        let (_, entries) = index::open(&sealed, &keys.index_key).unwrap();
        let exported = entries.into_iter().next().unwrap();

        // Back through the journal.
        let staged = PendingRecord {
            record_id: "r1".into(),
            op: PendingOp::Create,
            item_id: None,
            title: exported.title.clone(),
            url: "https://example.com/login".into(),
            identity_value: exported.username.clone(),
            identity_hint: Some(exported.identity_type.clone()),
            password: exported.password.clone(),
            totp_secret: None,
            created_at: 0,
        };
        let journal =
            journal::seal_record(&staged, &keys.journal_public, &keys.index_key).unwrap();
        let summary = target
            .drain_autofill_journal(&journal, &keys.journal_secret, None)
            .unwrap();

        // Re-export from the target and compare the shape.
        let sealed2 = target
            .build_autofill_index(&keys.index_key, 1, 0, IndexOptions::default())
            .unwrap();
        let (_, entries2) = index::open(&sealed2, &keys.index_key).unwrap();
        let reimported = entries2.into_iter().next().unwrap();

        assert_eq!(summary.created.len(), 1);
        assert_eq!(reimported.identity_type, exported.identity_type);
        assert_eq!(reimported.username, exported.username);
        assert_eq!(reimported.password, exported.password);
        assert_eq!(reimported.title, exported.title);
        assert_eq!(reimported.hosts, exported.hosts);
        assert_eq!(reimported.registrable, exported.registrable);
    }

    #[test]
    fn a_garbage_journal_drains_to_nothing_without_creating_a_folder_full_of_junk() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let summary = w
            .drain_autofill_journal(b"not a journal", &keys.journal_secret, None)
            .unwrap();
        assert!(summary.created.is_empty());
        assert!(summary.updated.is_empty());
        assert_eq!(summary.skipped, 0);
    }
}
