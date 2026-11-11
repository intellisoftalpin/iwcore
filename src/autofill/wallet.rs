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
use crate::passkey::{PasskeySummary, FIELD_PASSKEY};

use super::index::{self, IndexHeader, IndexOptions};
use super::journal::{self, DrainKeys, PendingOp, PendingRecord};
use super::{AUTOFILL_FOLDER_NAME, FIELD_LINK, FIELD_OLD_PASSWORD, FIELD_PASSWORD, FIELD_TOTP};

/// Outcome of one drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainSummary {
    /// Item id of the `AutoFill` folder used. The app stores this so the folder
    /// keeps working after the user renames it.
    pub folder_id: String,
    /// Items created, in import order.
    pub created: Vec<String>,
    /// Items whose password was updated, or that received a passkey.
    pub updated: Vec<String>,
    /// Records that named a login the vault already held, with the same
    /// password, and were therefore dropped. A re-capture of something the user
    /// already has is not news and must not become a second item.
    pub unchanged: usize,
    /// Records that could not be applied at all.
    pub skipped: usize,
    /// Staged passkeys added to the vault (on a matching login or a new item).
    pub passkeys_added: usize,
    /// Staged passkeys that would replace a live passkey for the same site and
    /// account. None of them has replaced anything: each is stored in the
    /// trash, on the item of the passkey it would replace, until the user
    /// confirms with [`Wallet::confirm_passkey_replacement`].
    pub pending_replacements: Vec<PasskeyReplacement>,
    /// Well-framed records refused because they could not prove they were
    /// written by the provider (see [`journal::open_for_drain`]). Never
    /// applied. Nonzero means the journal was written by something else, or
    /// tagged under a key from before a rotation.
    pub unauthenticated: usize,
    /// Authenticated records an earlier drain already applied, so not
    /// applied again (see [`Wallet::drain_autofill_journal`]). Nonzero after
    /// a crash between a drain and deleting the journal, or when old journal
    /// bytes come back.
    pub already_applied: usize,
    /// Bytes at the end of the journal the drain could not read as records
    /// (see [`journal::DrainRead::unparsed_bytes`]). Nonzero means records
    /// may have been lost to this drain: keep the journal instead of deleting
    /// it.
    pub unparsed_bytes: usize,
}

/// A staged passkey waiting for the user to confirm that it replaces a live
/// one. Both summaries name the same item; neither carries a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyReplacement {
    /// The live passkey that stays in use until the user confirms.
    pub existing: PasskeySummary,
    /// The staged passkey, held in the trash meanwhile.
    pub staged: PasskeySummary,
}

/// What became of one staged passkey.
enum PasskeyOutcome {
    AlreadyThere,
    /// Applied by an earlier drain and no longer in the vault: not added again.
    AlreadyApplied,
    NeedsConfirmation(Box<PasskeyReplacement>),
    AttachedTo(String),
    Created(String),
    Invalid,
}

/// A passkey in the trash, identified without its secrets.
struct TrashedPasskey {
    item_id: String,
    field_id: String,
    credential_id: Vec<u8>,
    rp_id: String,
    user_handle: Vec<u8>,
}

/// What an unattributed create record turned out to be, once the vault could be
/// consulted. See [`Wallet::drain_autofill_journal`].
enum Match {
    /// The vault already holds this login with this password.
    Same,
    /// The vault already holds this login with a different password. Carries
    /// the item to update.
    PasswordChanged(String),
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
        let passkeys = self.passkey_index_entries(&items)?;

        index::build_with_passkeys(
            &entries,
            &passkeys,
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
    /// index key has since been rotated or invalidated.
    ///
    /// Each record is applied at most once per vault. The vault remembers the
    /// `record_id` of every record it applied (bounded, with a `created_at`
    /// floor for ids it no longer keeps), in the same transaction as the
    /// drain, and skips them on any later drain: a crash between writing an
    /// item and deleting the journal cannot double-import, and journal bytes
    /// that come back later cannot undo a change made since. Such records are
    /// counted in [`DrainSummary::already_applied`]. A staged passkey still
    /// waiting in the trash for confirmation is reported again, so the
    /// question is not lost.
    ///
    /// Records are applied in `created_at` order (file order among equal
    /// times), so of two captures for the same login the later one wins.
    ///
    /// Applies only records that prove they were written by the provider: a
    /// valid tag under `keys.auth_key`, or for legacy records a provider wrap
    /// under one of `keys.legacy_wrap_keys`. The rest are counted in
    /// [`DrainSummary::unauthenticated`] and left alone.
    ///
    /// `folder_id` is the previously recorded `AutoFill` folder. Pass `None` on
    /// the first drain, or when the recorded folder no longer exists; a fresh
    /// one is then created and returned.
    ///
    /// # Reconciliation
    ///
    /// A provider that cannot open the vault cannot know whether the login it
    /// just captured is new. The Android `AutofillService` is handed a password
    /// by the system with no authentication at all, so it has no access to the
    /// index at that moment and stages every capture as a
    /// [`PendingOp::Create`]. Resolving that is this function's job, because
    /// this is the only place with the whole vault open:
    ///
    /// * a create naming a login the vault already holds, with the same
    ///   password, is dropped;
    /// * a create naming a login the vault already holds, with a different
    ///   password, becomes a password update on that item, old value moved into
    ///   `OLDP`;
    /// * anything else is imported into the `AutoFill` folder as before.
    ///
    /// "Already holds" means a `LINK` resolving to the same host or the same
    /// registrable domain, **and** the same identity value ignoring ASCII case.
    /// Looser tiers are deliberately not accepted: importing a duplicate is
    /// recoverable, overwriting the password of an entry that only loosely
    /// matched is not.
    pub fn drain_autofill_journal(
        &mut self,
        journal_bytes: &[u8],
        keys: &DrainKeys<'_>,
        folder_id: Option<&str>,
    ) -> Result<DrainSummary> {
        self.ensure_unlocked()?;

        let read = journal::open_for_drain(journal_bytes, keys);
        let mut records = journal::dedupe(read.records);
        records.sort_by_key(|r| r.created_at);
        // All or nothing: a failure part-way leaves the vault as it was, and the
        // journal, which is only deleted after a successful drain, is retried.
        // The applied set is written in the same transaction.
        let mut summary = self.in_transaction(|w| {
            let seen: Vec<(String, i64)> = records.iter().map(|r| (r.record_id.clone(), r.created_at)).collect();
            let applied = super::applied::load(w.drain_connection()?)?;
            let summary = w.drain_records(records, folder_id, &applied)?;
            super::applied::remember(w.drain_connection()?, &seen)?;
            Ok(summary)
        })?;
        summary.unauthenticated = read.unauthenticated;
        summary.unparsed_bytes = read.unparsed_bytes;
        Ok(summary)
    }

    /// Accept a replacement reported in [`DrainSummary::pending_replacements`]:
    /// the existing passkey moves to the trash and the staged one, already on
    /// the same item, comes out of it. Both stay recoverable.
    ///
    /// Refuses unless `existing_field_id` is a live passkey on `item_id`,
    /// `staged_field_id` is a trashed passkey on the same item, and both are
    /// for the same rpId and user handle. To decline, do nothing: the staged
    /// passkey simply stays in the trash.
    pub fn confirm_passkey_replacement(
        &mut self,
        item_id: &str,
        existing_field_id: &str,
        staged_field_id: &str,
    ) -> Result<()> {
        self.ensure_unlocked()?;
        let refuse = |why: &str| WalletError::InvalidOperation(format!("cannot replace the passkey: {why}"));

        let existing = self
            .live_passkeys()?
            .into_iter()
            .find(|(item, field, _)| item == item_id && field == existing_field_id)
            .map(|(_, _, record)| record)
            .ok_or_else(|| refuse("the passkey to replace is not a live passkey on this item"))?;
        let staged = self
            .trashed_passkeys()?
            .into_iter()
            .find(|t| t.item_id == item_id && t.field_id == staged_field_id)
            .ok_or_else(|| refuse("the staged passkey is not in the trash on this item"))?;
        if !staged.rp_id.eq_ignore_ascii_case(&existing.rp_id) || staged.user_handle != existing.user_handle {
            return Err(refuse("the two passkeys are for different accounts"));
        }

        self.in_transaction(|w| {
            w.delete_field(item_id, existing_field_id)?;
            w.undelete_field(item_id, staged_field_id)
        })
    }

    fn drain_connection(&self) -> Result<&rusqlite::Connection> {
        self.db
            .as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()
    }

    fn drain_records(
        &mut self,
        records: Vec<PendingRecord>,
        folder_id: Option<&str>,
        applied: &super::applied::Applied,
    ) -> Result<DrainSummary> {
        let folder = self.resolve_autofill_folder(folder_id)?;

        // Snapshot of the login-shaped vault, taken once. It is kept current by
        // hand as records are applied rather than rebuilt, because rebuilding
        // decrypts every field and a journal may carry fifty records.
        let items = self.get_items()?.to_vec();
        let fields = self.get_fields()?.to_vec();
        let mut known = index::entries_from_vault(&items, &fields, IndexOptions::default());

        let mut summary = DrainSummary {
            folder_id: folder.clone(),
            created: Vec::new(),
            updated: Vec::new(),
            unchanged: 0,
            skipped: 0,
            passkeys_added: 0,
            pending_replacements: Vec::new(),
            unauthenticated: 0,
            already_applied: 0,
            unparsed_bytes: 0,
        };

        for record in records {
            let replayed = applied.contains(&record);
            if record.op == PendingOp::CreatePasskey {
                match self.apply_staged_passkey(&record, &known, &folder, replayed)? {
                    PasskeyOutcome::NeedsConfirmation(pending) => summary.pending_replacements.push(*pending),
                    PasskeyOutcome::AttachedTo(item_id) => {
                        summary.passkeys_added = summary.passkeys_added.saturating_add(1);
                        summary.updated.push(item_id);
                    }
                    PasskeyOutcome::Created(item_id) => {
                        summary.passkeys_added = summary.passkeys_added.saturating_add(1);
                        summary.created.push(item_id);
                    }
                    PasskeyOutcome::AlreadyThere => summary.unchanged = summary.unchanged.saturating_add(1),
                    PasskeyOutcome::AlreadyApplied => summary.already_applied = summary.already_applied.saturating_add(1),
                    PasskeyOutcome::Invalid => summary.skipped = summary.skipped.saturating_add(1),
                }
                continue;
            }
            if replayed {
                summary.already_applied = summary.already_applied.saturating_add(1);
                continue;
            }

            // An explicit update wins outright: the provider named an item, so
            // there is nothing to reconcile. A create-only record never
            // replaces anything: an exact duplicate is skipped, everything else
            // becomes a new entry, whatever item it names.
            let mut target = match (record.op, record.create_only) {
                (PendingOp::CreatePasskey, _) => unreachable!("handled above"),
                (PendingOp::UpdatePassword, false) => record.item_id.clone(),
                (PendingOp::Create, _) | (PendingOp::UpdatePassword, true) => {
                    match Self::reconcile(&known, &record) {
                        Some(Match::Same) => {
                            summary.unchanged = summary.unchanged.saturating_add(1);
                            continue;
                        }
                        Some(Match::PasswordChanged(_)) if record.create_only => None,
                        Some(Match::PasswordChanged(item_id)) => Some(item_id),
                        None => None,
                    }
                }
            };

            if let Some(item_id) = target.take()
                && let Some(applied) = self.apply_password_update(&item_id, &record.password)?
            {
                Self::remember_password(&mut known, &applied, &record.password);
                summary.updated.push(applied);
                continue;
            }

            // A create, an update naming an item that no longer exists, or a
            // reconciled match that turned out to have lost its password field:
            // import it rather than dropping it, since the password is still
            // the user's.
            match self.create_from_record(&record, &folder) {
                Ok(item_id) => {
                    known.push(Self::entry_for(&item_id, &record));
                    summary.created.push(item_id);
                }
                Err(_) => summary.skipped = summary.skipped.saturating_add(1),
            }
        }

        Ok(summary)
    }

    /// Put a staged passkey into the vault. First match wins:
    ///
    /// 1. the vault already holds this credential id: already drained, nothing
    ///    to do (when that copy is a staged replacement still waiting in the
    ///    trash, it is reported again, so a crash before the user was asked
    ///    does not lose the question);
    /// 2. a live passkey for the same rpId **and** user handle: WebAuthn treats
    ///    the new one as a replacement, but a journal record alone is not
    ///    enough to drop a working passkey. The staged one is stored on the
    ///    same item, straight into the trash, and reported for confirmation;
    /// 3. a live login whose `LINK` is the rpId's host, or shares its
    ///    registrable domain under the full Public Suffix List (not the
    ///    curated list login ranking uses), **and** whose identity equals the
    ///    user name (ignoring ASCII case): the passkey is added to that item;
    /// 4. otherwise a new item in the `AutoFill` folder.
    ///
    /// A `replayed` record (applied by an earlier drain) only gets step 1:
    /// anything that would add it again is [`PasskeyOutcome::AlreadyApplied`].
    fn apply_staged_passkey(
        &mut self,
        record: &PendingRecord,
        known: &[index::IndexEntry],
        folder: &str,
        replayed: bool,
    ) -> Result<PasskeyOutcome> {
        let Some(passkey) = record.staged_passkey() else { return Ok(PasskeyOutcome::Invalid) };
        let value = passkey.to_field_value()?;

        let existing = self.live_passkeys()?;
        if existing.iter().any(|(_, _, r)| r.credential_id == passkey.credential_id) {
            return Ok(PasskeyOutcome::AlreadyThere);
        }
        // A live passkey for the same account, on `item` when one is named.
        let same_account = |item: Option<&str>| {
            existing.iter().find(|(i, _, r)| {
                item.is_none_or(|item| i == item) && r.rp_id == passkey.rp_id && r.user_handle == passkey.user_handle
            })
        };
        if let Some(trashed) = self
            .trashed_passkeys()?
            .into_iter()
            .find(|t| t.credential_id == passkey.credential_id)
        {
            return Ok(match same_account(Some(&trashed.item_id)) {
                Some((item_id, field_id, current)) => PasskeyOutcome::NeedsConfirmation(Box::new(PasskeyReplacement {
                    existing: current.summary(item_id, field_id),
                    staged: passkey.summary(item_id, &trashed.field_id),
                })),
                None => PasskeyOutcome::AlreadyThere,
            });
        }
        if replayed {
            return Ok(PasskeyOutcome::AlreadyApplied);
        }
        if let Some((item_id, field_id, current)) = same_account(None) {
            let staged_field = self.add_field_unchecked(item_id, FIELD_PASSKEY, &value, None)?;
            self.delete_field(item_id, &staged_field)?;
            return Ok(PasskeyOutcome::NeedsConfirmation(Box::new(PasskeyReplacement {
                existing: current.summary(item_id, field_id),
                staged: passkey.summary(item_id, &staged_field),
            })));
        }

        let user = passkey.user_name.trim();
        if !user.is_empty()
            && let Some(entry) = known.iter().find(|e| {
                e.username.trim().eq_ignore_ascii_case(user)
                    && e.hosts.iter().any(|h| super::domain::passkey_matches_host(h, &passkey.rp_id))
            })
        {
            let item_id = entry.item_id.clone();
            self.add_field_unchecked(&item_id, FIELD_PASSKEY, &value, None)?;
            return Ok(PasskeyOutcome::AttachedTo(item_id));
        }

        let item_id = self.add_item(&passkey.rp_id, "", false, Some(folder))?;
        self.add_field_unchecked(&item_id, FIELD_LINK, &format!("https://{}", passkey.rp_id), None)?;
        if !user.is_empty() {
            let kind = super::identity::classify(user);
            self.add_field_unchecked(&item_id, kind.field_type(), user, None)?;
        }
        self.add_field_unchecked(&item_id, FIELD_PASSKEY, &value, None)?;
        Ok(PasskeyOutcome::Created(item_id))
    }

    /// Decide what an unattributed create record actually means against the
    /// logins the vault already holds.
    fn reconcile(known: &[index::IndexEntry], record: &PendingRecord) -> Option<Match> {
        let identity = record.identity_value.trim();
        if identity.is_empty() {
            return None;
        }
        let host = super::domain::normalize_host(&record.url)?;

        let best = known
            .iter()
            .filter(|entry| entry.username.trim().eq_ignore_ascii_case(identity))
            .filter_map(|entry| {
                index::rank(entry, &host)
                    .filter(|tier| *tier >= super::domain::MatchTier::RegistrableDomain)
                    .map(|tier| (tier, entry))
            })
            .max_by_key(|(tier, _)| *tier)
            .map(|(_, entry)| entry)?;

        if best.password == record.password {
            Some(Match::Same)
        } else {
            Some(Match::PasswordChanged(best.item_id.clone()))
        }
    }

    /// Keep the snapshot honest after an update, so a second record naming the
    /// same login in the same journal reconciles against the new password.
    fn remember_password(known: &mut [index::IndexEntry], item_id: &str, password: &str) {
        if let Some(entry) = known.iter_mut().find(|e| e.item_id == item_id) {
            entry.password = password.to_string();
        }
    }

    /// The snapshot row a freshly imported record produces, so two identical
    /// captures in one journal do not become two items.
    fn entry_for(item_id: &str, record: &PendingRecord) -> index::IndexEntry {
        let hosts: Vec<String> = super::domain::normalize_host(&record.url)
            .into_iter()
            .collect();
        let registrable = hosts
            .iter()
            .filter_map(|h| super::domain::registrable_domain(h))
            .collect();
        index::IndexEntry {
            item_id: item_id.to_string(),
            title: record.title.clone(),
            identity_type: record.identity_kind().field_type().to_string(),
            username: record.identity_value.clone(),
            password: record.password.clone(),
            totp_secret: None,
            hosts,
            registrable,
        }
    }

    /// Identity of every readable passkey in the trash, from its public value.
    fn trashed_passkeys(&mut self) -> Result<Vec<TrashedPasskey>> {
        let mut out = Vec::new();
        for field in self.get_deleted_fields()? {
            if field.field_type != FIELD_PASSKEY {
                continue;
            }
            let Ok(public) = serde_json::from_str::<serde_json::Value>(&field.value) else { continue };
            let decode = |k: &str| {
                public
                    .get(k)
                    .and_then(serde_json::Value::as_str)
                    .and_then(|v| crate::passkey::b64::decode(v, k).ok())
            };
            let (Some(credential_id), Some(user_handle), Some(rp_id)) = (
                decode("credentialId"),
                decode("userHandle"),
                public.get("rpId").and_then(serde_json::Value::as_str),
            ) else {
                continue;
            };
            out.push(TrashedPasskey {
                rp_id: rp_id.to_string(),
                item_id: field.item_id,
                field_id: field.field_id,
                credential_id,
                user_handle,
            });
        }
        Ok(out)
    }

    /// Every readable passkey on a live item, as the index carries it.
    /// Unreadable records are left out, never fatal.
    fn passkey_index_entries(&mut self, items: &[crate::IWItem]) -> Result<Vec<index::PasskeyIndexEntry>> {
        let titles: std::collections::HashMap<&str, &str> =
            items.iter().map(|i| (i.item_id.as_str(), i.name.as_str())).collect();
        let mut out = Vec::new();
        for (item_id, field_id, record) in self.live_passkeys()? {
            let title = titles.get(item_id.as_str()).copied().unwrap_or_default().to_string();
            out.push(index::PasskeyIndexEntry::new(item_id, field_id, title, record));
        }
        Ok(out)
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
    fn apply_password_update(
        &mut self,
        item_id: &str,
        new_password: &str,
    ) -> Result<Option<String>> {
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

        self.update_field(&pass_field_id, new_password, None)?;
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
    use crate::passkey::PasskeyRecord;
    use crate::autofill::keys::generate_keys;
    use tempfile::TempDir;

    fn dk(keys: &crate::autofill::AutofillKeys) -> DrainKeys<'_> {
        DrainKeys { journal_secret: &keys.journal_secret, auth_key: &keys.journal_auth_key, legacy_wrap_keys: &[] }
    }

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
            passkey: None,
            create_only: false,
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
                &journal::seal_record(&r, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap(),
            );
        }

        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
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
                    &keys.index_key, &keys.journal_auth_key)
                .unwrap(),
            );
        }

        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
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
    /// Two separate guards meet here, and both are load-bearing.
    ///
    /// Within one journal, `record_id` dedupe collapses a repeated record. That
    /// was the only guard until reconciliation existed, and it never covered a
    /// crash *between* drains: the same bytes drained twice used to import the
    /// login a second time, despite the doc comment claiming otherwise.
    /// Reconciliation closes that, because on the second pass the vault already
    /// holds the login with the same password.
    fn drain_is_idempotent_across_a_simulated_crash() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let journal =
            journal::seal_record(&record("r1", "bkv"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key)
                .unwrap();

        // First drain succeeds, then the process dies before the journal is
        // deleted, so the same bytes are drained again.
        let first = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();
        let mut doubled = journal.clone();
        doubled.extend_from_slice(&journal);
        let second = w
            .drain_autofill_journal(&doubled, &dk(&keys), Some(&first.folder_id))
            .unwrap();

        assert_eq!(first.created.len(), 1);
        assert!(
            second.created.is_empty(),
            "a re-drained record must not become a second item"
        );
        assert_eq!(
            (second.already_applied, second.unchanged),
            (1, 0),
            "the repeated record_id collapses to one, and the vault remembers applying it"
        );
        assert_eq!(second.folder_id, first.folder_id, "folder is reused");
    }

    #[test]
    fn the_folder_is_reused_by_id_after_a_rename() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let journal =
            journal::seal_record(&record("r1", "bkv"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key)
                .unwrap();

        let first = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();
        w.update_item_name(&first.folder_id, "My logins").unwrap();

        let journal2 =
            journal::seal_record(&record("r2", "bkv"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key)
                .unwrap();
        let second = w
            .drain_autofill_journal(&journal2, &dk(&keys), Some(&first.folder_id))
            .unwrap();

        assert_eq!(second.folder_id, first.folder_id);
    }

    #[test]
    fn a_deleted_folder_is_recreated_without_duplicating() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let journal =
            journal::seal_record(&record("r1", "bkv"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key)
                .unwrap();

        let first = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();
        w.delete_item(&first.folder_id).unwrap();

        let journal2 =
            journal::seal_record(&record("r2", "bkv"), &keys.journal_public, &keys.index_key, &keys.journal_auth_key)
                .unwrap();
        let second = w
            .drain_autofill_journal(&journal2, &dk(&keys), Some(&first.folder_id))
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
            journal::seal_record(&update, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();

        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
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
            journal::seal_record(&update, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();

        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
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
            passkey: None,
            create_only: false,
        };
        let journal =
            journal::seal_record(&staged, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();
        let summary = target
            .drain_autofill_journal(&journal, &dk(&keys), None)
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

    // ---- integrity of drained records ---------------------------------------

    #[test]
    fn an_update_without_a_valid_tag_is_refused_and_reported() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let unrelated = generate_keys().unwrap();
        let item = login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");

        let mut update = capture("f1", "https://github.com/login", "bkv", "hunter3");
        update.op = PendingOp::UpdatePassword;
        update.item_id = Some(item.clone());
        // Sealed to the right app key, but tagged under another auth key.
        let journal = journal::seal_record(&update, &keys.journal_public, &unrelated.index_key, &unrelated.journal_auth_key)
            .unwrap();
        let summary = w.drain_autofill_journal(&journal, &dk(&keys), None).unwrap();

        assert_eq!(summary.unauthenticated, 1);
        assert!(summary.updated.is_empty() && summary.created.is_empty());
        assert_eq!(password_of(&mut w, &item, FIELD_PASSWORD).as_deref(), Some("hunter2"));
        assert_eq!(password_of(&mut w, &item, FIELD_OLD_PASSWORD), None);
    }

    #[test]
    fn a_legacy_record_is_applied_only_through_the_recovery_keys() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let legacy = journal::seal_legacy_record(&record("old", "bkv"), &keys.journal_public, &keys.index_key).unwrap();

        let refused = w.drain_autofill_journal(&legacy, &dk(&keys), None).unwrap();
        assert_eq!((refused.unauthenticated, refused.created.len()), (1, 0));

        let recovery = [*keys.index_key];
        let with_recovery = DrainKeys { legacy_wrap_keys: &recovery, ..dk(&keys) };
        let applied = w.drain_autofill_journal(&legacy, &with_recovery, None).unwrap();
        assert_eq!((applied.unauthenticated, applied.created.len()), (0, 1));
    }

    // ---- passkey replacement needs confirmation -----------------------------

    fn staged_passkey(keys: &crate::autofill::AutofillKeys, id: &str, handle: &[u8]) -> (Vec<u8>, PasskeyRecord) {
        let reg = crate::passkey::sign::register(&crate::passkey::sign::RegisterInput {
            rp_id: "example.com",
            user_name: "bkv",
            user_display_name: "bkv",
            user_handle: handle,
            exclude_credentials: &[],
            held_credential_ids: &[],
            user_verified: true,
            now: 1,
        })
        .unwrap();
        let mut r = record(id, "bkv");
        r.op = PendingOp::CreatePasskey;
        r.password = String::new();
        r.passkey = Some(reg.record.to_field_value().unwrap());
        let sealed = journal::seal_record(&r, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap();
        (sealed, reg.record)
    }

    /// Two passkeys for the same account, the second waiting in the trash.
    struct Pending {
        replacement: PasskeyReplacement,
        first: PasskeyRecord,
        second: PasskeyRecord,
        keys: crate::autofill::AutofillKeys,
        second_journal: Vec<u8>,
    }

    fn pending_replacement(w: &mut Wallet) -> Pending {
        let keys = generate_keys().unwrap();
        let (j1, first) = staged_passkey(&keys, "p1", b"handle");
        let (j2, second) = staged_passkey(&keys, "p2", b"handle");
        w.drain_autofill_journal(&j1, &dk(&keys), None).unwrap();
        let summary = w.drain_autofill_journal(&j2, &dk(&keys), None).unwrap();
        assert_eq!(summary.pending_replacements.len(), 1);
        assert_eq!(summary.passkeys_added, 0);
        Pending { replacement: summary.pending_replacements[0].clone(), first, second, keys, second_journal: j2 }
    }

    #[test]
    fn a_replacing_passkey_is_held_in_the_trash_until_confirmed() {
        let (mut w, _dir) = wallet();
        let Pending { replacement: pending, first, second, .. } = pending_replacement(&mut w);

        assert_eq!(pending.existing.credential_id, first.credential_id);
        assert_eq!(pending.staged.credential_id, second.credential_id);
        assert_eq!(pending.existing.item_id, pending.staged.item_id);
        let live: Vec<_> = w.list_passkeys().unwrap().into_iter().map(|p| p.credential_id).collect();
        assert_eq!(live, vec![first.credential_id.clone()], "nothing replaced yet");

        w.confirm_passkey_replacement(&pending.existing.item_id, &pending.existing.field_id, &pending.staged.field_id)
            .unwrap();
        let live: Vec<_> = w.list_passkeys().unwrap().into_iter().map(|p| p.credential_id).collect();
        assert_eq!(live, vec![second.credential_id.clone()]);
        assert!(
            w.get_deleted_fields().unwrap().iter().any(|f| f.field_id == pending.existing.field_id),
            "the replaced passkey stays recoverable"
        );
    }

    #[test]
    fn confirming_a_replacement_refuses_anything_but_the_reported_pair() {
        let (mut w, _dir) = wallet();
        let pending = pending_replacement(&mut w).replacement;
        let (item, existing, staged) =
            (pending.existing.item_id.clone(), pending.existing.field_id.clone(), pending.staged.field_id.clone());

        // Swapped roles, unknown ids, another item.
        assert!(w.confirm_passkey_replacement(&item, &staged, &existing).is_err());
        assert!(w.confirm_passkey_replacement(&item, "nope", &staged).is_err());
        assert!(w.confirm_passkey_replacement(&item, &existing, "nope").is_err());
        assert!(w.confirm_passkey_replacement("other-item", &existing, &staged).is_err());

        // A trashed passkey for another account on the same item.
        let keys = generate_keys().unwrap();
        let (j, other) = staged_passkey(&keys, "p3", b"another-handle");
        w.drain_autofill_journal(&j, &dk(&keys), None).unwrap();
        let (other_item, other_field) = w
            .list_passkeys()
            .unwrap()
            .into_iter()
            .find(|p| p.credential_id == other.credential_id)
            .map(|p| (p.item_id, p.field_id))
            .unwrap();
        let moved = w.passkey_stored_value(&other_item, &other_field).unwrap().unwrap();
        let foreign = w.add_field_unchecked(&item, FIELD_PASSKEY, &moved, None).unwrap();
        w.delete_field(&item, &foreign).unwrap();
        let err = w.confirm_passkey_replacement(&item, &existing, &foreign).unwrap_err();
        assert!(err.to_string().contains("different accounts"), "{err}");

        // Nothing changed through any of that, and the real pair still works.
        w.confirm_passkey_replacement(&item, &existing, &staged).unwrap();

        w.lock();
        assert!(matches!(w.confirm_passkey_replacement(&item, &existing, &staged), Err(WalletError::Locked)));
    }

    #[test]
    fn re_draining_a_pending_replacement_asks_again_without_a_second_copy() {
        let (mut w, _dir) = wallet();
        let p = pending_replacement(&mut w);
        let again = w.drain_autofill_journal(&p.second_journal, &dk(&p.keys), None).unwrap();
        assert_eq!(again.pending_replacements, vec![p.replacement.clone()]);
        assert_eq!(w.trashed_passkeys().unwrap().len(), 1);
        assert_eq!(w.list_passkeys().unwrap()[0].credential_id, p.first.credential_id);
    }

    #[test]
    fn a_staged_passkey_already_in_the_trash_without_a_live_rival_is_already_there() {
        let (mut w, _dir) = wallet();
        let p = pending_replacement(&mut w);
        // The user deletes the live passkey instead of confirming.
        w.delete_field(&p.replacement.existing.item_id, &p.replacement.existing.field_id).unwrap();

        let again = w.drain_autofill_journal(&p.second_journal, &dk(&p.keys), None).unwrap();
        assert!(again.pending_replacements.is_empty());
        assert_eq!((again.unchanged, again.passkeys_added), (1, 0));
        assert!(w.list_passkeys().unwrap().is_empty(), "nothing was restored behind the user's back");
        assert!(w.trashed_passkeys().unwrap().iter().any(|t| t.credential_id == p.second.credential_id));
    }

    #[test]
    fn unreadable_passkeys_in_the_trash_are_ignored() {
        let (mut w, _dir) = wallet();
        let item = w.add_item("Broken", "", false, Some(crate::ROOT_ID)).unwrap();
        let field = w.add_field_unchecked(&item, FIELD_PASSKEY, "{\"v\":1}", None).unwrap();
        w.delete_field(&item, &field).unwrap();
        let other = w.add_field(&item, "NOTE", "plain", None).unwrap();
        w.delete_field(&item, &other).unwrap();
        assert!(w.trashed_passkeys().unwrap().is_empty());
    }

    #[test]
    fn a_garbage_journal_drains_to_nothing_without_creating_a_folder_full_of_junk() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let summary = w
            .drain_autofill_journal(b"not a journal", &dk(&keys), None)
            .unwrap();
        assert!(summary.created.is_empty());
        assert!(summary.updated.is_empty());
        assert_eq!(summary.skipped, 0);
    }

    // ---- where a staged passkey attaches -------------------------------------

    fn staged_passkey_for(keys: &crate::autofill::AutofillKeys, id: &str, rp_id: &str, user: &str) -> Vec<u8> {
        let reg = crate::passkey::sign::register(&crate::passkey::sign::RegisterInput {
            rp_id,
            user_name: user,
            user_display_name: user,
            user_handle: id.as_bytes(),
            exclude_credentials: &[],
            held_credential_ids: &[],
            user_verified: true,
            now: 1,
        })
        .unwrap();
        let mut r = record(id, user);
        r.op = PendingOp::CreatePasskey;
        r.password = String::new();
        r.passkey = Some(reg.record.to_field_value().unwrap());
        journal::seal_record(&r, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap()
    }

    #[test]
    fn a_passkey_never_attaches_to_a_login_of_another_site_under_a_hosting_suffix() {
        let (mut w, _dir) = wallet();
        let theirs = login(&mut w, "Theirs", "https://theirs.onrender.com/login", "bkv", "pw");
        let keys = generate_keys().unwrap();
        let j = staged_passkey_for(&keys, "p-ours", "ours.onrender.com", "bkv");

        let summary = w.drain_autofill_journal(&j, &dk(&keys), None).unwrap();
        assert_eq!(summary.passkeys_added, 1);
        assert!(summary.updated.is_empty(), "{summary:?}");
        assert_eq!(summary.created.len(), 1);
        assert_ne!(summary.created[0], theirs);
        let on_theirs = w.list_passkeys().unwrap().into_iter().filter(|p| p.item_id == theirs).count();
        assert_eq!(on_theirs, 0);
    }

    #[test]
    fn a_passkey_attaches_to_a_login_on_its_registrable_domain_or_exact_host() {
        let (mut w, _dir) = wallet();
        let parent = login(&mut w, "Example", "https://example.com", "bkv", "pw");
        let exact = login(&mut w, "Render", "https://mine.onrender.com", "bkv", "pw");
        let keys = generate_keys().unwrap();
        let mut j = staged_passkey_for(&keys, "p-sub", "login.example.com", "BKV");
        j.extend(staged_passkey_for(&keys, "p-exact", "mine.onrender.com", "bkv"));

        let summary = w.drain_autofill_journal(&j, &dk(&keys), None).unwrap();
        assert_eq!(summary.passkeys_added, 2);
        assert!(summary.created.is_empty(), "{summary:?}");
        assert_eq!(summary.updated, vec![parent.clone(), exact.clone()]);
        let mut holders: Vec<_> = w.list_passkeys().unwrap().into_iter().map(|p| p.item_id).collect();
        holders.sort();
        let mut want = vec![parent, exact];
        want.sort();
        assert_eq!(holders, want);
    }

    // ---- reconciliation of unattributed create records ----------------------
    //
    // The Android provider stages every capture as a create, because it is
    // handed a password with no authentication and therefore cannot open the
    // index to see whether the login already exists. Everything below is what
    // the app does about that on the way in.

    /// A login already in the vault, with one LINK, one identity and one PASS.
    fn login(w: &mut Wallet, title: &str, link: &str, identity: &str, password: &str) -> String {
        let item = w.add_item(title, "", false, Some(crate::ROOT_ID)).unwrap();
        w.add_field(&item, "USER", identity, Some(0)).unwrap();
        w.add_field(&item, "PASS", password, Some(100)).unwrap();
        w.add_field(&item, "LINK", link, Some(200)).unwrap();
        item
    }

    fn capture(id: &str, url: &str, identity: &str, password: &str) -> PendingRecord {
        PendingRecord {
            record_id: id.to_string(),
            op: PendingOp::Create,
            item_id: None,
            title: "Captured".into(),
            url: url.into(),
            identity_value: identity.into(),
            identity_hint: None,
            password: password.into(),
            totp_secret: None,
            created_at: 1_700_000_000,
            passkey: None,
            create_only: false,
        }
    }

    fn seal_all(records: &[PendingRecord], keys: &crate::autofill::AutofillKeys) -> Vec<u8> {
        let mut journal = Vec::new();
        for r in records {
            journal.extend_from_slice(
                &journal::seal_record(r, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap(),
            );
        }
        journal
    }

    fn password_of(w: &mut Wallet, item_id: &str, field_type: &str) -> Option<String> {
        w.get_fields_by_item(item_id)
            .unwrap()
            .iter()
            .filter(|f| !f.deleted && f.field_type == field_type)
            .min_by_key(|f| f.sort_weight)
            .map(|f| f.value.clone())
    }

    fn sealed(keys: &crate::autofill::AutofillKeys, records: &[PendingRecord]) -> Vec<u8> {
        let mut journal = Vec::new();
        for r in records {
            journal.extend_from_slice(
                &journal::seal_record(r, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap(),
            );
        }
        journal
    }

    fn set_password(w: &mut Wallet, item_id: &str, password: &str) {
        let field = w
            .get_fields_by_item(item_id)
            .unwrap()
            .iter()
            .find(|f| !f.deleted && f.field_type == FIELD_PASSWORD)
            .map(|f| f.field_id.clone())
            .unwrap();
        w.update_field(&field, password, None).unwrap();
    }

    #[test]
    fn old_journal_bytes_drained_again_do_not_roll_a_password_back() {
        for explicit_update in [false, true] {
            let (mut w, dir) = wallet();
            let keys = generate_keys().unwrap();
            let item = login(&mut w, "GitHub", "https://github.com/login", "bkv", "v1");

            let mut capture = capture("c1", "https://github.com/login", "bkv", "v2");
            if explicit_update {
                capture.op = PendingOp::UpdatePassword;
                capture.item_id = Some(item.clone());
            }
            let journal = sealed(&keys, &[capture]);
            let first = w.drain_autofill_journal(&journal, &dk(&keys), None).unwrap();
            assert_eq!(first.updated, vec![item.clone()]);
            assert_eq!(password_of(&mut w, &item, FIELD_PASSWORD).as_deref(), Some("v2"));

            // The user changes the password in the app; later the same bytes
            // are drained again, even after the vault was closed and reopened.
            set_password(&mut w, &item, "v3");
            w.close();
            let mut w = Wallet::open(dir.path()).unwrap();
            assert!(w.unlock("test-password").unwrap());

            let again = w.drain_autofill_journal(&journal, &dk(&keys), Some(&first.folder_id)).unwrap();
            assert_eq!(again.already_applied, 1);
            assert!(again.updated.is_empty() && again.created.is_empty());
            assert_eq!(password_of(&mut w, &item, FIELD_PASSWORD).as_deref(), Some("v3"), "explicit: {explicit_update}");
        }
    }

    #[test]
    fn a_drain_reports_a_journal_it_could_not_read_to_the_end() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let good = sealed(&keys, &[record("r1", "bkv")]);
        let clean = w.drain_autofill_journal(&good, &dk(&keys), None).unwrap();
        assert_eq!(clean.unparsed_bytes, 0);

        let mut torn = sealed(&keys, &[record("r2", "other")]);
        torn.truncate(torn.len() / 2);
        let torn_len = torn.len();
        let summary = w.drain_autofill_journal(&torn, &dk(&keys), Some(&clean.folder_id)).unwrap();
        assert_eq!(summary.unparsed_bytes, torn_len);
        assert!(summary.created.is_empty());
    }

    #[test]
    fn a_replayed_record_is_refused_inside_a_journal_with_new_ones() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let old = sealed(&keys, &[capture("c1", "https://a.example/login", "bkv", "pw-a")]);
        w.drain_autofill_journal(&old, &dk(&keys), None).unwrap();

        let mut mixed = sealed(&keys, &[capture("c2", "https://b.example/login", "bkv", "pw-b")]);
        mixed.extend_from_slice(&old);
        let summary = w.drain_autofill_journal(&mixed, &dk(&keys), None).unwrap();
        assert_eq!((summary.created.len(), summary.already_applied), (1, 1));
    }

    #[test]
    fn records_apply_in_creation_order_not_file_order() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let item = login(&mut w, "GitHub", "https://github.com/login", "bkv", "v1");

        let mut newer = capture("c-new", "https://github.com/login", "bkv", "newer");
        newer.created_at = 2_000;
        let mut older = capture("c-old", "https://github.com/login", "bkv", "older");
        older.created_at = 1_000;
        let journal = sealed(&keys, &[newer, older]);
        w.drain_autofill_journal(&journal, &dk(&keys), None).unwrap();

        assert_eq!(password_of(&mut w, &item, FIELD_PASSWORD).as_deref(), Some("newer"));
        assert_eq!(password_of(&mut w, &item, FIELD_OLD_PASSWORD).as_deref(), Some("older"));
    }

    #[test]
    fn a_replayed_passkey_whose_item_was_purged_is_not_added_again() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let (j, _) = staged_passkey(&keys, "p1", b"handle");
        let first = w.drain_autofill_journal(&j, &dk(&keys), None).unwrap();
        assert_eq!(first.passkeys_added, 1);
        let item = first.created[0].clone();
        // Gone for good, trash included.
        let conn = w.drain_connection().unwrap();
        conn.execute("DELETE FROM nswallet_fields WHERE item_id = ?1", [&item]).unwrap();
        conn.execute("DELETE FROM nswallet_items WHERE item_id = ?1", [&item]).unwrap();
        w.clear_caches();

        let again = w.drain_autofill_journal(&j, &dk(&keys), None).unwrap();
        assert_eq!((again.passkeys_added, again.already_applied), (0, 1));
        assert!(w.list_passkeys().unwrap().is_empty());
    }

    #[test]
    fn a_recaptured_login_the_vault_already_holds_is_dropped() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");

        let journal = seal_all(
            &[capture("r1", "https://github.com/login", "bkv", "hunter2")],
            &keys,
        );
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.unchanged, 1);
        assert!(summary.created.is_empty());
        assert!(summary.updated.is_empty());
    }

    #[test]
    fn a_capture_with_a_new_password_updates_in_place_and_keeps_the_old_one() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let item = login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");

        let journal = seal_all(
            &[capture("r1", "https://github.com/settings", "bkv", "hunter3")],
            &keys,
        );
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.updated, vec![item.clone()]);
        assert!(summary.created.is_empty());
        assert_eq!(summary.unchanged, 0);
        assert_eq!(password_of(&mut w, &item, FIELD_PASSWORD).as_deref(), Some("hunter3"));
        assert_eq!(
            password_of(&mut w, &item, FIELD_OLD_PASSWORD).as_deref(),
            Some("hunter2")
        );
    }

    #[test]
    fn a_create_only_capture_with_a_new_password_is_a_new_login_and_replaces_nothing() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let item = login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");

        let mut unverified = capture("r1", "https://github.com/settings", "bkv", "attacker");
        unverified.create_only = true;
        let summary = w
            .drain_autofill_journal(&seal_all(&[unverified], &keys), &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.created.len(), 1);
        assert!(summary.updated.is_empty());
        assert_ne!(summary.created[0], item);
        assert_eq!(password_of(&mut w, &item, FIELD_PASSWORD).as_deref(), Some("hunter2"));
        assert_eq!(password_of(&mut w, &item, FIELD_OLD_PASSWORD), None);
        assert_eq!(
            password_of(&mut w, &summary.created[0], FIELD_PASSWORD).as_deref(),
            Some("attacker")
        );
    }

    #[test]
    fn a_create_only_update_naming_an_item_is_filed_as_a_new_login() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let item = login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");

        let mut update = capture("r1", "https://github.com/login", "bkv", "attacker");
        update.op = PendingOp::UpdatePassword;
        update.item_id = Some(item.clone());
        update.create_only = true;
        let summary = w
            .drain_autofill_journal(&seal_all(&[update], &keys), &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.created.len(), 1);
        assert!(summary.updated.is_empty());
        assert_eq!(password_of(&mut w, &item, FIELD_PASSWORD).as_deref(), Some("hunter2"));
        assert_eq!(password_of(&mut w, &item, FIELD_OLD_PASSWORD), None);
    }

    #[test]
    fn a_create_only_capture_the_vault_already_holds_is_dropped() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");

        let mut same = capture("r1", "https://github.com/login", "bkv", "hunter2");
        same.create_only = true;
        let summary = w
            .drain_autofill_journal(&seal_all(&[same], &keys), &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.unchanged, 1);
        assert!(summary.created.is_empty());
        assert!(summary.updated.is_empty());
    }

    #[test]
    fn a_capture_for_a_different_username_on_the_same_site_is_a_new_login() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");

        let journal = seal_all(
            &[capture("r1", "https://github.com/login", "someone-else", "hunter3")],
            &keys,
        );
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.created.len(), 1);
        assert!(summary.updated.is_empty());
    }

    #[test]
    fn a_capture_for_the_same_username_on_a_different_site_is_a_new_login() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");

        let journal = seal_all(
            &[capture("r1", "https://gitlab.com/users/sign_in", "bkv", "hunter3")],
            &keys,
        );
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.created.len(), 1);
        assert!(summary.updated.is_empty());
    }

    #[test]
    fn a_subdomain_capture_reconciles_against_the_registrable_domain() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let item = login(&mut w, "GitHub", "https://github.com", "bkv", "hunter2");

        let journal = seal_all(
            &[capture("r1", "https://gist.github.com/new", "bkv", "hunter3")],
            &keys,
        );
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.updated, vec![item]);
    }

    #[test]
    fn identity_matching_ignores_ascii_case() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let item = login(&mut w, "GitHub", "https://github.com/login", "BKV", "hunter2");

        let journal = seal_all(
            &[capture("r1", "https://github.com/login", "bkv", "hunter3")],
            &keys,
        );
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.updated, vec![item]);
    }

    #[test]
    fn a_deleted_item_is_never_reconciled_against() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let item = login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");
        w.delete_item(&item).unwrap();

        let journal = seal_all(
            &[capture("r1", "https://github.com/login", "bkv", "hunter3")],
            &keys,
        );
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.created.len(), 1);
        assert!(summary.updated.is_empty());
    }

    #[test]
    fn a_capture_with_no_identity_value_is_never_reconciled() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        login(&mut w, "GitHub", "https://github.com/login", "", "hunter2");

        let journal = seal_all(&[capture("r1", "https://github.com/login", "", "hunter3")], &keys);
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.created.len(), 1);
        assert!(summary.updated.is_empty());
    }

    #[test]
    fn two_identical_captures_in_one_journal_produce_one_item() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let journal = seal_all(
            &[
                capture("r1", "https://example.com/signup", "bkv", "hunter2"),
                capture("r2", "https://example.com/login", "bkv", "hunter2"),
            ],
            &keys,
        );
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.created.len(), 1);
        assert_eq!(summary.unchanged, 1);
    }

    #[test]
    fn a_second_capture_in_one_journal_updates_the_first() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let journal = seal_all(
            &[
                capture("r1", "https://example.com/signup", "bkv", "hunter2"),
                capture("r2", "https://example.com/settings", "bkv", "hunter3"),
            ],
            &keys,
        );
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.created.len(), 1);
        assert_eq!(summary.updated.len(), 1);
        assert_eq!(summary.created, summary.updated);
        let item = &summary.created[0];
        assert_eq!(password_of(&mut w, item, FIELD_PASSWORD).as_deref(), Some("hunter3"));
        assert_eq!(
            password_of(&mut w, item, FIELD_OLD_PASSWORD).as_deref(),
            Some("hunter2")
        );
    }

    #[test]
    fn an_explicit_update_record_still_wins_over_reconciliation() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let named = login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");
        // A second, unrelated login that a create would have matched instead.
        login(&mut w, "GitHub alt", "https://github.com/login", "bkv2", "hunter2");

        let mut record = capture("r1", "https://github.com/login", "bkv", "hunter3");
        record.op = PendingOp::UpdatePassword;
        record.item_id = Some(named.clone());

        let journal = seal_all(&[record], &keys);
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.updated, vec![named]);
        assert_eq!(summary.unchanged, 0);
    }

    #[test]
    fn a_staged_record_without_a_password_is_skipped() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let journal = seal_all(&[capture("r1", "https://example.com/signup", "bkv", "")], &keys);
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.skipped, 1);
        assert!(summary.created.is_empty());
    }

    #[test]
    fn a_capture_repeating_an_updated_password_is_unchanged() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let journal = seal_all(
            &[
                capture("r1", "https://example.com/signup", "bkv", "hunter2"),
                capture("r2", "https://example.com/settings", "bkv", "hunter3"),
                capture("r3", "https://example.com/login", "bkv", "hunter3"),
            ],
            &keys,
        );
        let summary = w
            .drain_autofill_journal(&journal, &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.created.len(), 1);
        assert_eq!(summary.updated.len(), 1);
        assert_eq!(summary.unchanged, 1);
    }

    #[test]
    fn the_folder_is_found_by_name_when_no_id_is_recorded() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let first = w
            .drain_autofill_journal(&seal_all(&[record("r1", "bkv")], &keys), &dk(&keys), None)
            .unwrap();
        let second = w
            .drain_autofill_journal(&seal_all(&[record("r2", "other")], &keys), &dk(&keys), None)
            .unwrap();

        assert_eq!(second.folder_id, first.folder_id);
        let folders = w
            .get_items()
            .unwrap()
            .iter()
            .filter(|i| i.folder && i.name == AUTOFILL_FOLDER_NAME)
            .count();
        assert_eq!(folders, 1);
    }

    #[test]
    fn a_password_update_naming_a_folder_degrades_to_a_create() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let folder = w.add_item("Logins", "", true, Some(crate::ROOT_ID)).unwrap();
        w.add_field(&folder, "PASS", "folder-password", Some(100)).unwrap();

        let mut update = record("r1", "bkv");
        update.op = PendingOp::UpdatePassword;
        update.item_id = Some(folder.clone());
        let summary = w
            .drain_autofill_journal(&seal_all(&[update], &keys), &dk(&keys), None)
            .unwrap();

        assert!(summary.updated.is_empty());
        assert_eq!(summary.created.len(), 1);
        assert_eq!(
            password_of(&mut w, &folder, FIELD_PASSWORD).as_deref(),
            Some("folder-password")
        );
    }

    #[test]
    fn a_password_update_reuses_an_existing_oldp_field() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();
        let item = login(&mut w, "GitHub", "https://github.com/login", "bkv", "hunter2");
        w.add_field(&item, FIELD_OLD_PASSWORD, "hunter1", Some(300)).unwrap();

        let mut update = capture("r1", "https://github.com/login", "bkv", "hunter3");
        update.op = PendingOp::UpdatePassword;
        update.item_id = Some(item.clone());
        w.drain_autofill_journal(&seal_all(&[update], &keys), &dk(&keys), None)
            .unwrap();

        let oldp: Vec<String> = w
            .get_fields_by_item(&item)
            .unwrap()
            .iter()
            .filter(|f| !f.deleted && f.field_type == FIELD_OLD_PASSWORD)
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(oldp, vec!["hunter2".to_string()]);
    }

    #[test]
    fn a_staged_totp_secret_is_imported_and_a_blank_one_is_not() {
        let (mut w, _dir) = wallet();
        let keys = generate_keys().unwrap();

        let mut with_totp = capture("r1", "https://example.com/signup", "bkv", "hunter2");
        with_totp.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
        let mut blank_totp = capture("r2", "https://other.example.org/signup", "bkv", "hunter2");
        blank_totp.totp_secret = Some("  ".into());
        let summary = w
            .drain_autofill_journal(&seal_all(&[with_totp, blank_totp], &keys), &dk(&keys), None)
            .unwrap();

        assert_eq!(summary.created.len(), 2);
        assert_eq!(
            password_of(&mut w, &summary.created[0], FIELD_TOTP).as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert_eq!(password_of(&mut w, &summary.created[1], FIELD_TOTP), None);
    }
}
