//! Signing with the passkeys a provider holds, without handing their keys out.
//!
//! A provider (the iOS AutoFill extension, the Android Credential Manager
//! provider) holds two sources of passkeys: the index the app built, and
//! passkeys it created itself and staged in the journal, which the app has not
//! drained yet. Both carry private keys. Everything here works on those
//! sources directly, so a provider lists candidates from their public summary
//! and signs through [`HeldPasskeys::sign`] or [`sign_from_index`]; it never
//! decodes a record or sees a private key or PRF secret.
//!
//! The rpId check of [`crate::passkey::sign::assert`] applies to every
//! signature: a passkey signs only for its own rpId.

use crate::error::{Result, WalletError};
use crate::passkey::prf::{self, PrfInputs, PrfOutputs};
use crate::passkey::sign::{self, Assertion};
use crate::passkey::{PasskeyRecord, PasskeySummary};

use super::crypto::KEY_LEN;
use super::journal::{self, PendingOp};
use super::index;

/// One passkey a provider can offer, without any secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCandidate {
    /// Public metadata. `item_id` and `field_id` are empty for a staged
    /// passkey, which is not in the vault yet.
    pub summary: PasskeySummary,
    /// Item title from the index, or the staged record's title.
    pub title: String,
    /// True when the passkey comes from the journal rather than the index.
    pub staged: bool,
}

/// What a sign-in asks for.
#[derive(Debug, Clone)]
pub struct SignRequest<'a> {
    /// The credential the user picked (or the platform named).
    pub credential_id: &'a [u8],
    /// The rpId the platform verified for the caller.
    pub rp_id: &'a str,
    /// SHA-256 of the client data, as the platform supplies it.
    pub client_data_hash: &'a [u8; 32],
    /// The provider checked the user with a biometric or device passcode.
    pub user_verified: bool,
    /// The site's `allowCredentials`; empty allows any credential.
    pub allow_credentials: &'a [Vec<u8>],
    /// The site's raw PRF inputs for this credential, if it asked for PRF.
    pub prf: Option<&'a PrfInputs>,
}

/// A sign-in response.
#[derive(Debug, Clone)]
pub struct SignedAssertion {
    pub assertion: Assertion,
    /// PRF results, when asked for and the passkey supports PRF.
    pub prf: Option<PrfOutputs>,
    /// The item holding the passkey; empty for a staged passkey.
    pub item_id: String,
    /// True when the passkey came from the journal.
    pub staged: bool,
}

struct Held {
    record: PasskeyRecord,
    item_id: String,
    field_id: String,
    title: String,
    staged: bool,
}

/// Every passkey a provider holds: the index's, then staged ones not yet in
/// it. A credential id appears once, the index copy winning. `Debug` shows
/// only how many there are.
pub struct HeldPasskeys {
    held: Vec<Held>,
}

impl std::fmt::Debug for HeldPasskeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldPasskeys").field("count", &self.held.len()).finish()
    }
}

impl HeldPasskeys {
    /// Open the index and the journal.
    ///
    /// `index` is the sealed index; empty skips it (a provider passes nothing
    /// once the index has expired, while staged passkeys keep working). The
    /// journal is read with `index_key` and every key in `journal_keys` (on
    /// Android, the staging key), through the provider's read-back wrap; empty
    /// `journal` bytes mean no journal.
    pub fn open(
        index: &[u8],
        index_key: &[u8; KEY_LEN],
        journal: &[u8],
        journal_keys: &[[u8; KEY_LEN]],
    ) -> Result<Self> {
        let mut held: Vec<Held> = Vec::new();
        if !index.is_empty() {
            let (_, contents) = index::open_all(index, index_key)?;
            for entry in contents.passkeys {
                let record = entry.record().clone();
                held.push(Held {
                    record,
                    item_id: entry.item_id,
                    field_id: entry.field_id,
                    title: entry.title,
                    staged: false,
                });
            }
        }

        let mut staged = journal::open_with_index_key(journal, index_key);
        for key in journal_keys {
            staged.extend(journal::open_with_index_key(journal, key));
        }
        for rec in journal::dedupe(staged) {
            if rec.op != PendingOp::CreatePasskey {
                continue;
            }
            let Some(record) = rec.staged_passkey() else { continue };
            if held.iter().all(|h| h.record.credential_id != record.credential_id) {
                held.push(Held {
                    record,
                    item_id: String::new(),
                    field_id: String::new(),
                    title: rec.title,
                    staged: true,
                });
            }
        }
        Ok(Self { held })
    }

    /// Passkeys for `rp_id` (ASCII case ignored), narrowed to
    /// `allow_credentials` when it is not empty.
    pub fn candidates(&self, rp_id: &str, allow_credentials: &[Vec<u8>]) -> Vec<PasskeyCandidate> {
        self.held
            .iter()
            .filter(|h| h.record.rp_id.eq_ignore_ascii_case(rp_id))
            .filter(|h| allow_credentials.is_empty() || allow_credentials.contains(&h.record.credential_id))
            .map(|h| PasskeyCandidate {
                summary: h.record.summary(&h.item_id, &h.field_id),
                title: h.title.clone(),
                staged: h.staged,
            })
            .collect()
    }

    /// Every credential id held, for a registration's `excludeCredentials`.
    pub fn credential_ids(&self) -> Vec<Vec<u8>> {
        self.held.iter().map(|h| h.record.credential_id.clone()).collect()
    }

    /// Sign in with the passkey `request.credential_id`.
    ///
    /// Refuses a credential outside a non-empty `allow_credentials`, one that
    /// is not held, and (through [`sign::assert`]) one whose rpId is not
    /// `request.rp_id`.
    pub fn sign(&self, request: &SignRequest<'_>) -> Result<SignedAssertion> {
        if !request.allow_credentials.is_empty()
            && !request.allow_credentials.iter().any(|c| c.as_slice() == request.credential_id)
        {
            return Err(WalletError::InvalidInput("credential is not allowed by the request".into()));
        }
        let found = self
            .held
            .iter()
            .find(|h| h.record.credential_id == request.credential_id)
            .ok_or_else(|| WalletError::InvalidInput("no passkey with this credential id".into()))?;

        let assertion = sign::assert(&found.record, request.rp_id, request.client_data_hash, request.user_verified)?;
        let prf = match request.prf {
            None => None,
            Some(inputs) => prf::evaluate_inputs(&found.record, inputs, request.user_verified)?,
        };
        Ok(SignedAssertion { assertion, prf, item_id: found.item_id.clone(), staged: found.staged })
    }
}

/// Open the index and the journal, then sign: [`HeldPasskeys::open`] followed
/// by [`HeldPasskeys::sign`], for a provider that signs once per process.
pub fn sign_from_index(
    index: &[u8],
    index_key: &[u8; KEY_LEN],
    journal: &[u8],
    journal_keys: &[[u8; KEY_LEN]],
    request: &SignRequest<'_>,
) -> Result<SignedAssertion> {
    HeldPasskeys::open(index, index_key, journal, journal_keys)?.sign(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autofill::index::{IndexHeader, PasskeyIndexEntry};
    use crate::autofill::journal::PendingRecord;
    use crate::autofill::keys::generate_keys;
    use crate::passkey::sign::RegisterInput;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    struct Made {
        record: PasskeyRecord,
        spki: Vec<u8>,
    }

    fn make(rp: &str, user: &str) -> Made {
        let reg = sign::register(&RegisterInput {
            rp_id: rp,
            user_name: user,
            user_display_name: user,
            user_handle: user.as_bytes(),
            exclude_credentials: &[],
            held_credential_ids: &[],
            user_verified: true,
            now: 1,
        })
        .unwrap();
        Made { record: reg.record, spki: reg.public_key_spki }
    }

    fn sealed_index(key: &[u8; KEY_LEN], passkeys: &[PasskeyIndexEntry]) -> Vec<u8> {
        index::build_with_passkeys(
            &[],
            passkeys,
            key,
            &IndexHeader { format_version: index::FORMAT_VERSION, generation: 1, built_at: 0, database_id: "db".into() },
        )
        .unwrap()
    }

    fn verifies(made: &Made, signed: &SignedAssertion, hash: &[u8; 32]) -> bool {
        let key = VerifyingKey::from_public_key_der(&made.spki).unwrap();
        let sig = Signature::from_der(&signed.assertion.signature).unwrap();
        let mut msg = signed.assertion.authenticator_data.clone();
        msg.extend_from_slice(hash);
        key.verify(&msg, &sig).is_ok()
    }

    fn request<'a>(id: &'a [u8], rp: &'a str, hash: &'a [u8; 32]) -> SignRequest<'a> {
        SignRequest {
            credential_id: id,
            rp_id: rp,
            client_data_hash: hash,
            user_verified: true,
            allow_credentials: &[],
            prf: None,
        }
    }

    #[test]
    fn signs_from_the_index_and_from_the_journal() {
        let keys = generate_keys().unwrap();
        let staging = generate_keys().unwrap().index_key;
        let indexed = make("example.com", "alice");
        let staged = make("example.com", "bob");
        let index = sealed_index(&keys.index_key, &[PasskeyIndexEntry::new("item", "field", "Example", indexed.record.clone())]);
        let journal = journal::seal_record(
            &PendingRecord::new_passkey("p1", "Example", &staged.record, 1).unwrap(),
            &keys.journal_public,
            &staging,
            &keys.journal_auth_key,
        )
        .unwrap();
        let hash = [7u8; 32];

        let held = HeldPasskeys::open(&index, &keys.index_key, &journal, &[*staging]).unwrap();
        assert_eq!(format!("{held:?}"), "HeldPasskeys { count: 2 }");
        let candidates = held.candidates("EXAMPLE.com", &[]);
        assert_eq!(candidates.len(), 2);
        assert_eq!((candidates[0].staged, candidates[0].summary.item_id.as_str()), (false, "item"));
        assert_eq!((candidates[1].staged, candidates[1].summary.item_id.as_str()), (true, ""));
        assert_eq!(candidates[1].summary.user_name, "bob");

        let a = held.sign(&request(&indexed.record.credential_id, "example.com", &hash)).unwrap();
        assert!(verifies(&indexed, &a, &hash));
        assert_eq!((a.item_id.as_str(), a.staged), ("item", false));

        let b = sign_from_index(&index, &keys.index_key, &journal, &[*staging], &request(&staged.record.credential_id, "example.com", &hash))
            .unwrap();
        assert!(verifies(&staged, &b, &hash));
        assert!(b.staged && b.item_id.is_empty());
    }

    #[test]
    fn the_rp_id_check_and_the_allow_list_are_enforced() {
        let keys = generate_keys().unwrap();
        let made = make("example.com", "alice");
        let index = sealed_index(&keys.index_key, &[PasskeyIndexEntry::new("i", "f", "t", made.record.clone())]);
        let held = HeldPasskeys::open(&index, &keys.index_key, &[], &[]).unwrap();
        let id = made.record.credential_id.clone();
        let hash = [1u8; 32];

        assert!(held.sign(&request(&id, "other.example", &hash)).is_err(), "another rpId");
        assert!(held.sign(&request(&id, "sub.example.com", &hash)).is_err(), "a subdomain");
        assert!(held.sign(&request(b"unknown", "example.com", &hash)).is_err(), "not held");

        let others = vec![b"another".to_vec()];
        let mut narrowed = request(&id, "example.com", &hash);
        narrowed.allow_credentials = &others;
        assert!(held.sign(&narrowed).is_err(), "outside allowCredentials");
        let allowed = vec![id.clone()];
        narrowed.allow_credentials = &allowed;
        assert!(held.sign(&narrowed).is_ok());

        assert!(held.candidates("example.com", &others).is_empty());
        assert_eq!(held.candidates("example.com", &allowed).len(), 1);
        assert!(held.candidates("other.example", &[]).is_empty());
        assert_eq!(held.credential_ids(), vec![id]);
    }

    #[test]
    fn prf_is_answered_when_asked_for() {
        let keys = generate_keys().unwrap();
        let made = make("example.com", "alice");
        let index = sealed_index(&keys.index_key, &[PasskeyIndexEntry::new("i", "f", "t", made.record.clone())]);
        let held = HeldPasskeys::open(&index, &keys.index_key, &[], &[]).unwrap();
        let hash = [1u8; 32];
        let inputs = PrfInputs { first: b"salt".to_vec(), second: None };

        let mut req = request(&made.record.credential_id, "example.com", &hash);
        assert!(held.sign(&req).unwrap().prf.is_none());
        req.prf = Some(&inputs);
        let out = held.sign(&req).unwrap().prf.unwrap();
        assert_eq!(out, prf::evaluate_inputs(&made.record, &inputs, true).unwrap().unwrap());

        let too_long = PrfInputs { first: vec![0; prf::INPUT_MAX + 1], second: None };
        req.prf = Some(&too_long);
        assert!(held.sign(&req).is_err());
    }

    #[test]
    fn the_index_copy_wins_and_only_passkey_records_count() {
        let keys = generate_keys().unwrap();
        let made = make("example.com", "alice");
        let index = sealed_index(&keys.index_key, &[PasskeyIndexEntry::new("i", "f", "t", made.record.clone())]);
        let mut journal = journal::seal_record(
            &PendingRecord::new_passkey("p1", "Staged copy", &made.record, 1).unwrap(),
            &keys.journal_public,
            &keys.index_key,
            &keys.journal_auth_key,
        )
        .unwrap();
        let login = PendingRecord::new_login("l1", "Login", "https://example.com", "alice", "pw", 1);
        journal.extend_from_slice(
            &journal::seal_record(&login, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap(),
        );
        let mut broken = PendingRecord::new_login("b1", "Broken", "https://example.com", "alice", "", 1);
        broken.op = PendingOp::CreatePasskey;
        journal.extend_from_slice(
            &journal::seal_record(&broken, &keys.journal_public, &keys.index_key, &keys.journal_auth_key).unwrap(),
        );

        let held = HeldPasskeys::open(&index, &keys.index_key, &journal, &[]).unwrap();
        let c = held.candidates("example.com", &[]);
        assert_eq!(c.len(), 1);
        assert_eq!((c[0].title.as_str(), c[0].staged), ("t", false));
    }

    #[test]
    fn an_unreadable_index_is_an_error_and_an_empty_one_is_skipped() {
        let keys = generate_keys().unwrap();
        let other = generate_keys().unwrap();
        let index = sealed_index(&keys.index_key, &[]);
        assert!(HeldPasskeys::open(&index, &other.index_key, &[], &[]).is_err());
        assert!(HeldPasskeys::open(b"junk", &keys.index_key, &[], &[]).is_err());
        let empty = HeldPasskeys::open(&[], &keys.index_key, b"junk", &[]).unwrap();
        assert!(empty.credential_ids().is_empty());
    }
}
