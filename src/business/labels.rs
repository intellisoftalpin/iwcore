//! Label operations
//!
//! This module provides label management operations for the Wallet.

use std::collections::HashMap;
use chrono::Utc;
use crate::error::{WalletError, Result};
use crate::database::{IWLabel, queries};
use crate::database::queries::parse_timestamp;
use crate::utils::generate_label_id;
use super::wallet::Wallet;

impl Wallet {
    /// Add system labels to the database
    pub fn add_system_labels(&mut self) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        // System labels with their properties
        let system_labels = [
            ("MAIL", "Email", "mail", "mail"),
            ("PASS", "Password", "pass", "pass"),
            ("NOTE", "Note", "text", "note"),
            ("LINK", "Link", "link", "link"),
            ("ACNT", "Account", "text", "account"),
            ("CARD", "Card", "text", "card"),
            ("NAME", "Name", "text", "name"),
            ("PHON", "Phone", "phon", "phone"),
            ("PINC", "PIN", "pass", "pin"),
            ("USER", "Username", "text", "user"),
            ("OLDP", "Old Password", "pass", "oldpass"),
            ("DATE", "Date", "date", "date"),
            ("TIME", "Time", "time", "time"),
            ("EXPD", "Expiry Date", "date", "expiry"),
            ("SNUM", "Serial Number", "text", "serial"),
            ("ADDR", "Address", "text", "address"),
            ("SQUE", "Secret Question", "text", "question"),
            ("SANS", "Secret Answer", "pass", "answer"),
            ("2FAC", "2FA", "pass", "2fa"),
            ("SEED", "Seed Phrase", "text", "seed"),
        ];

        for (field_type, name, value_type, icon) in system_labels {
            queries::create_label(conn, field_type, name, value_type, icon, true)?;
        }

        self.labels_cache = None;
        Ok(())
    }

    /// Get all labels
    pub fn get_labels(&mut self) -> Result<Vec<IWLabel>> {
        self.load_labels_if_needed()?;
        let labels = self.labels_cache.as_ref().unwrap();
        let mut result: Vec<IWLabel> = labels.values().cloned().collect();

        // Sort: system first, then by name
        result.sort_by(|a, b| {
            match (a.system, b.system) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            }
        });

        Ok(result)
    }

    /// Load labels from database if not cached
    pub(crate) fn load_labels_if_needed(&mut self) -> Result<()> {
        if self.labels_cache.is_some() {
            return Ok(());
        }

        let db = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?;

        let conn = db.connection()?;
        let raw_labels = queries::get_all_labels(conn)?;

        let mut labels = HashMap::with_capacity(raw_labels.len());

        for raw in raw_labels {
            labels.insert(raw.field_type.clone(), IWLabel {
                field_type: raw.field_type,
                name: raw.label_name,
                value_type: raw.value_type,
                icon: raw.icon,
                system: raw.system,
                change_timestamp: raw.change_timestamp
                    .as_ref()
                    .and_then(|s| parse_timestamp(s))
                    .unwrap_or_else(Utc::now),
                deleted: raw.deleted,
                usage: raw.usage as u32,
            });
        }

        self.labels_cache = Some(labels);
        Ok(())
    }

    /// Add a new label
    pub fn add_label(&mut self, name: &str, icon: &str, value_type: &str) -> Result<String> {
        let label_id = generate_label_id();

        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        let created = queries::create_label(conn, &label_id, name, value_type, icon, false)?;

        if !created {
            return Err(WalletError::InvalidOperation("Failed to create label".to_string()));
        }

        self.labels_cache = None;
        Ok(label_id)
    }

    /// Update label name
    pub fn update_label_name(&mut self, field_type: &str, name: &str) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::update_label_name(conn, field_type, name)?;

        self.labels_cache = None;
        Ok(())
    }

    /// Update label icon
    pub fn update_label_icon(&mut self, field_type: &str, icon: &str) -> Result<()> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        queries::update_label_icon(conn, field_type, icon)?;

        self.labels_cache = None;
        Ok(())
    }

    /// Delete a label (returns usage count, only deletes if 0)
    pub fn delete_label(&mut self, field_type: &str) -> Result<i32> {
        let conn = self.db.as_ref()
            .ok_or_else(|| WalletError::DatabaseError("Database not open".to_string()))?
            .connection()?;

        let count = queries::delete_label(conn, field_type)?;

        self.labels_cache = None;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use crate::business::wallet::tests::create_test_wallet;

    #[test]
    fn test_labels() {
        let (mut wallet, _temp) = create_test_wallet();
        let labels = wallet.get_labels().unwrap();
        assert_eq!(labels.len(), 20); // System labels count
    }

    /// Test: CreateDeleteLabel from C# BusinessFixture
    #[test]
    fn test_create_delete_label() {
        let (mut wallet, _temp) = create_test_wallet();

        // Create custom label
        let label_id = wallet.add_label("Test Label 789", "labelcalendar", "date").unwrap();

        // Verify it exists
        let labels = wallet.get_labels().unwrap();
        let created = labels.iter().find(|l| l.field_type == label_id);
        assert!(created.is_some());
        let label = created.unwrap();
        assert_eq!(label.name, "Test Label 789");
        assert_eq!(label.value_type, "date");
        assert!(!label.system);

        // Delete it
        wallet.delete_label(&label_id).unwrap();

        // Verify it's gone
        let labels_after = wallet.get_labels().unwrap();
        let deleted = labels_after.iter().find(|l| l.field_type == label_id);
        assert!(deleted.is_none());
    }

    /// Test: UpdateLabelName
    #[test]
    fn test_update_label_name() {
        let (mut wallet, _temp) = create_test_wallet();
        let label_id = wallet.add_label("Original Label", "labelcalendar", "text").unwrap();

        wallet.update_label_name(&label_id, "Renamed Label").unwrap();

        let labels = wallet.get_labels().unwrap();
        let label = labels.iter().find(|l| l.field_type == label_id).unwrap();
        assert_eq!(label.name, "Renamed Label");
    }

    /// Test: UpdateLabelIcon
    #[test]
    fn test_update_label_icon() {
        let (mut wallet, _temp) = create_test_wallet();
        let label_id = wallet.add_label("Test Label", "labelcalendar", "text").unwrap();

        wallet.update_label_icon(&label_id, "labellink").unwrap();

        let labels = wallet.get_labels().unwrap();
        let label = labels.iter().find(|l| l.field_type == label_id).unwrap();
        assert_eq!(label.icon, "labellink");
    }
}
