//! Multi-format export functionality (PDF, CSV, JSON, XML)

use crate::error::Result;
use super::wallet::Wallet;

impl Wallet {
    /// Export all wallet data as a PDF document.
    ///
    /// Returns the PDF file contents as bytes.
    pub fn export_pdf(&mut self) -> Result<Vec<u8>> {
        self.ensure_unlocked()?;

        let items = self.get_items()?.to_vec();
        let fields = self.get_fields()?.to_vec();

        crate::export::generate_pdf(&items, &fields)
    }

    /// Export all wallet data as an RFC 4180 CSV document.
    ///
    /// Returns the CSV file contents as UTF-8 bytes.
    pub fn export_csv(&mut self) -> Result<Vec<u8>> {
        self.ensure_unlocked()?;

        let items = self.get_items()?.to_vec();
        let fields = self.get_fields()?.to_vec();

        crate::export::generate_csv(&items, &fields)
    }

    /// Export all wallet data as a JSON document.
    ///
    /// Returns pretty-printed JSON as UTF-8 bytes.
    pub fn export_json(&mut self) -> Result<Vec<u8>> {
        self.ensure_unlocked()?;

        let items = self.get_items()?.to_vec();
        let fields = self.get_fields()?.to_vec();

        crate::export::generate_json(&items, &fields)
    }

    /// Export all wallet data as an XML document.
    ///
    /// Returns the XML file contents as UTF-8 bytes.
    pub fn export_xml(&mut self) -> Result<Vec<u8>> {
        self.ensure_unlocked()?;

        let items = self.get_items()?.to_vec();
        let fields = self.get_fields()?.to_vec();

        crate::export::generate_xml(&items, &fields)
    }
}
