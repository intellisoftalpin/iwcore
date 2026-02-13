//! PDF export functionality

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
}
