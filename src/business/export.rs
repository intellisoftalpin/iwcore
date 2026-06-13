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

#[cfg(test)]
mod tests {
    use crate::Wallet;
    use crate::business::wallet::tests::create_test_wallet;
    use tempfile::TempDir;

    /// A wallet with a folder, a nested entry with two fields, and a top-level
    /// note whose value contains characters that must be escaped (`<`, `&`).
    fn populated() -> (Wallet, TempDir) {
        let (mut wallet, temp) = create_test_wallet();
        let folder = wallet.add_item("Banking", "folder", true, None).unwrap();
        let item = wallet.add_item("My Bank", "bank", false, Some(&folder)).unwrap();
        wallet.add_field(&item, "MAIL", "user@example.com", None).unwrap();
        wallet.add_field(&item, "PASS", "s3cr3t!", None).unwrap();
        let note = wallet.add_item("Note", "document", false, None).unwrap();
        wallet.add_field(&note, "NOTE", "a<b & c \"д\"", None).unwrap();
        (wallet, temp)
    }

    #[test]
    fn export_pdf_produces_pdf_bytes() {
        let (mut wallet, _t) = populated();
        let pdf = wallet.export_pdf().unwrap();
        assert!(pdf.len() > 100, "PDF should have real content");
        assert_eq!(&pdf[..4], b"%PDF", "should start with the PDF magic header");
    }

    #[test]
    fn export_csv_contains_values() {
        let (mut wallet, _t) = populated();
        let csv = String::from_utf8(wallet.export_csv().unwrap()).unwrap();
        assert!(csv.contains("My Bank"));
        assert!(csv.contains("user@example.com"));
        assert!(csv.contains("s3cr3t!"));
    }

    #[test]
    fn export_json_is_valid_and_contains_values() {
        let (mut wallet, _t) = populated();
        let json = String::from_utf8(wallet.export_json().unwrap()).unwrap();
        assert!(json.contains("user@example.com"));
        // Must be syntactically valid JSON.
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn export_xml_contains_values_and_escapes_specials() {
        let (mut wallet, _t) = populated();
        let xml = String::from_utf8(wallet.export_xml().unwrap()).unwrap();
        assert!(xml.contains("user@example.com"));
        // The raw `<` and `&` from the note value must be entity-escaped.
        assert!(xml.contains("&lt;"));
        assert!(xml.contains("&amp;"));
        assert!(!xml.contains("a<b & c"), "raw specials must not appear unescaped");
    }

    #[test]
    fn exports_require_unlock() {
        let (mut wallet, _t) = create_test_wallet();
        wallet.lock();
        assert!(wallet.export_pdf().is_err());
        assert!(wallet.export_csv().is_err());
        assert!(wallet.export_json().is_err());
        assert!(wallet.export_xml().is_err());
    }
}
