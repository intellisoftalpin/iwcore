//! base64url, as WebAuthn and CXF use it.
//!
//! Always **written** without padding. **Read** with or without padding, since
//! other managers' exports are not all strict about it.

use base64::alphabet::URL_SAFE;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use base64::engine::DecodePaddingMode;
use base64::Engine;

use crate::error::{Result, WalletError};

const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Encode as base64url without padding.
pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url, padded or not. `what` names the field in the error, so
/// the error never carries the value itself.
pub(crate) fn decode(text: &str, what: &str) -> Result<Vec<u8>> {
    LENIENT
        .decode(text)
        .map_err(|_| WalletError::InvalidInput(format!("{what} is not valid base64url")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_without_padding() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len as u8).collect();
            let text = encode(&data);
            assert!(!text.contains('=') && !text.contains('+') && !text.contains('/'));
            assert_eq!(decode(&text, "x").unwrap(), data);
        }
    }

    #[test]
    fn padded_input_is_accepted() {
        assert_eq!(decode("AQ==", "x").unwrap(), vec![1]);
        assert_eq!(decode("AQ", "x").unwrap(), vec![1]);
    }

    #[test]
    fn standard_alphabet_and_garbage_are_rejected_without_echoing_the_value() {
        for bad in ["a+b/", "!!!!", "A"] {
            let err = decode(bad, "credentialId").unwrap_err().to_string();
            assert!(err.contains("credentialId"));
            assert!(!err.contains(bad));
        }
    }
}
