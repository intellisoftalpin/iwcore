//! ID generation utilities

use rand::Rng;

/// Characters used for ID generation
const ID_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Generate a unique string ID of specified length
pub fn generate_id(length: usize) -> String {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..ID_CHARS.len());
            ID_CHARS[idx] as char
        })
        .collect()
}

/// Generate an item ID (8 characters)
pub fn generate_item_id() -> String {
    generate_id(crate::ITEM_ID_LENGTH)
}

/// Generate a field ID (4 characters)
pub fn generate_field_id() -> String {
    generate_id(crate::FIELD_ID_LENGTH)
}

/// Generate a label ID (4 characters)
pub fn generate_label_id() -> String {
    generate_id(crate::LABEL_ID_LENGTH)
}

/// Generate a database ID (32 characters, UUID-like)
pub fn generate_database_id() -> String {
    uuid::Uuid::new_v4().to_string().replace("-", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id_length() {
        assert_eq!(generate_id(8).len(), 8);
        assert_eq!(generate_id(4).len(), 4);
        assert_eq!(generate_id(32).len(), 32);
    }

    #[test]
    fn test_generate_item_id() {
        let id = generate_item_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_database_id() {
        let id = generate_database_id();
        assert_eq!(id.len(), 32);
    }
}
