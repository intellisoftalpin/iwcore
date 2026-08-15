//! Login identity classification.
//!
//! A login entry carries exactly one identity field, never two. Three field
//! types can play that role, and this module decides which one a raw value
//! belongs in:
//!
//! - [`IdentityKind::Mail`] (`MAIL`) for email addresses
//! - [`IdentityKind::Account`] (`ACNT`) for identifier-shaped values: account
//!   numbers, member numbers, card numbers, phone-like digit strings
//! - [`IdentityKind::User`] (`USER`) for everything else
//!
//! The same three types, in the order `USER`, `MAIL`, `ACNT`, are also the
//! read-side priority when an existing vault entry happens to carry more than
//! one of them (see [`super::index`]). Write side and read side agree by
//! construction, which is what lets an entry round-trip out through the index
//! and back through the journal unchanged.
//!
//! `PHON` is deliberately not an identity type. Some sites do accept a phone
//! number as a login, but `PHON` is not produced here and not indexed on the
//! read side, so admitting it would break that symmetry. Digit-shaped logins
//! land in `ACNT` instead.

/// Which field type a login identity value belongs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityKind {
    /// `MAIL` - an email address.
    Mail,
    /// `USER` - a username or handle. The default.
    User,
    /// `ACNT` - an account number or other identifier.
    Account,
}

impl IdentityKind {
    /// The iwcore field type code for this kind.
    pub fn field_type(self) -> &'static str {
        match self {
            IdentityKind::Mail => "MAIL",
            IdentityKind::User => "USER",
            IdentityKind::Account => "ACNT",
        }
    }

    /// Parse a field type code back into a kind. Returns `None` for any code
    /// that is not one of the three identity types, which is what makes a
    /// nonsensical hint from the extension harmless: it is rejected here and
    /// the classifier decides instead.
    pub fn from_field_type(code: &str) -> Option<Self> {
        match code {
            "MAIL" => Some(IdentityKind::Mail),
            "USER" => Some(IdentityKind::User),
            "ACNT" => Some(IdentityKind::Account),
            _ => None,
        }
    }
}

/// Read-side priority. An entry carrying several identity fields indexes the
/// first of these that is present and non-empty.
pub const READ_PRIORITY: [IdentityKind; 3] =
    [IdentityKind::User, IdentityKind::Mail, IdentityKind::Account];

/// Characters that are punctuation inside an identifier rather than part of
/// it: they are ignored when deciding whether a value is digit-shaped, so
/// `4111 1111 1111 1111` and `+38 (067) 000-00-00` both read as identifiers.
const SEPARATORS: [char; 7] = ['-', '+', '.', ' ', '(', ')', '/'];

/// Classify a raw identity value.
///
/// Never fails and never panics: every input maps to exactly one kind, with
/// [`IdentityKind::User`] as the deliberate default rather than an error path.
/// Empty and whitespace-only values also map to `User`; callers are expected
/// to skip them before storing, but a classifier that could not be called on
/// arbitrary input would be a worse contract.
pub fn classify(value: &str) -> IdentityKind {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return IdentityKind::User;
    }
    if looks_like_email(trimmed) {
        return IdentityKind::Mail;
    }
    if looks_like_identifier(trimmed) {
        return IdentityKind::Account;
    }
    IdentityKind::User
}

/// Deliberately stricter than RFC 5322: exactly one `@`, a non-empty local
/// part, and a domain part that contains a dot and no whitespace. A value like
/// `a@b` is not treated as an email, because in a login field it is far more
/// likely to be a handle than an address.
fn looks_like_email(value: &str) -> bool {
    // Whitespace or control characters mean this is not a structured address,
    // whatever else it looks like. Keeps degenerate input (embedded NUL,
    // newlines) out of the MAIL bucket.
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    // A dot that starts or ends the domain does not count as a separator.
    match domain.find('.') {
        Some(0) => false,
        Some(idx) => idx + 1 < domain.len(),
        None => false,
    }
}

/// Identifier-shaped: once punctuation is removed, the value is non-empty,
/// contains at least one digit, and is at least half digits. That covers plain
/// account numbers (`1234567890`), padded ones (`0001`), card and phone
/// numbers, and mixed references like `AB-99-12345`, without swallowing
/// ordinary usernames that merely contain a year (`user_2024`).
fn looks_like_identifier(value: &str) -> bool {
    let core: Vec<char> = value.chars().filter(|c| !SEPARATORS.contains(c)).collect();
    if core.is_empty() {
        return false;
    }
    let digits = core.iter().filter(|c| c.is_ascii_digit()).count();
    digits > 0 && digits * 2 >= core.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_type_codes_round_trip() {
        for kind in READ_PRIORITY {
            assert_eq!(IdentityKind::from_field_type(kind.field_type()), Some(kind));
        }
    }

    #[test]
    fn non_identity_field_types_are_rejected() {
        // The hint from the extension is untrusted input. Anything that is not
        // one of the three identity types must not become a field type.
        for code in ["PASS", "NOTE", "PHON", "LINK", "SEED", "", "mail", "MAI"] {
            assert_eq!(
                IdentityKind::from_field_type(code),
                None,
                "{code} must not be accepted as an identity type"
            );
        }
    }

    #[test]
    fn emails_classify_as_mail() {
        for value in [
            "a@bkv.me",
            "first.last+tag@sub.example.co.uk",
            "UPPER@Example.COM",
            "user@example.travel",
            "имя@пример.рф",
            "123456@example.com",
        ] {
            assert_eq!(classify(value), IdentityKind::Mail, "{value}");
        }
    }

    #[test]
    fn near_emails_do_not_classify_as_mail() {
        for value in [
            "a@b",           // no dot in the domain
            "@example.com",  // empty local part
            "user@",         // empty domain
            "a@b@c.com",     // two separators
            "user example@example.com", // whitespace
            "user@.com",     // domain starts with a dot
            "user@example.", // domain ends with a dot
        ] {
            assert_ne!(classify(value), IdentityKind::Mail, "{value}");
        }
    }

    #[test]
    fn identifiers_classify_as_account() {
        for value in [
            "1234567890",
            "0001",
            "4111 1111 1111 1111",
            "+38 067 000 00 00",
            "+38 (067) 000-00-00",
            "AB-99-12345",
            "07700900123",
        ] {
            assert_eq!(classify(value), IdentityKind::Account, "{value}");
        }
    }

    #[test]
    fn usernames_classify_as_user() {
        for value in [
            "bkv",
            "john.doe",
            "user_2024",
            "админ",
            "O'Brien",
            "a",
            "some.long.handle",
        ] {
            assert_eq!(classify(value), IdentityKind::User, "{value}");
        }
    }

    #[test]
    fn degenerate_input_defaults_to_user_without_panicking() {
        for value in ["", "   ", "\t\n", "-", "---", "()"] {
            assert_eq!(classify(value), IdentityKind::User, "{value:?}");
        }
    }

    #[test]
    fn very_long_and_exotic_input_does_not_panic() {
        let long = "a".repeat(4000);
        assert_eq!(classify(&long), IdentityKind::User);

        let long_digits = "1".repeat(4000);
        assert_eq!(classify(&long_digits), IdentityKind::Account);

        // Embedded control characters must not be treated as an email and must
        // not blow up the classifier.
        assert_ne!(classify("user\u{0}@example.com\n"), IdentityKind::Mail);
    }

    #[test]
    fn leading_and_trailing_whitespace_is_ignored() {
        assert_eq!(classify("  a@bkv.me  "), IdentityKind::Mail);
        assert_eq!(classify("\t1234\n"), IdentityKind::Account);
        assert_eq!(classify("  bkv  "), IdentityKind::User);
    }
}
