//! Host normalization and registrable-domain computation for autofill matching.
//!
//! `LINK` field values are free text. Users paste full URLs, bare hosts, hosts
//! with ports, and occasionally junk. Everything in this module runs on the
//! **app** side while the index is built, and the results are stored in the
//! index precomputed, so the iOS AutoFill extension only ever does plain string
//! comparison and never needs a public suffix list of its own.
//!
//! # Why the registrable domain matters
//!
//! Matching on the bare last two labels is wrong for multi-label suffixes:
//! `login.example.co.uk` and `evil.co.uk` would both reduce to `co.uk` and
//! appear to match each other. For a password manager that is not a cosmetic
//! bug, so the registrable domain (eTLD+1) is computed against the full Mozilla
//! Public Suffix List (ICANN and private sections, the `psl` crate), and a
//! candidate that is itself a public suffix is rejected outright. Hosting
//! suffixes such as `onrender.com` or `github.io` are in the private section,
//! so two customers of the same host never match each other.
//!
//! Until 0.8 this module carried a curated subset of the list for logins and
//! used the full list only for passkeys. The subset let `a.onrender.com` and
//! `b.onrender.com` count as one site; both now use the same full list.

/// Match strength between a stored entry and the site being filled.
///
/// Ordered weakest first, so `max` picks the best host of a multi-link entry.
/// Since 0.8 a parent or child host outranks a mere sibling: a login stored
/// for `oxisoft.net` belongs to `auth.oxisoft.net` more surely than one
/// stored for `chat.oxisoft.net` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchTier {
    /// Both resolve to the same registrable domain (eTLD+1) and neither host
    /// sits under the other: siblings such as `chat.example.com` and
    /// `auth.example.com`.
    RegistrableDomain,
    /// One host sits under the other at a label boundary, inside the same
    /// registrable domain: `example.com` and `auth.example.com`.
    HostSuffix,
    /// Byte-for-byte identical hosts.
    ExactHost,
}

/// URI schemes that never denote a web login target. A `LINK` field holding one
/// of these yields no host at all rather than a bogus one.
const REJECTED_SCHEMES: [&str; 8] = [
    "mailto", "javascript", "data", "tel", "sms", "file", "about", "blob",
];

/// True if `candidate` is itself a public suffix under the full Public Suffix
/// List (`com`, `co.uk`, `github.io`, `onrender.com`), so it can never be a
/// matching key.
pub fn is_public_suffix(candidate: &str) -> bool {
    !candidate.is_empty() && psl::suffix_str(candidate) == Some(candidate)
}

/// Normalize a raw `LINK` value into a comparable host.
///
/// Strips the scheme, path, query, fragment, userinfo and port; lowercases;
/// removes a trailing root dot and a leading `www.`; and converts non-ASCII
/// labels to punycode so a host typed in Cyrillic matches the `xn--` form iOS
/// supplies. Returns `None` for anything that does not yield a plausible host.
///
/// Never panics, whatever the input.
pub fn normalize_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Scheme. `://` is the common form; a bare `scheme:` prefix is how the
    // schemes we reject (mailto:, javascript:, ...) actually appear.
    let after_scheme = match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            if is_rejected_scheme(scheme) {
                return None;
            }
            rest
        }
        None => {
            if let Some((scheme, _)) = trimmed.split_once(':')
                && is_rejected_scheme(scheme)
            {
                return None;
            }
            trimmed
        }
    };

    // Protocol-relative form (`//example.com/x`), which users do paste.
    let after_scheme = after_scheme.strip_prefix("//").unwrap_or(after_scheme);

    // Authority ends at the first path, query or fragment delimiter. A
    // backslash counts as a path delimiter too, as it does in browsers for
    // http(s): `https://a.com\@b.com/` opens a.com, so it must name a.com.
    let authority = after_scheme
        .split(['/', '?', '#', '\\'])
        .next()
        .unwrap_or(after_scheme);
    if authority.is_empty() {
        return None;
    }

    // Userinfo: everything up to and including the last `@`.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, host)| host);

    let host = strip_port(host_port)?;
    if host.is_empty() {
        return None;
    }

    let lowered = host.to_lowercase();
    let no_root_dot = lowered.trim_end_matches('.');
    if no_root_dot.is_empty() {
        return None;
    }

    let ascii = to_ascii_host(no_root_dot)?;
    let stripped = ascii.strip_prefix("www.").unwrap_or(&ascii);
    if stripped.is_empty() {
        return None;
    }

    is_plausible_host(stripped).then(|| stripped.to_string())
}

/// Compute the registrable domain (eTLD+1) of an already-normalized host,
/// under the full Public Suffix List.
///
/// Returns `None` for IP literals, single-label hosts, and any host that is
/// itself a public suffix, because none of those may be used as a matching key:
/// treating `co.uk` as a registrable domain would match every British site
/// against every other.
pub fn registrable_domain(host: &str) -> Option<String> {
    if !host.contains('.') {
        return None;
    }
    psl_registrable_domain(host).map(str::to_string)
}

/// Strength of the match between a stored host and the host being filled.
/// `None` means the two are unrelated and the entry must not be suggested by
/// domain at all.
pub fn match_tier(stored_host: &str, query_host: &str) -> Option<MatchTier> {
    if stored_host.is_empty() || query_host.is_empty() {
        return None;
    }
    if stored_host == query_host {
        return Some(MatchTier::ExactHost);
    }
    let (Some(stored_reg), Some(query_reg)) = (registrable_domain(stored_host), registrable_domain(query_host)) else {
        return None;
    };
    if stored_reg != query_reg {
        return None;
    }
    // A label-aligned suffix relationship, so `example.com` cannot match
    // `notexample.com`; both sit inside one registrable domain here.
    if is_subdomain_of(stored_host, query_host) || is_subdomain_of(query_host, stored_host) {
        return Some(MatchTier::HostSuffix);
    }
    Some(MatchTier::RegistrableDomain)
}

/// Labels too generic to name a site: a login for `auth.de` says nothing
/// about `auth.com`. A site name equal to one of these is never used for
/// matching across registrable domains. Sorted, so lookups are a binary
/// search (a test keeps it sorted).
pub const GENERIC_NAME_LABELS: &[&str] = &[
    "account", "accounts", "admin", "auth", "cloud", "demo", "email", "example",
    "home", "identity", "internal", "intranet", "local", "localhost", "login",
    "mail", "online", "portal", "secure", "server", "service", "services",
    "shop", "signin", "site", "store", "test", "webmail",
];

/// Shortest site name used for matching across registrable domains. Shorter
/// names (`my`, `go`, `abc`) collide between unrelated owners far too often.
pub const MIN_SITE_NAME_LEN: usize = 4;

/// First labels that mark a single sign-on or identity host (`auth.example.com`,
/// `sso.example.com`). A login on such a host is typically the account for
/// every service of that registrable domain.
pub const SSO_LABELS: &[&str] = &["accounts", "auth", "id", "identity", "login", "sso"];

/// The site name of a normalized host: the label left of its public suffix
/// (`oxisoft` for `auth.oxisoft.net`, `example` for `login.example.co.uk`).
///
/// It is what lets `oxisoft.net` and `oxisoft.io` be recognised as the same
/// name under different registrable domains. That is a weak signal, anyone
/// can register `oxisoft.xyz`, so callers must keep such matches apart from
/// real domain matches (see [`super::suggest`](mod@super::suggest)). To keep it as narrow as it
/// can be, `None` is returned unless:
///
/// - the public suffix is from the ICANN section of the list (a private
///   hosting suffix, `alice.github.io`, names a customer, not a brand);
/// - the name is at least [`MIN_SITE_NAME_LEN`] characters long, is not all
///   digits and is not in [`GENERIC_NAME_LABELS`].
pub fn site_name(host: &str) -> Option<String> {
    // No separate guard for empty hosts or IP literals: neither has an ICANN
    // suffix (an IPv4 address ends in a number, an IPv6 literal has no dot),
    // so both are refused below. The tests pin that.
    let domain = psl::domain(host.as_bytes())?;
    if domain.suffix().typ() != Some(psl::Type::Icann) {
        return None;
    }
    let registrable = std::str::from_utf8(domain.as_bytes()).ok()?;
    let name = registrable.split('.').next()?;
    is_usable_site_name(name).then(|| name.to_string())
}

/// Whether a word may serve as a site name: long enough, not a number and not
/// a generic label. Shared with title matching, so a title word is held to
/// exactly the same bar as a domain label.
pub fn is_usable_site_name(name: &str) -> bool {
    name.chars().count() >= MIN_SITE_NAME_LEN
        && !name.bytes().all(|b| b.is_ascii_digit())
        && GENERIC_NAME_LABELS.binary_search(&name).is_err()
}

/// True when the first label of a normalized host marks a sign-on host
/// ([`SSO_LABELS`]) and the host has a registrable domain below it.
pub fn is_sso_host(host: &str) -> bool {
    let Some(registrable) = registrable_domain(host) else {
        return false;
    };
    if registrable == host {
        return false;
    }
    host.split('.').next().is_some_and(|first| SSO_LABELS.contains(&first))
}

/// True when `child` sits under `parent` at a label boundary.
pub(crate) fn is_subdomain_of(child: &str, parent: &str) -> bool {
    child
        .strip_suffix(parent)
        .is_some_and(|head| head.ends_with('.'))
}

fn is_rejected_scheme(scheme: &str) -> bool {
    let lowered = scheme.trim().to_ascii_lowercase();
    REJECTED_SCHEMES.contains(&lowered.as_str())
}

/// Remove a `:port` suffix, handling bracketed IPv6 literals. Returns `None`
/// when the authority is structurally broken (an unclosed bracket).
fn strip_port(host_port: &str) -> Option<&str> {
    if let Some(rest) = host_port.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host);
    }
    match host_port.rsplit_once(':') {
        Some((host, port)) => {
            // Only a genuinely numeric tail is a port. A bare unbracketed IPv6
            // literal has several colons and no numeric-only tail, and is left
            // intact rather than truncated.
            if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                Some(host)
            } else {
                Some(host_port)
            }
        }
        None => Some(host_port),
    }
}

fn is_plausible_host(host: &str) -> bool {
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return false;
    }
    if host.starts_with('-') || host.ends_with('-') {
        return false;
    }
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b':')
}

/// Registrable domain of a normalized host under the full Public Suffix List
/// (ICANN and private sections, `psl` crate), as WebAuthn scopes passkeys.
///
/// The curated list above is enough to rank logins, but a passkey is bound to
/// its rpId: two hosts under a hosting suffix the curated list does not carry
/// (`a.onrender.com`, `b.onrender.com`) belong to different owners. Returns
/// `None` for IP literals and for hosts that are themselves public suffixes.
pub(crate) fn psl_registrable_domain(host: &str) -> Option<&str> {
    if host.is_empty() || is_ip_literal(host) {
        return None;
    }
    psl::domain_str(host)
}

/// May a passkey for `rp_id` sit on a login stored for `stored_host`?
///
/// Yes when both normalize to the same host, or when both have the same
/// registrable domain under the full Public Suffix List.
pub(crate) fn passkey_matches_host(stored_host: &str, rp_id: &str) -> bool {
    let (Some(stored), Some(rp)) = (normalize_host(stored_host), normalize_host(rp_id)) else {
        return false;
    };
    if stored == rp {
        return true;
    }
    matches!(
        (psl_registrable_domain(&stored), psl_registrable_domain(&rp)),
        (Some(a), Some(b)) if a == b
    )
}

fn is_ip_literal(host: &str) -> bool {
    // IPv6 (already unbracketed by strip_port) always contains a colon.
    if host.contains(':') {
        return true;
    }
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets
            .iter()
            .all(|o| !o.is_empty() && o.len() <= 3 && o.bytes().all(|b| b.is_ascii_digit()))
}

/// Convert a host to its ASCII (punycode) form, label by label. ASCII labels
/// pass through untouched, which is the overwhelming majority of real input.
fn to_ascii_host(host: &str) -> Option<String> {
    if host.is_ascii() {
        return Some(host.to_string());
    }
    let mut out = String::with_capacity(host.len());
    for (i, label) in host.split('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        if label.is_ascii() {
            out.push_str(label);
        } else {
            out.push_str("xn--");
            out.push_str(&punycode_encode(label)?);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Punycode (RFC 3492), encoding only.
//
// Deliberately hand-rolled rather than pulled in as a dependency: the full IDNA
// crate chain costs roughly twenty transitive crates in a published security
// library, and this is a deterministic string encoding with published test
// vectors. Note that UTS-46 mapping is NOT applied; input is lowercased by the
// caller and otherwise used as-is, which covers ordinary IDN hosts.
// ---------------------------------------------------------------------------

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

/// Largest `delta` `adapt` leaves unscaled, per RFC 3492 section 6.1.
const ADAPT_LIMIT: u32 = ((BASE - TMIN) * TMAX) / 2;
/// Digit alphabet, value 0 to 35.
const DIGITS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Every step is checked arithmetic: an overflow (which RFC 3492 itself
/// treats as a failure) or any impossible state yields `None`, never a panic or
/// a wrapped value.
fn punycode_encode(label: &str) -> Option<String> {
    let input: Vec<u32> = label.chars().map(u32::from).collect();
    let mut output = String::new();

    for &c in &input {
        if c < INITIAL_N {
            output.push(char::from_u32(c)?);
        }
    }
    // Basic code points are ASCII, so bytes and chars agree.
    let basic_count = u32::try_from(output.len()).ok()?;
    let total = u32::try_from(input.len()).ok()?;
    let mut handled = basic_count;
    if basic_count > 0 {
        output.push('-');
    }

    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;

    while handled < total {
        let m = *input.iter().filter(|&&c| c >= n).min()?;
        delta = delta.checked_add(m.checked_sub(n)?.checked_mul(handled.checked_add(1)?)?)?;
        n = m;

        for &c in &input {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    // TMIN when k <= bias, TMAX when k >= bias + TMAX, else k - bias.
                    let t = k.saturating_sub(bias).clamp(TMIN, TMAX);
                    if q < t {
                        break;
                    }
                    let span = BASE.checked_sub(t)?;
                    let rest = q.checked_sub(t)?;
                    output.push(digit_to_char(t.checked_add(rest.checked_rem(span)?)?)?);
                    q = rest.checked_div(span)?;
                    k = k.checked_add(BASE)?;
                }
                output.push(digit_to_char(q)?);
                let next = handled.checked_add(1)?;
                bias = adapt(delta, next, handled == basic_count)?;
                delta = 0;
                handled = next;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }

    Some(output)
}

fn adapt(delta: u32, numpoints: u32, first_time: bool) -> Option<u32> {
    let mut delta = delta.checked_div(if first_time { DAMP } else { 2 })?;
    delta = delta.checked_add(delta.checked_div(numpoints)?)?;
    let mut k: u32 = 0;
    while delta > ADAPT_LIMIT {
        delta = delta.checked_div(BASE - TMIN)?;
        k = k.checked_add(BASE)?;
    }
    let scaled = (BASE - TMIN + 1).checked_mul(delta)?.checked_div(delta.checked_add(SKEW)?)?;
    k.checked_add(scaled)
}

fn digit_to_char(d: u32) -> Option<char> {
    DIGITS.get(usize::try_from(d).ok()?).map(|&b| char::from(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_name_labels_are_sorted_for_binary_search() {
        let mut sorted = GENERIC_NAME_LABELS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(GENERIC_NAME_LABELS, sorted.as_slice());
    }

    #[test]
    fn public_suffixes_come_from_the_full_list() {
        for s in ["com", "co.uk", "com.ua", "github.io", "onrender.com", "blogspot.com"] {
            assert!(is_public_suffix(s), "{s}");
        }
        for d in ["example.com", "example.co.uk", "alice.github.io", ""] {
            assert!(!is_public_suffix(d), "{d}");
        }
    }

    #[test]
    fn site_names_are_the_label_left_of_an_icann_suffix() {
        assert_eq!(site_name("auth.oxisoft.net").as_deref(), Some("oxisoft"));
        assert_eq!(site_name("oxisoft.io").as_deref(), Some("oxisoft"));
        // `example` is a generic label: the reserved documentation domain.
        assert_eq!(site_name("login.example.co.uk"), None);
        assert_eq!(site_name("login.acmecorp.co.uk").as_deref(), Some("acmecorp"));
        assert_eq!(site_name("shop.mybank.com.ua").as_deref(), Some("mybank"));
    }

    #[test]
    fn site_names_refuse_private_suffixes_short_generic_numeric_and_ip() {
        for host in [
            "alice.github.io",
            "ours.onrender.com",
            "my.com",
            "abc.com",
            "auth.de",
            "login.com",
            "12345.com",
            "192.168.1.1",
            "::1",
            "localhost",
            "com",
            "",
        ] {
            assert_eq!(site_name(host), None, "{host}");
        }
    }

    #[test]
    fn usable_site_names_need_four_characters_counted_as_characters() {
        assert!(is_usable_site_name("abcd"));
        assert!(!is_usable_site_name("abc"));
        assert!(!is_usable_site_name("щит"));
        assert!(is_usable_site_name("щита"));
        assert!(!is_usable_site_name("2026"));
        assert!(is_usable_site_name("2026a"));
        assert!(!is_usable_site_name("portal"));
    }

    #[test]
    fn sso_hosts_are_sign_on_labels_under_a_registrable_domain() {
        for host in ["auth.oxisoft.net", "sso.example.co.uk", "id.example.com", "accounts.google.com"] {
            assert!(is_sso_host(host), "{host}");
        }
        for host in ["oxisoft.net", "auth.de", "chat.oxisoft.net", "authx.example.com", "auth", "auth.github.io", ""] {
            assert!(!is_sso_host(host), "{host}");
        }
    }

    #[test]
    fn strips_scheme_path_query_fragment_and_port() {
        for raw in [
            "https://example.com",
            "http://example.com/login",
            "https://example.com:8443/login?next=1#form",
            "example.com/login",
            "example.com:8080",
            "//example.com/x",
            "  https://example.com/  ",
        ] {
            assert_eq!(normalize_host(raw).as_deref(), Some("example.com"), "{raw}");
        }
    }

    #[test]
    fn strips_userinfo_and_www_and_case_and_root_dot() {
        for raw in [
            "https://user:pass@www.Example.COM/",
            "WWW.EXAMPLE.COM",
            "example.com.",
            "https://user@example.com",
        ] {
            assert_eq!(normalize_host(raw).as_deref(), Some("example.com"), "{raw}");
        }
    }

    #[test]
    fn www_is_only_stripped_as_a_whole_label() {
        assert_eq!(normalize_host("wwwexample.com").as_deref(), Some("wwwexample.com"));
        assert_eq!(normalize_host("www2.example.com").as_deref(), Some("www2.example.com"));
    }

    #[test]
    fn rejects_non_web_schemes_and_junk() {
        for raw in [
            "mailto:a@example.com",
            "javascript:alert(1)",
            "data:text/html,x",
            "tel:+380670000000",
            "file:///etc/passwd",
            "about:blank",
            "",
            "   ",
            "https://",
            "/just/a/path",
            "?query=only",
        ] {
            assert_eq!(normalize_host(raw), None, "{raw:?} should not yield a host");
        }
    }

    #[test]
    fn malformed_input_never_panics() {
        for raw in [
            "https://[unclosed",
            "::::",
            "..",
            "-example.com",
            "example.com-",
            "a..b",
            "\u{0}\u{1}",
            "https://:8080",
        ] {
            let _ = normalize_host(raw);
        }
    }

    #[test]
    fn punycode_matches_published_vectors() {
        // Canonical, widely published IDN examples.
        assert_eq!(punycode_encode("bücher").as_deref(), Some("bcher-kva"));
        assert_eq!(punycode_encode("münchen").as_deref(), Some("mnchen-3ya"));
        assert_eq!(punycode_encode("рф").as_deref(), Some("p1ai"));
        assert_eq!(punycode_encode("пример").as_deref(), Some("e1afmkfd"));
    }

    /// RFC 3492 treats an overflowing `delta` as a failure. The encoder must
    /// report it as `None`, not wrap (release) or panic (debug).
    #[test]
    fn punycode_overflow_is_a_failure_not_a_wrap() {
        let huge = format!("{}\u{10FFFF}", "a".repeat(5000));
        assert_eq!(punycode_encode(&huge), None);
        assert_eq!(normalize_host(&format!("https://{huge}.com/")), None);
        // Long, but within range: still encodes.
        let fine = format!("{}é", "a".repeat(50));
        assert!(punycode_encode(&fine).is_some());
    }

    #[test]
    fn digits_map_to_the_rfc_alphabet_and_nothing_past_it() {
        assert_eq!(digit_to_char(0), Some('a'));
        assert_eq!(digit_to_char(25), Some('z'));
        assert_eq!(digit_to_char(26), Some('0'));
        assert_eq!(digit_to_char(35), Some('9'));
        assert_eq!(digit_to_char(36), None);
        assert_eq!(digit_to_char(u32::MAX), None);
    }

    #[test]
    fn a_backslash_ends_the_authority_as_in_a_browser() {
        assert_eq!(normalize_host("https://bank.com\\@evil.com/").as_deref(), Some("bank.com"));
        assert_eq!(normalize_host("https://bank.com\\@evil.com/login").as_deref(), Some("bank.com"));
        assert_eq!(normalize_host("bank.com\\@evil.com").as_deref(), Some("bank.com"));
        assert_eq!(normalize_host("https://user@bank.com\\path").as_deref(), Some("bank.com"));
        assert_eq!(normalize_host("https://bank.com:443\\x").as_deref(), Some("bank.com"));
        assert_eq!(normalize_host("https://\\evil.com"), None);
    }

    #[test]
    fn an_encoded_at_sign_is_not_a_userinfo_delimiter() {
        // `%40` stays part of the host, which then is no valid host at all.
        assert_eq!(normalize_host("https://bank.com%40evil.com/"), None);
        // In the userinfo it is just an encoded character.
        assert_eq!(normalize_host("https://me%40mail.com@bank.com/").as_deref(), Some("bank.com"));
        assert_eq!(normalize_host("https://bank.com%40evil.com@real.com/").as_deref(), Some("real.com"));
    }

    #[test]
    fn idn_hosts_normalize_to_punycode() {
        assert_eq!(normalize_host("пример.рф").as_deref(), Some("xn--e1afmkfd.xn--p1ai"));
        assert_eq!(normalize_host("https://Bücher.de/x").as_deref(), Some("xn--bcher-kva.de"));
        // Mixed: only the non-ASCII label is encoded.
        assert_eq!(normalize_host("münchen.example.com").as_deref(), Some("xn--mnchen-3ya.example.com"));
    }

    #[test]
    fn registrable_domain_handles_plain_gtlds() {
        assert_eq!(registrable_domain("example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("login.example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("a.b.c.example.org").as_deref(), Some("example.org"));
    }

    #[test]
    fn registrable_domain_respects_multi_label_suffixes() {
        assert_eq!(registrable_domain("example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable_domain("login.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable_domain("shop.example.com.ua").as_deref(), Some("example.com.ua"));
        assert_eq!(registrable_domain("user.github.io").as_deref(), Some("user.github.io"));
        assert_eq!(registrable_domain("blog.user.github.io").as_deref(), Some("user.github.io"));
    }

    #[test]
    fn bare_public_suffixes_have_no_registrable_domain() {
        // The whole point: `co.uk` must never become a matching key.
        for host in ["co.uk", "com.ua", "github.io", "blogspot.com"] {
            assert_eq!(registrable_domain(host), None, "{host}");
        }
    }

    #[test]
    fn ip_literals_and_single_labels_have_no_registrable_domain() {
        for host in ["192.168.1.1", "8.8.8.8", "localhost", "::1", "fe80::1"] {
            assert_eq!(registrable_domain(host), None, "{host}");
        }
    }

    #[test]
    fn ip_literals_normalize_but_stay_exact_match_only() {
        assert_eq!(normalize_host("http://192.168.1.1:8080/admin").as_deref(), Some("192.168.1.1"));
        assert_eq!(normalize_host("https://[::1]:8080/").as_deref(), Some("::1"));
        assert_eq!(
            match_tier("192.168.1.1", "192.168.1.1"),
            Some(MatchTier::ExactHost)
        );
        assert_eq!(match_tier("192.168.1.1", "192.168.1.2"), None);
    }

    #[test]
    fn an_empty_host_never_matches() {
        assert_eq!(match_tier("", "example.com"), None);
        assert_eq!(match_tier("example.com", ""), None);
        assert_eq!(match_tier("", ""), None);
    }

    #[test]
    fn match_tiers_rank_as_documented() {
        assert_eq!(match_tier("example.com", "example.com"), Some(MatchTier::ExactHost));
        assert_eq!(match_tier("example.com", "login.example.com"), Some(MatchTier::HostSuffix));
        assert_eq!(match_tier("login.example.com", "example.com"), Some(MatchTier::HostSuffix));
        assert_eq!(match_tier("example.co.uk", "login.example.co.uk"), Some(MatchTier::HostSuffix));
        assert_eq!(match_tier("chat.example.com", "auth.example.com"), Some(MatchTier::RegistrableDomain));
        assert!(MatchTier::ExactHost > MatchTier::HostSuffix);
        assert!(MatchTier::HostSuffix > MatchTier::RegistrableDomain);
    }

    #[test]
    fn unrelated_hosts_under_a_shared_suffix_do_not_match() {
        // The regression this module exists to prevent.
        assert_eq!(match_tier("example.co.uk", "evil.co.uk"), None);
        assert_eq!(match_tier("mybank.com.ua", "phisher.com.ua"), None);
        assert_eq!(match_tier("alice.github.io", "mallory.github.io"), None);
        // Hosting suffixes the old curated list lacked separate owners too.
        assert_eq!(match_tier("theirs.onrender.com", "ours.onrender.com"), None);
        assert_eq!(match_tier("onrender.com", "ours.onrender.com"), None);
        // And no accidental substring matching.
        assert_eq!(match_tier("example.com", "notexample.com"), None);
        assert_eq!(match_tier("example.com", "example.com.evil.net"), None);
    }

    #[test]
    fn passkeys_match_by_exact_host_or_the_full_public_suffix_list() {
        // Exact host, after normalization.
        assert!(passkey_matches_host("https://www.Example.com/login", "example.com"));
        assert!(passkey_matches_host("localhost", "localhost"));
        // Same registrable domain under the full list.
        assert!(passkey_matches_host("example.com", "login.example.com"));
        assert!(passkey_matches_host("app.example.co.uk", "example.co.uk"));
        // Hosting suffixes the curated list does not carry still separate owners.
        assert!(!passkey_matches_host("theirs.onrender.com", "ours.onrender.com"));
        assert!(!passkey_matches_host("alice.github.io", "mallory.github.io"));
        assert!(!passkey_matches_host("example.co.uk", "other.co.uk"));
        // A public suffix, an IP literal or junk never matches by domain.
        assert!(!passkey_matches_host("onrender.com", "ours.onrender.com"));
        assert!(!passkey_matches_host("10.0.0.1", "10.0.0.2"));
        assert!(!passkey_matches_host("", "example.com"));
        assert!(!passkey_matches_host("example.com", "javascript:alert(1)"));
        assert!(!passkey_matches_host("example.com", "notexample.com"));
    }

    #[test]
    fn psl_registrable_domain_refuses_suffixes_and_ip_literals() {
        assert_eq!(psl_registrable_domain("a.b.example.com"), Some("example.com"));
        assert_eq!(psl_registrable_domain("ours.onrender.com"), Some("ours.onrender.com"));
        assert_eq!(psl_registrable_domain("onrender.com"), None);
        assert_eq!(psl_registrable_domain("co.uk"), None);
        assert_eq!(psl_registrable_domain("192.168.1.1"), None);
        assert_eq!(psl_registrable_domain("::1"), None);
        assert_eq!(psl_registrable_domain(""), None);
    }
}
