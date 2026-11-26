//! Which logins to suggest for the site being filled, in which order, and
//! under which heading.
//!
//! A provider shows the result in up to three labelled sections, always above
//! the complete alphabetical list:
//!
//! 1. [`Section::ForSite`]: logins that belong to this host. The exact host,
//!    then a parent (`oxisoft.net` on `auth.oxisoft.net`), then a child host.
//!    On a sign-on host (`auth.`, `sso.`, `login.`, see
//!    [`domain::SSO_LABELS`]) every login of the registrable domain belongs
//!    here too, since that one account usually serves all of them. The login
//!    the user picked on this exact host last time leads the section.
//! 2. [`Section::SameSite`]: other logins on the same registrable domain
//!    (siblings such as `chat.oxisoft.net`), closest first: one stored for a
//!    sign-on host, then deeper shared labels, then ones whose title or
//!    account names the host's own labels (`auth` in "OxiSoft Auth").
//! 3. [`Section::SameName`]: logins under a different registrable domain with
//!    the same site name ([`domain::site_name`]: `oxisoft.io` on
//!    `oxisoft.net`), and logins with no usable link whose title names the
//!    site. This is the weak section. Anyone can register `oxisoft.xyz`, so a
//!    provider must keep it visually apart, show the stored domain on every
//!    row, and never offer it in a one-tap surface (iOS QuickType, the
//!    Android "Logins for" block). Passkeys never use it.
//!
//! Every login appears at most once, under its strongest reason. Nothing here
//! fills anything: a suggestion still takes a tap.

use super::domain::{self, MatchTier};
use super::index::IndexEntry;

/// Heading a suggestion is listed under. Ordered for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Section {
    /// Logins for this host.
    ForSite,
    /// Other logins on this registrable domain.
    SameSite,
    /// Logins under another domain with the same site name. Weak.
    SameName,
}

/// Why a login is suggested. Also the label a provider may show on the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// The user picked this login on this exact host before.
    Picked,
    /// Stored for exactly this host.
    ExactHost,
    /// Stored for a parent of this host (`oxisoft.net` on `auth.oxisoft.net`).
    ParentHost,
    /// Stored for a host under this one (`auth.oxisoft.net` on `oxisoft.net`).
    ChildHost,
    /// A sibling on the same registrable domain, offered because this host or
    /// the stored one is a sign-on host.
    SignOn,
    /// Another host on the same registrable domain.
    Sibling,
    /// Another registrable domain with the same site name.
    SameName,
    /// No usable link; the title names the site.
    TitleName,
}

/// One suggested login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    /// Position of the login in the slice handed to [`suggest`].
    pub entry: usize,
    pub section: Section,
    pub reason: Reason,
    /// Higher is better within a section. Only the order is meaningful.
    pub score: u32,
    /// The stored host that matched, for display on the row. `None` for
    /// [`Reason::TitleName`], and for a [`Reason::Picked`] login that no
    /// longer matches by domain.
    pub host: Option<String>,
}

const SCORE_PICKED: u32 = 2000;
const SCORE_EXACT: u32 = 1000;
const SCORE_PARENT: u32 = 900;
const SCORE_CHILD: u32 = 800;
const SCORE_SIBLING: u32 = 500;
const BONUS_SSO_STORED: u32 = 40;
const BONUS_LABEL_IN_TEXT: u32 = 30;
const BONUS_PER_SHARED_LABEL: u32 = 20;
const MAX_SHARED_LABELS: u32 = 5;
const PENALTY_PER_LABEL: u32 = 10;
const MAX_DISTANCE: u32 = 9;
const SCORE_SAME_NAME: u32 = 300;
const SCORE_TITLE_NAME: u32 = 200;
/// Host labels shorter than this are not looked for in titles: `id` or `my`
/// appear inside far too many words.
const MIN_TEXT_LABEL_LEN: usize = 3;

/// Rank `entries` for the site at `query_host`.
///
/// `query_host` may be a raw URL or host; it is normalized here. `picked_item`
/// is the item the user chose on this exact host last time (see
/// [`super::picks`]): it leads [`Section::ForSite`] as long as it is still in
/// `entries`, whatever its links say, because it was the user's own choice for
/// this very host.
///
/// Returns suggestions sorted for display: by section, then score, then title
/// and account (case-insensitive), then position. A query without a usable
/// host yields only the picked login, if any.
pub fn suggest(entries: &[IndexEntry], query_host: &str, picked_item: Option<&str>) -> Vec<Suggestion> {
    let query = Query::new(query_host);
    let mut out: Vec<Suggestion> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, entry)| {
            let found = query.as_ref().and_then(|q| q.best(entry));
            if picked_item.is_some_and(|p| !p.is_empty() && p == entry.item_id) {
                return Some(Suggestion {
                    entry: i,
                    section: Section::ForSite,
                    reason: Reason::Picked,
                    score: SCORE_PICKED,
                    host: found.and_then(|f| f.host),
                });
            }
            found.map(|f| Suggestion { entry: i, section: f.section, reason: f.reason, score: f.score, host: f.host })
        })
        .collect();

    out.sort_by(|a, b| {
        a.section
            .cmp(&b.section)
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| sort_key(entries, a.entry).cmp(&sort_key(entries, b.entry)))
            .then_with(|| a.entry.cmp(&b.entry))
    });
    out
}

fn sort_key(entries: &[IndexEntry], i: usize) -> (String, String) {
    entries
        .get(i)
        .map(|e| (e.title.to_lowercase(), e.username.to_lowercase()))
        .unwrap_or_default()
}

struct Found {
    section: Section,
    reason: Reason,
    score: u32,
    host: Option<String>,
}

struct Query {
    host: String,
    registrable: Option<String>,
    name: Option<String>,
    sso: bool,
    /// Labels of the host left of its registrable domain (`auth` for
    /// `auth.oxisoft.net`), as looked for in titles and accounts.
    own_labels: Vec<String>,
}

impl Query {
    fn new(raw: &str) -> Option<Self> {
        let host = domain::normalize_host(raw)?;
        let registrable = domain::registrable_domain(&host);
        let own_labels = registrable
            .as_deref()
            .and_then(|reg| host.strip_suffix(reg))
            .map(|head| {
                head.split('.')
                    .filter(|l| l.len() >= MIN_TEXT_LABEL_LEN)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            name: domain::site_name(&host),
            sso: domain::is_sso_host(&host),
            registrable,
            own_labels,
            host,
        })
    }

    /// The strongest reason to suggest `entry`, over all its hosts.
    fn best(&self, entry: &IndexEntry) -> Option<Found> {
        let by_domain = entry
            .hosts
            .iter()
            .filter_map(|stored| self.by_host(entry, stored))
            .max_by(|a, b| b.section.cmp(&a.section).then_with(|| a.score.cmp(&b.score)));
        by_domain.or_else(|| self.by_name(entry))
    }

    fn by_host(&self, entry: &IndexEntry, stored: &str) -> Option<Found> {
        let found = |section, reason, score| Some(Found { section, reason, score, host: Some(stored.to_string()) });
        match domain::match_tier(stored, &self.host)? {
            MatchTier::ExactHost => found(Section::ForSite, Reason::ExactHost, SCORE_EXACT),
            MatchTier::HostSuffix if domain::is_subdomain_of(&self.host, stored) => found(
                Section::ForSite,
                Reason::ParentHost,
                SCORE_PARENT.saturating_sub(distance(&self.host, stored)),
            ),
            MatchTier::HostSuffix => found(
                Section::ForSite,
                Reason::ChildHost,
                SCORE_CHILD.saturating_sub(distance(stored, &self.host)),
            ),
            MatchTier::RegistrableDomain => {
                let stored_sso = domain::is_sso_host(stored);
                let mut score = SCORE_SIBLING.saturating_add(self.shared_labels(stored));
                if stored_sso {
                    score = score.saturating_add(BONUS_SSO_STORED);
                }
                if self.labels_named_in(entry) {
                    score = score.saturating_add(BONUS_LABEL_IN_TEXT);
                }
                let reason = if self.sso || stored_sso { Reason::SignOn } else { Reason::Sibling };
                let section = if self.sso { Section::ForSite } else { Section::SameSite };
                found(section, reason, score)
            }
        }
    }

    /// Same site name under another registrable domain, or a title naming the
    /// site on a login with no usable link.
    fn by_name(&self, entry: &IndexEntry) -> Option<Found> {
        let name = self.name.as_deref()?;
        if let Some(stored) = entry.hosts.iter().find(|h| {
            domain::site_name(h).as_deref() == Some(name) && domain::registrable_domain(h) != self.registrable
        }) {
            return Some(Found {
                section: Section::SameName,
                reason: Reason::SameName,
                score: SCORE_SAME_NAME,
                host: Some(stored.clone()),
            });
        }
        (entry.hosts.is_empty() && words(&entry.title).any(|w| w == name)).then_some(Found {
            section: Section::SameName,
            reason: Reason::TitleName,
            score: SCORE_TITLE_NAME,
            host: None,
        })
    }

    /// Bonus for labels a sibling shares with the query beyond the registrable
    /// domain: `a.b.example.com` is closer to `c.b.example.com` than to
    /// `example.com`'s other children.
    fn shared_labels(&self, stored: &str) -> u32 {
        let Some(reg) = self.registrable.as_deref() else { return 0 };
        let (Some(q), Some(s)) = (self.host.strip_suffix(reg), stored.strip_suffix(reg)) else {
            return 0;
        };
        let shared = q
            .trim_end_matches('.')
            .rsplit('.')
            .zip(s.trim_end_matches('.').rsplit('.'))
            .take_while(|(a, b)| !a.is_empty() && a == b)
            .count();
        u32::try_from(shared)
            .unwrap_or(MAX_SHARED_LABELS)
            .min(MAX_SHARED_LABELS)
            .saturating_mul(BONUS_PER_SHARED_LABEL)
    }

    /// Whether the entry's title or account names one of this host's own
    /// labels, as a whole word.
    fn labels_named_in(&self, entry: &IndexEntry) -> bool {
        self.own_labels
            .iter()
            .any(|label| words(&entry.title).chain(words(&entry.username)).any(|w| w == *label))
    }
}

/// Label distance between a host and one of its ancestors, capped.
fn distance(child: &str, ancestor: &str) -> u32 {
    let count = |h: &str| h.split('.').count();
    let d = count(child).saturating_sub(count(ancestor));
    u32::try_from(d)
        .unwrap_or(MAX_DISTANCE)
        .min(MAX_DISTANCE)
        .saturating_mul(PENALTY_PER_LABEL)
}

/// Lowercased alphanumeric words of a text.
fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, title: &str, user: &str, links: &[&str]) -> IndexEntry {
        let hosts: Vec<String> = links.iter().filter_map(|l| domain::normalize_host(l)).collect();
        let (registrable, names) = super::super::index::derived_keys(&hosts);
        IndexEntry {
            item_id: id.into(),
            title: title.into(),
            identity_type: "USER".into(),
            username: user.into(),
            password: "pw".into(),
            totp_secret: None,
            hosts,
            registrable,
            names,
        }
    }

    fn ids(entries: &[IndexEntry], got: &[Suggestion]) -> Vec<String> {
        got.iter().map(|s| entries[s.entry].item_id.clone()).collect()
    }

    fn of<'a>(got: &'a [Suggestion], entries: &[IndexEntry], id: &str) -> &'a Suggestion {
        got.iter().find(|s| entries[s.entry].item_id == id).unwrap()
    }

    /// The case that started this: many logins on one registrable domain, the
    /// right one alphabetically last. A plain tier sort cut at three hid it.
    fn oxisoft_vault() -> Vec<IndexEntry> {
        vec![
            entry("analytics", "Analytics", "bkv", &["https://analytics.oxisoft.net"]),
            entry("chat", "Chat", "bkv", &["chat.oxisoft.net"]),
            entry("gitea", "Gitea", "bkv", &["https://g.oxisoft.io/user/login"]),
            entry("pilot", "Pilot", "bkv", &["pilot.oxisoft.net"]),
            entry("root", "OxiSoft site", "admin", &["https://oxisoft.net"]),
            entry("sso", "Zz SSO", "bkv", &["https://auth.oxisoft.net/login"]),
            entry("notes", "OxiSoft notes", "bkv", &[]),
            entry("other", "Bank", "bkv", &["mybank.com"]),
        ]
    }

    #[test]
    fn the_exact_host_leads_however_it_sorts_alphabetically() {
        let v = oxisoft_vault();
        let got = suggest(&v, "https://auth.oxisoft.net/realms/x", None);
        assert_eq!(ids(&v, &got)[0], "sso");
        assert_eq!(of(&got, &v, "sso").reason, Reason::ExactHost);
    }

    #[test]
    fn on_a_sign_on_host_every_login_of_the_domain_is_for_this_site() {
        let v = oxisoft_vault();
        let got = suggest(&v, "auth.oxisoft.net", None);
        let for_site: Vec<String> = got
            .iter()
            .filter(|s| s.section == Section::ForSite)
            .map(|s| v[s.entry].item_id.clone())
            .collect();
        assert_eq!(for_site, ["sso", "root", "analytics", "chat", "pilot"]);
        assert_eq!(of(&got, &v, "root").reason, Reason::ParentHost);
        assert_eq!(of(&got, &v, "chat").reason, Reason::SignOn);
    }

    #[test]
    fn same_name_under_another_domain_is_a_separate_weak_section() {
        let v = oxisoft_vault();
        let got = suggest(&v, "auth.oxisoft.net", None);
        let gitea = of(&got, &v, "gitea");
        assert_eq!((gitea.section, gitea.reason), (Section::SameName, Reason::SameName));
        assert_eq!(gitea.host.as_deref(), Some("g.oxisoft.io"));
        let notes = of(&got, &v, "notes");
        assert_eq!((notes.section, notes.reason, notes.host.clone()), (Section::SameName, Reason::TitleName, None));
        assert!(got.iter().all(|s| v[s.entry].item_id != "other"));
        assert_eq!(ids(&v, &got).last().map(String::as_str), Some("notes"));
    }

    #[test]
    fn without_a_sign_on_host_siblings_are_other_logins_on_the_domain() {
        let v = oxisoft_vault();
        let got = suggest(&v, "chat.oxisoft.net", None);
        assert_eq!(ids(&v, &got)[..2], ["chat".to_string(), "root".to_string()]);
        let same_site: Vec<String> = got
            .iter()
            .filter(|s| s.section == Section::SameSite)
            .map(|s| v[s.entry].item_id.clone())
            .collect();
        // The login stored for the sign-on host leads the siblings.
        assert_eq!(same_site, ["sso", "analytics", "pilot"]);
        assert_eq!(of(&got, &v, "sso").reason, Reason::SignOn);
        assert_eq!(of(&got, &v, "pilot").reason, Reason::Sibling);
    }

    #[test]
    fn a_closer_parent_outranks_a_farther_one_and_a_parent_outranks_a_child() {
        let v = vec![
            entry("far", "A", "u", &["example.com"]),
            entry("near", "B", "u", &["b.example.com"]),
            entry("child", "C", "u", &["x.a.b.example.com"]),
        ];
        let got = suggest(&v, "a.b.example.com", None);
        assert_eq!(ids(&v, &got), ["near", "far", "child"]);
        assert_eq!(of(&got, &v, "child").reason, Reason::ChildHost);
        assert!(of(&got, &v, "near").score > of(&got, &v, "far").score);
    }

    #[test]
    fn deeper_shared_labels_and_named_labels_rank_siblings() {
        let v = vec![
            entry("plain", "Aaa", "u", &["mail.example.com"]),
            entry("deep", "Bbb", "u", &["x.eu.example.com"]),
            entry("named", "Ccc Shop", "u", &["www2.example.com"]),
        ];
        let got = suggest(&v, "shop.eu.example.com", None);
        assert_eq!(ids(&v, &got), ["named", "deep", "plain"]);
        assert_eq!(of(&got, &v, "named").score, SCORE_SIBLING + BONUS_LABEL_IN_TEXT);
        assert_eq!(of(&got, &v, "deep").score, SCORE_SIBLING + BONUS_PER_SHARED_LABEL);
        assert_eq!(of(&got, &v, "plain").score, SCORE_SIBLING);
        // The account counts as well as the title, as a whole word only.
        let v2 = vec![entry("u", "Zzz", "shop", &["www2.example.com"]), entry("w", "Zzz", "shopper", &["www3.example.com"])];
        let got2 = suggest(&v2, "shop.example.com", None);
        assert_eq!(ids(&v2, &got2), ["u", "w"]);
        assert_eq!(got2[1].score, SCORE_SIBLING);
        // A sign-on stored host adds its own bonus.
        let v3 = vec![entry("s", "Zzz", "u", &["sso.example.com"])];
        assert_eq!(suggest(&v3, "shop.example.com", None)[0].score, SCORE_SIBLING + BONUS_SSO_STORED);
    }

    #[test]
    fn the_picked_login_leads_even_without_a_domain_match() {
        let v = oxisoft_vault();
        let got = suggest(&v, "auth.oxisoft.net", Some("other"));
        let first = &got[0];
        assert_eq!((v[first.entry].item_id.as_str(), first.reason, first.section), ("other", Reason::Picked, Section::ForSite));
        assert_eq!(first.host, None);
        let got = suggest(&v, "auth.oxisoft.net", Some("chat"));
        assert_eq!(got[0].host.as_deref(), Some("chat.oxisoft.net"));
        assert_eq!(got.iter().filter(|s| v[s.entry].item_id == "chat").count(), 1);
    }

    #[test]
    fn an_unknown_or_empty_pick_changes_nothing() {
        let v = oxisoft_vault();
        let plain = suggest(&v, "auth.oxisoft.net", None);
        assert_eq!(suggest(&v, "auth.oxisoft.net", Some("gone")), plain);
        assert_eq!(suggest(&v, "auth.oxisoft.net", Some("")), plain);
    }

    #[test]
    fn no_usable_query_host_yields_only_the_pick() {
        let v = oxisoft_vault();
        assert!(suggest(&v, "", None).is_empty());
        assert!(suggest(&v, "javascript:alert(1)", None).is_empty());
        let got = suggest(&v, "", Some("chat"));
        assert_eq!(ids(&v, &got), ["chat"]);
    }

    #[test]
    fn shared_hosting_customers_never_match_each_other_by_name_or_domain() {
        let v = vec![
            entry("a", "Alice", "u", &["alice.github.io"]),
            entry("b", "Theirs", "u", &["theirs.onrender.com"]),
        ];
        assert!(suggest(&v, "mallory.github.io", None).is_empty());
        assert!(suggest(&v, "ours.onrender.com", None).is_empty());
        // `github.io` is private, so the label left of it is not a brand.
        assert!(suggest(&v, "alice.com", None).is_empty());
    }

    #[test]
    fn a_lookalike_name_is_not_the_same_name() {
        let v = vec![entry("o", "OxiSoft", "u", &["oxisoft.net"]), entry("t", "OxiSoft", "u", &[])];
        assert!(suggest(&v, "oxisoft-login.com", None).is_empty());
        assert!(suggest(&v, "oxisoftware.com", None).is_empty());
        assert!(suggest(&v, "oxisoft.net.evil.com", None).is_empty());
        // The same name under another ICANN suffix is offered, weakly.
        let got = suggest(&v, "oxisoft.xyz", None);
        assert!(got.iter().all(|s| s.section == Section::SameName));
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn generic_and_short_names_do_not_match_across_domains() {
        let v = vec![entry("a", "Login", "u", &["login.com"]), entry("b", "My", "u", &["my.de"]), entry("c", "auth", "u", &[])];
        assert!(suggest(&v, "login.de", None).is_empty());
        assert!(suggest(&v, "my.com", None).is_empty());
        assert!(suggest(&v, "auth.com", None).is_empty());
    }

    #[test]
    fn a_titled_login_with_links_elsewhere_is_not_a_title_match() {
        let v = vec![entry("gh", "OxiSoft GitHub", "u", &["github.com"])];
        assert!(suggest(&v, "oxisoft.net", None).is_empty());
    }

    #[test]
    fn the_best_host_of_a_multi_link_login_is_used_once() {
        let v = vec![entry("m", "Multi", "u", &["oxisoft.io", "chat.oxisoft.net", "auth.oxisoft.net"])];
        let got = suggest(&v, "auth.oxisoft.net", None);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].reason, got[0].host.as_deref()), (Reason::ExactHost, Some("auth.oxisoft.net")));
        // Of two siblings, the sign-on host is the closer one.
        let got = suggest(&v, "pilot.oxisoft.net", None);
        assert_eq!((got[0].section, got[0].host.as_deref()), (Section::SameSite, Some("auth.oxisoft.net")));
        let got = suggest(&v, "oxisoft.com", None);
        assert_eq!((got[0].section, got[0].host.as_deref()), (Section::SameName, Some("oxisoft.io")));
    }

    #[test]
    fn ties_sort_by_title_then_account_then_position() {
        let v = vec![
            entry("2", "b", "z", &["example.com"]),
            entry("1", "B", "a", &["example.com"]),
            entry("3", "a", "z", &["example.com"]),
            entry("4", "a", "z", &["example.com"]),
        ];
        assert_eq!(ids(&v, &suggest(&v, "example.com", None)), ["3", "4", "1", "2"]);
    }

    #[test]
    fn ip_literals_match_exactly_only() {
        let v = vec![entry("r", "Router", "admin", &["http://192.168.1.1/"]), entry("s", "Other", "admin", &["192.168.1.2"])];
        assert_eq!(ids(&v, &suggest(&v, "192.168.1.1:8080", None)), ["r"]);
    }

    #[test]
    fn distance_and_shared_labels_are_capped() {
        assert_eq!(distance("a.b.c.d.e.f.g.h.i.j.k.l.example.com", "example.com"), MAX_DISTANCE * PENALTY_PER_LABEL);
        assert_eq!(distance("a.example.com", "example.com"), PENALTY_PER_LABEL);
        let q = Query::new("a.b.c.d.e.f.g.example.com").unwrap();
        assert_eq!(q.shared_labels("z.b.c.d.e.f.g.example.com"), MAX_SHARED_LABELS * BONUS_PER_SHARED_LABEL);
        assert_eq!(q.shared_labels("other.com"), 0);
        let ip = Query::new("10.0.0.1").unwrap();
        assert_eq!(ip.shared_labels("10.0.0.1"), 0);
    }

    #[test]
    fn short_host_labels_are_not_looked_for_in_titles() {
        let q = Query::new("id.my.example.com").unwrap();
        assert!(q.own_labels.is_empty());
        let q = Query::new("shop.example.com").unwrap();
        assert_eq!(q.own_labels, ["shop"]);
    }

    /// The shared vectors the iOS extension's Swift ranking is tested against.
    #[test]
    fn the_shared_vectors_hold() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/autofill/suggest_vectors.json")).unwrap();
        let entries: Vec<IndexEntry> = doc["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let links: Vec<&str> = e["links"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect();
                entry(
                    e["item_id"].as_str().unwrap(),
                    e["title"].as_str().unwrap(),
                    e["username"].as_str().unwrap(),
                    &links,
                )
            })
            .collect();
        let cases = doc["cases"].as_array().unwrap();
        assert!(cases.len() >= 10);
        for case in cases {
            let query = case["query"].as_str().unwrap();
            let got: Vec<String> = suggest(&entries, query, case["picked"].as_str())
                .iter()
                .map(|s| format!("{} {:?} {:?}", entries[s.entry].item_id, s.section, s.reason))
                .collect();
            let want: Vec<String> = case["expect"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let row = row.as_array().unwrap();
                    format!("{} {} {}", row[0].as_str().unwrap(), row[1].as_str().unwrap(), row[2].as_str().unwrap())
                })
                .collect();
            assert_eq!(got, want, "query {query:?}");
        }
    }
}
