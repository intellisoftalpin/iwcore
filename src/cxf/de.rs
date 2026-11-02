//! Reading CXF JSON without building a document tree.
//!
//! Every reader takes the shape it expects and skips any other value with
//! [`IgnoredAny`], which keeps nothing; members nobody reads are skipped the
//! same way. Strings borrow from the payload where JSON allows it, and
//! credentials stay raw slices of the payload until they are mapped, one at a
//! time. Memory therefore follows what the import keeps, not the size of the
//! payload, and the item, credential and collection limits stop the reading as
//! soon as they are crossed.
//!
//! The rules are those of a plain JSON reader: a member of the wrong JSON type
//! counts as absent, and of two members with the same name the last one wins.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::value::RawValue;

use super::{COLLECTIONS_MAX, COLLECTION_DEPTH_MAX, CREDENTIALS_PER_ITEM_MAX, CUSTOM_FIELDS_MAX, ENTRIES_MAX, ITEMS_MAX};

/// Counters shared by the readers of one payload, and the limit that stopped
/// the reading, if any.
#[derive(Debug, Default)]
pub(crate) struct Ctx {
    items: usize,
    collections: usize,
    entries: usize,
    pub limit: Option<&'static str>,
}

impl Ctx {
    fn stop<E: de::Error>(&mut self, msg: &'static str) -> E {
        self.limit = Some(msg);
        E::custom(msg)
    }

    /// Count one kept list entry against [`ENTRIES_MAX`].
    fn entry<E: de::Error>(&mut self) -> Result<(), E> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > ENTRIES_MAX {
            return Err(self.stop("CXF payload has more than 1 000 000 list entries"));
        }
        Ok(())
    }
}

fn drain_seq<'de, A: SeqAccess<'de>>(mut seq: A) -> Result<(), A::Error> {
    while seq.next_element::<IgnoredAny>()?.is_some() {}
    Ok(())
}

fn drain_map<'de, A: MapAccess<'de>>(mut map: A) -> Result<(), A::Error> {
    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
    Ok(())
}

/// The visit methods for every JSON kind a reader does not want: the value is
/// consumed and `None` returned. `seq` and `map` are listed separately so a
/// reader can take one of them.
macro_rules! skip_scalars {
    () => {
        fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    };
}
macro_rules! skip_seq {
    () => {
        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
            drain_seq(seq).map(|()| None)
        }
    };
}
macro_rules! skip_map {
    () => {
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            drain_map(map).map(|()| None)
        }
    };
}

// --- shapes without context ---------------------------------------------------

/// A JSON shape a reader accepts; every other kind of value is skipped.
pub(crate) trait Shape<'de>: Sized {
    fn from_str(_: Cow<'de, str>) -> Option<Self> {
        None
    }
    fn from_u64(_: u64) -> Option<Self> {
        None
    }
    fn from_i64(_: i64) -> Option<Self> {
        None
    }
    fn from_seq<A: SeqAccess<'de>>(seq: A) -> Result<Option<Self>, A::Error> {
        drain_seq(seq).map(|()| None)
    }
    fn from_map<A: MapAccess<'de>>(map: A) -> Result<Option<Self>, A::Error> {
        drain_map(map).map(|()| None)
    }
}

/// `Some` when the value had the expected shape.
pub(crate) struct Loose<T>(pub Option<T>);

impl<'de, T: Shape<'de>> Deserialize<'de> for Loose<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(LooseVisitor(PhantomData)).map(Loose)
    }
}

struct LooseVisitor<T>(PhantomData<T>);

impl<'de, T: Shape<'de>> Visitor<'de> for LooseVisitor<T> {
    type Value = Option<T>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(T::from_i64(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(T::from_u64(v))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
        Ok(T::from_str(Cow::Borrowed(v)))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(T::from_str(Cow::Owned(v.to_owned())))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(T::from_str(Cow::Owned(v)))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        T::from_seq(seq)
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        T::from_map(map)
    }
}

/// Read a value of shape `T`; `None` for any other shape.
fn value<'de, T: Shape<'de>, A: MapAccess<'de>>(map: &mut A) -> Result<Option<T>, A::Error> {
    map.next_value::<Loose<T>>().map(|l| l.0)
}

/// The next member name. JSON names are always strings.
fn key<'de, A: MapAccess<'de>>(map: &mut A) -> Result<Option<Cow<'de, str>>, A::Error> {
    Ok(map.next_key::<Loose<Cow<'de, str>>>()?.map(|k| k.0.unwrap_or_default()))
}

/// Skip the value of the member just read.
fn skip<'de, A: MapAccess<'de>>(map: &mut A) -> Result<(), A::Error> {
    map.next_value::<IgnoredAny>().map(|_| ())
}

impl<'de> Shape<'de> for Cow<'de, str> {
    fn from_str(v: Cow<'de, str>) -> Option<Self> {
        Some(v)
    }
}

impl<'de> Shape<'de> for u64 {
    fn from_u64(v: u64) -> Option<Self> {
        Some(v)
    }
    fn from_i64(v: i64) -> Option<Self> {
        u64::try_from(v).ok()
    }
}

impl<'de> Shape<'de> for i64 {
    fn from_u64(v: u64) -> Option<Self> {
        i64::try_from(v).ok()
    }
    fn from_i64(v: i64) -> Option<Self> {
        Some(v)
    }
}

/// `{"version": {"major": ...}}`.
#[derive(Debug, Default)]
pub(crate) struct Version {
    pub major: Option<u64>,
}

impl<'de> Shape<'de> for Version {
    fn from_map<A: MapAccess<'de>>(mut map: A) -> Result<Option<Self>, A::Error> {
        let mut out = Self::default();
        while let Some(k) = key(&mut map)? {
            match k.as_ref() {
                "major" => out.major = value(&mut map)?,
                _ => skip(&mut map)?,
            }
        }
        Ok(Some(out))
    }
}

/// An item's `scope`.
#[derive(Debug, Default)]
pub(crate) struct Scope<'a> {
    pub urls: Vec<Cow<'a, str>>,
    pub android_apps: Vec<Cow<'a, str>>,
}

struct ScopeSeed<'c>(&'c mut Ctx);

impl<'de> DeserializeSeed<'de> for ScopeSeed<'_> {
    type Value = Option<Scope<'de>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ScopeSeed<'_> {
    type Value = Option<Scope<'de>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a CXF scope")
    }
    skip_scalars!();
    skip_seq!();
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = Scope::default();
        while let Some(k) = key(&mut map)? {
            match k.as_ref() {
                "urls" => out.urls = map.next_value_seed(ListSeed::new(&mut *self.0))?.unwrap_or_default(),
                "androidApps" => {
                    out.android_apps = map
                        .next_value_seed(ListSeed::<AndroidApp>::new(&mut *self.0))?
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|a| a.0)
                        .collect();
                }
                _ => skip(&mut map)?,
            }
        }
        Ok(Some(out))
    }
}

/// An array of `T`, each kept element counted against [`ENTRIES_MAX`];
/// elements of another shape are left out, any other value reads as `None`.
struct ListSeed<'c, T> {
    ctx: &'c mut Ctx,
    of: PhantomData<T>,
}

impl<'c, T> ListSeed<'c, T> {
    fn new(ctx: &'c mut Ctx) -> Self {
        Self { ctx, of: PhantomData }
    }
}

impl<'de, T: Shape<'de>> DeserializeSeed<'de> for ListSeed<'_, T> {
    type Value = Option<Vec<T>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de, T: Shape<'de>> Visitor<'de> for ListSeed<'_, T> {
    type Value = Option<Vec<T>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON array")
    }
    skip_scalars!();
    skip_map!();
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Loose(v)) = seq.next_element::<Loose<T>>()? {
            if let Some(v) = v {
                self.ctx.entry()?;
                out.push(v);
            }
        }
        Ok(Some(out))
    }
}

struct AndroidApp<'a>(Option<Cow<'a, str>>);

impl<'de> Shape<'de> for AndroidApp<'de> {
    fn from_map<A: MapAccess<'de>>(mut map: A) -> Result<Option<Self>, A::Error> {
        let mut bundle = None;
        while let Some(k) = key(&mut map)? {
            match k.as_ref() {
                "bundleId" => bundle = value(&mut map)?,
                _ => skip(&mut map)?,
            }
        }
        Ok(Some(Self(bundle)))
    }
}

/// A collection's link to an item: `{"item": ..., "account": ...}`.
#[derive(Debug, Default)]
pub(crate) struct Link<'a> {
    pub item: Option<Cow<'a, str>>,
    pub account: Option<Cow<'a, str>>,
}

impl<'de> Shape<'de> for Link<'de> {
    fn from_map<A: MapAccess<'de>>(mut map: A) -> Result<Option<Self>, A::Error> {
        let mut out = Self::default();
        while let Some(k) = key(&mut map)? {
            match k.as_ref() {
                "item" => out.item = value(&mut map)?,
                "account" => out.account = value(&mut map)?,
                _ => skip(&mut map)?,
            }
        }
        Ok(Some(out))
    }
}

/// An editable field, `{"fieldType": ..., "value": ..., "label": ...}`, or a
/// custom field, which has the same members.
#[derive(Debug, Default)]
pub(crate) struct Ef<'a> {
    pub field_type: Option<Cow<'a, str>>,
    pub value: Option<Cow<'a, str>>,
    pub label: Option<Cow<'a, str>>,
}

impl<'de> Shape<'de> for Ef<'de> {
    fn from_map<A: MapAccess<'de>>(mut map: A) -> Result<Option<Self>, A::Error> {
        let mut out = Self::default();
        while let Some(k) = key(&mut map)? {
            match k.as_ref() {
                "fieldType" => out.field_type = value(&mut map)?,
                "value" => out.value = value(&mut map)?,
                "label" => out.label = value(&mut map)?,
                _ => skip(&mut map)?,
            }
        }
        Ok(Some(out))
    }
}

// --- the document ---------------------------------------------------------------

/// The members of the document root that are read.
#[derive(Debug, Default)]
pub(crate) struct RawHeader<'a> {
    pub version: Option<Version>,
    pub exporter_display_name: Option<Cow<'a, str>>,
    pub timestamp: Option<u64>,
    pub accounts: Option<Vec<RawAccount<'a>>>,
}

#[derive(Debug, Default)]
pub(crate) struct RawAccount<'a> {
    pub id: Option<Cow<'a, str>>,
    pub username: Option<Cow<'a, str>>,
    pub email: Option<Cow<'a, str>>,
    pub collections: Vec<RawCollection<'a>>,
    pub items: Vec<RawItem<'a>>,
}

#[derive(Debug, Default)]
pub(crate) struct RawCollection<'a> {
    pub title: Option<Cow<'a, str>>,
    pub links: Vec<Link<'a>>,
    pub sub: Vec<RawCollection<'a>>,
}

#[derive(Debug, Default)]
pub(crate) struct RawItem<'a> {
    pub id: Option<Cow<'a, str>>,
    pub creation_at: Option<i64>,
    pub title: Option<Cow<'a, str>>,
    pub subtitle: Option<Cow<'a, str>>,
    pub scope: Option<Scope<'a>>,
    pub tags: Vec<Cow<'a, str>>,
    /// Every element of `credentials`, unread.
    pub credentials: Vec<&'a RawValue>,
}

/// Read the document root. `None` when it is not a JSON object.
pub(crate) fn header<'a>(json: &'a str, ctx: &mut Ctx) -> serde_json::Result<Option<RawHeader<'a>>> {
    let mut de = serde_json::Deserializer::from_str(json);
    let out = RootSeed(ctx).deserialize(&mut de)?;
    de.end()?;
    Ok(out)
}

struct RootSeed<'c>(&'c mut Ctx);

impl<'de> DeserializeSeed<'de> for RootSeed<'_> {
    type Value = Option<RawHeader<'de>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for RootSeed<'_> {
    type Value = Option<RawHeader<'de>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a CXF document")
    }
    skip_scalars!();
    skip_seq!();
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = RawHeader::default();
        while let Some(k) = key(&mut map)? {
            match k.as_ref() {
                "version" => out.version = value(&mut map)?,
                "exporterDisplayName" => out.exporter_display_name = value(&mut map)?,
                "timestamp" => out.timestamp = value(&mut map)?,
                "accounts" => out.accounts = map.next_value_seed(AccountsSeed(&mut *self.0))?,
                _ => skip(&mut map)?,
            }
        }
        Ok(Some(out))
    }
}

/// `accounts`: `None` when it is not an array; elements that are not objects
/// are left out.
struct AccountsSeed<'c>(&'c mut Ctx);

impl<'de> DeserializeSeed<'de> for AccountsSeed<'_> {
    type Value = Option<Vec<RawAccount<'de>>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for AccountsSeed<'_> {
    type Value = Option<Vec<RawAccount<'de>>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("CXF accounts")
    }
    skip_scalars!();
    skip_map!();
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(account) = seq.next_element_seed(AccountSeed(&mut *self.0))? {
            out.extend(account);
        }
        Ok(Some(out))
    }
}

struct AccountSeed<'c>(&'c mut Ctx);

impl<'de> DeserializeSeed<'de> for AccountSeed<'_> {
    type Value = Option<RawAccount<'de>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for AccountSeed<'_> {
    type Value = Option<RawAccount<'de>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a CXF account")
    }
    skip_scalars!();
    skip_seq!();
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = RawAccount::default();
        while let Some(k) = key(&mut map)? {
            match k.as_ref() {
                "id" => out.id = value(&mut map)?,
                "username" => out.username = value(&mut map)?,
                "email" => out.email = value(&mut map)?,
                "items" => out.items = map.next_value_seed(ItemsSeed(&mut *self.0))?.unwrap_or_default(),
                "collections" => {
                    out.collections = map.next_value_seed(CollectionsSeed { ctx: &mut *self.0, depth: 1 })?.unwrap_or_default();
                }
                _ => skip(&mut map)?,
            }
        }
        Ok(Some(out))
    }
}

/// An account's `items`, counted against [`ITEMS_MAX`] across accounts.
struct ItemsSeed<'c>(&'c mut Ctx);

impl<'de> DeserializeSeed<'de> for ItemsSeed<'_> {
    type Value = Option<Vec<RawItem<'de>>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ItemsSeed<'_> {
    type Value = Option<Vec<RawItem<'de>>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("CXF items")
    }
    skip_scalars!();
    skip_map!();
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(item) = seq.next_element_seed(ItemSeed(&mut *self.0))? {
            let Some(item) = item else { continue };
            self.0.items = self.0.items.saturating_add(1);
            if self.0.items > ITEMS_MAX {
                return Err(self.0.stop("CXF payload has more than 100 000 items"));
            }
            self.0.entry()?;
            out.push(item);
        }
        Ok(Some(out))
    }
}

struct ItemSeed<'c>(&'c mut Ctx);

impl<'de> DeserializeSeed<'de> for ItemSeed<'_> {
    type Value = Option<RawItem<'de>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ItemSeed<'_> {
    type Value = Option<RawItem<'de>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a CXF item")
    }
    skip_scalars!();
    skip_seq!();
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = RawItem::default();
        while let Some(k) = key(&mut map)? {
            match k.as_ref() {
                "id" => out.id = value(&mut map)?,
                "creationAt" => out.creation_at = value(&mut map)?,
                "title" => out.title = value(&mut map)?,
                "subtitle" => out.subtitle = value(&mut map)?,
                "scope" => out.scope = map.next_value_seed(ScopeSeed(&mut *self.0))?,
                "tags" => out.tags = map.next_value_seed(ListSeed::new(&mut *self.0))?.unwrap_or_default(),
                "credentials" => out.credentials = map.next_value_seed(CredentialsSeed(&mut *self.0))?.unwrap_or_default(),
                _ => skip(&mut map)?,
            }
        }
        Ok(Some(out))
    }
}

/// An item's `credentials`, at most [`CREDENTIALS_PER_ITEM_MAX`], kept unread.
struct CredentialsSeed<'c>(&'c mut Ctx);

impl<'de> DeserializeSeed<'de> for CredentialsSeed<'_> {
    type Value = Option<Vec<&'de RawValue>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for CredentialsSeed<'_> {
    type Value = Option<Vec<&'de RawValue>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("CXF credentials")
    }
    skip_scalars!();
    skip_map!();
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(raw) = seq.next_element::<&'de RawValue>()? {
            if out.len() >= CREDENTIALS_PER_ITEM_MAX {
                return Err(self.0.stop("a CXF item has more than 64 credentials"));
            }
            self.0.entry()?;
            out.push(raw);
        }
        Ok(Some(out))
    }
}

/// `collections` or `subCollections` at `depth`.
struct CollectionsSeed<'c> {
    ctx: &'c mut Ctx,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for CollectionsSeed<'_> {
    type Value = Option<Vec<RawCollection<'de>>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for CollectionsSeed<'_> {
    type Value = Option<Vec<RawCollection<'de>>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("CXF collections")
    }
    skip_scalars!();
    skip_map!();
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(c) = seq.next_element_seed(CollectionSeed { ctx: &mut *self.ctx, depth: self.depth })? {
            out.extend(c);
        }
        Ok(Some(out))
    }
}

struct CollectionSeed<'c> {
    ctx: &'c mut Ctx,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for CollectionSeed<'_> {
    type Value = Option<RawCollection<'de>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for CollectionSeed<'_> {
    type Value = Option<RawCollection<'de>>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a CXF collection")
    }
    skip_scalars!();
    skip_seq!();
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        if self.depth > COLLECTION_DEPTH_MAX {
            return Err(self.ctx.stop("CXF collections are nested deeper than 32 levels"));
        }
        self.ctx.collections = self.ctx.collections.saturating_add(1);
        if self.ctx.collections > COLLECTIONS_MAX {
            return Err(self.ctx.stop("CXF payload has more than 100 000 collections"));
        }
        self.ctx.entry()?;
        let mut out = RawCollection::default();
        while let Some(k) = key(&mut map)? {
            match k.as_ref() {
                "title" => out.title = value(&mut map)?,
                "items" => out.links = map.next_value_seed(ListSeed::new(&mut *self.ctx))?.unwrap_or_default(),
                "subCollections" => {
                    let depth = self.depth.saturating_add(1);
                    out.sub = map.next_value_seed(CollectionsSeed { ctx: &mut *self.ctx, depth })?.unwrap_or_default();
                }
                _ => skip(&mut map)?,
            }
        }
        Ok(Some(out))
    }
}

// --- one credential ---------------------------------------------------------------

/// String members some credential type reads.
const STR_MEMBERS: &[&str] = &[
    "type", "algorithm", "secret", "issuer", "username", "password", "privateKey", "keyType", "keyComment",
    "credentialId", "rpId", "userDisplayName", "userHandle", "key", "label",
];
/// Editable-field members some credential type reads by name.
const EF_MEMBERS: &[&str] = &[
    "username", "password", "content", "number", "fullName", "verificationNumber", "pin", "expiryDate", "cardType",
    "validFrom", "networkSecurityType", "hidden", "ssid", "passphrase", "streetAddress", "postalCode", "city",
    "territory", "country", "tel", "title", "given", "given2", "surnamePrefix", "surname", "surname2", "generation",
    "credentials", "givenInformal", "key", "url", "keyType", "creationDate", "keyGenerationSource", "licenseNumber",
    "passportNumber", "documentNumber", "birthDate", "issueDate",
];

/// A credential member that is kept.
#[derive(Debug)]
pub(crate) enum Member<'a> {
    Str(Cow<'a, str>),
    Num(u64),
    Ef(Ef<'a>),
    /// `fields` of a `custom-fields` credential.
    Fields(Fields<'a>),
    /// `fido2Extensions`, unread.
    Raw(&'a RawValue),
}

/// The `fields` of a `custom-fields` credential: at most
/// [`CUSTOM_FIELDS_MAX`] kept, and whether there were more.
#[derive(Debug, Default)]
pub(crate) struct Fields<'a> {
    pub list: Vec<Ef<'a>>,
    pub over: bool,
}

impl<'de> Shape<'de> for Fields<'de> {
    fn from_seq<A: SeqAccess<'de>>(mut seq: A) -> Result<Option<Self>, A::Error> {
        let mut out = Self::default();
        let mut n = 0usize;
        while let Some(Loose(f)) = seq.next_element::<Loose<Ef>>()? {
            n = n.saturating_add(1);
            if n > CUSTOM_FIELDS_MAX {
                out.over = true;
                out.list = Vec::new();
                drain_seq(seq)?;
                break;
            }
            out.list.extend(f);
        }
        Ok(Some(out))
    }
}

/// The members of one credential that some mapping reads, by name (in name
/// order, as a JSON object map iterates). Editable fields under names no
/// mapping knows are kept for identity documents, up to
/// [`CUSTOM_FIELDS_MAX`]; `over` says there were more.
#[derive(Debug, Default)]
pub(crate) struct Cred<'a> {
    pub members: BTreeMap<Cow<'a, str>, Member<'a>>,
    pub over: bool,
}

impl<'a> Cred<'a> {
    /// Read one credential. Anything that is not an object reads as empty.
    pub fn read(raw: &'a RawValue) -> Self {
        serde_json::from_str::<Loose<Cred<'a>>>(raw.get()).ok().and_then(|l| l.0).unwrap_or_default()
    }

    pub fn str(&self, k: &str) -> Option<&str> {
        match self.members.get(k) {
            Some(Member::Str(s)) => Some(s),
            _ => None,
        }
    }

    pub fn u64(&self, k: &str) -> Option<u64> {
        match self.members.get(k) {
            Some(Member::Num(n)) => Some(*n),
            _ => None,
        }
    }

    pub fn ef(&self, k: &str) -> Option<&Ef<'a>> {
        match self.members.get(k) {
            Some(Member::Ef(e)) => Some(e),
            _ => None,
        }
    }

    pub fn fields(&self) -> Option<&Fields<'a>> {
        match self.members.get("fields") {
            Some(Member::Fields(f)) => Some(f),
            _ => None,
        }
    }

    pub fn raw(&self, k: &str) -> Option<&'a RawValue> {
        match self.members.get(k) {
            Some(Member::Raw(r)) => Some(r),
            _ => None,
        }
    }

    /// Every editable-field member, in name order.
    pub fn efs(&self) -> impl Iterator<Item = (&str, &Ef<'a>)> {
        self.members.iter().filter_map(|(k, m)| match m {
            Member::Ef(e) => Some((k.as_ref(), e)),
            _ => None,
        })
    }
}

/// A member value of any shape, sorted into what a [`Member`] may hold.
enum Any<'a> {
    Str(Cow<'a, str>),
    Num(u64),
    Ef(Ef<'a>),
}

impl<'de> Shape<'de> for Any<'de> {
    fn from_str(v: Cow<'de, str>) -> Option<Self> {
        Some(Any::Str(v))
    }
    fn from_u64(v: u64) -> Option<Self> {
        Some(Any::Num(v))
    }
    fn from_map<A: MapAccess<'de>>(map: A) -> Result<Option<Self>, A::Error> {
        Ef::from_map(map).map(|e| e.map(Any::Ef))
    }
}

impl<'de> Shape<'de> for Cred<'de> {
    fn from_map<A: MapAccess<'de>>(mut map: A) -> Result<Option<Self>, A::Error> {
        let mut out = Self::default();
        let mut unknown_efs = 0usize;
        while let Some(k) = key(&mut map)? {
            // The last member of a name wins, whatever its shape.
            out.members.remove(&k);
            let member = match k.as_ref() {
                "fields" => value::<Fields, _>(&mut map)?.map(Member::Fields),
                "fido2Extensions" => {
                    let raw = map.next_value::<&'de RawValue>()?;
                    raw.get().starts_with('{').then_some(Member::Raw(raw))
                }
                name => match value::<Any, _>(&mut map)? {
                    Some(Any::Str(s)) if STR_MEMBERS.contains(&name) => Some(Member::Str(s)),
                    Some(Any::Num(n)) if matches!(name, "digits" | "period") => Some(Member::Num(n)),
                    Some(Any::Ef(e)) if EF_MEMBERS.contains(&name) => Some(Member::Ef(e)),
                    Some(Any::Ef(e)) => {
                        unknown_efs = unknown_efs.saturating_add(1);
                        if unknown_efs > CUSTOM_FIELDS_MAX {
                            out.over = true;
                            None
                        } else {
                            Some(Member::Ef(e))
                        }
                    }
                    _ => None,
                },
            };
            if let Some(m) = member {
                out.members.insert(k, m);
            }
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(json: &str) -> Cred<'_> {
        let raw: &RawValue = serde_json::from_str(json).unwrap();
        Cred::read(raw)
    }

    #[test]
    fn members_of_the_wrong_shape_are_absent() {
        let c = cred(r#"{"type": 5, "secret": "S", "digits": "6", "period": 30, "username": {"value": "u"}, "label": ["x"]}"#);
        assert_eq!(c.str("type"), None);
        assert_eq!(c.str("secret"), Some("S"));
        assert_eq!(c.u64("digits"), None);
        assert_eq!(c.u64("period"), Some(30));
        assert_eq!(c.str("username"), None);
        assert_eq!(c.ef("username").and_then(|e| e.value.as_deref()), Some("u"));
        assert_eq!(c.str("label"), None);
        assert!(c.fields().is_none());
        for not_an_object in ["[]", "1", "\"x\"", "null", "true"] {
            assert!(cred(not_an_object).members.is_empty(), "{not_an_object}");
        }
    }

    #[test]
    fn the_last_member_of_a_name_wins() {
        let c = cred(r#"{"type": "note", "type": "totp", "secret": "A", "secret": 1, "key": "k", "key": {"value": "v"}}"#);
        assert_eq!(c.str("type"), Some("totp"));
        assert_eq!(c.str("secret"), None);
        assert_eq!(c.str("key"), None);
        assert!(c.ef("key").is_some());
    }

    #[test]
    fn members_nobody_reads_are_not_kept() {
        let c = cred(r#"{"type": "x", "pad": [0, 0, {"a": 1}], "other": "text", "n": 5, "digits": -1}"#);
        assert_eq!(c.members.len(), 1);
    }

    #[test]
    fn unknown_editable_fields_are_capped() {
        let mut s = String::from(r#"{"type": "passport""#);
        for i in 0..=CUSTOM_FIELDS_MAX {
            s.push_str(&format!(r#", "m{i:04}": {{"value": "v"}}"#));
        }
        s.push_str(r#", "passportNumber": {"value": "P"}}"#);
        let c = cred(&s);
        assert!(c.over);
        assert_eq!(c.efs().count(), CUSTOM_FIELDS_MAX + 1, "the cap leaves the known members");
        assert!(c.ef("passportNumber").is_some());

        let mut at = String::from(r#"{"type": "passport""#);
        for i in 0..CUSTOM_FIELDS_MAX {
            at.push_str(&format!(r#", "m{i:04}": {{"value": "v"}}"#));
        }
        at.push('}');
        assert!(!cred(&at).over);
    }

    #[test]
    fn custom_fields_are_capped_while_reading() {
        let list = |n: usize| format!(r#"{{"fields": [{}]}}"#, vec![r#"{"value": "v"}"#; n].join(","));
        let at = list(CUSTOM_FIELDS_MAX);
        let c = cred(&at);
        assert_eq!(c.fields().map(|f| (f.list.len(), f.over)), Some((CUSTOM_FIELDS_MAX, false)));
        let over = list(CUSTOM_FIELDS_MAX + 1);
        let c = cred(&over);
        assert_eq!(c.fields().map(|f| (f.list.len(), f.over)), Some((0, true)));
        // Elements that are not objects still count.
        let mixed = format!(r#"{{"fields": [{}, 1]}}"#, vec![r#"{"value": "v"}"#; CUSTOM_FIELDS_MAX].join(","));
        assert!(cred(&mixed).fields().is_some_and(|f| f.over));
    }

    #[test]
    fn extensions_are_kept_raw_only_when_an_object() {
        let c = cred(r#"{"fido2Extensions": {"hmacCredentials": {"a": 1}}}"#);
        assert_eq!(c.raw("fido2Extensions").map(RawValue::get), Some(r#"{"hmacCredentials": {"a": 1}}"#));
        assert!(cred(r#"{"fido2Extensions": [1]}"#).raw("fido2Extensions").is_none());
        assert!(cred(r#"{"fido2Extensions": "x"}"#).raw("fido2Extensions").is_none());
    }

    #[test]
    fn numbers_follow_json_ranges() {
        assert_eq!(<u64 as Shape>::from_i64(-1), None);
        assert_eq!(<u64 as Shape>::from_i64(5), Some(5));
        assert_eq!(<i64 as Shape>::from_u64(u64::MAX), None);
        assert_eq!(<i64 as Shape>::from_u64(7), Some(7));
        let v: Loose<i64> = serde_json::from_str("1.5").unwrap();
        assert!(v.0.is_none());
        let v: Loose<i64> = serde_json::from_str("-3").unwrap();
        assert_eq!(v.0, Some(-3));
        let v: Loose<Cow<str>> = serde_json::from_str(r#""a\nb""#).unwrap();
        assert_eq!(v.0.as_deref(), Some("a\nb"));
    }

    #[test]
    fn escaped_names_still_match() {
        let c = cred(r#"{"t\u0079pe": "note"}"#);
        assert_eq!(c.str("type"), Some("note"));
    }
}
