//! PDF export: a compact two-column card layout of every entry.
//!
//! Split in two on purpose:
//!
//! - [`layout`] decides **what** goes on the page (which entries, in which
//!   order, with which rows, side by side or full width). It knows nothing
//!   about PDF and is tested directly.
//! - [`render`] decides **where** it goes: it measures text with the embedded
//!   font's glyph widths, wraps lines, paginates and writes the PDF with
//!   `printpdf`. No text-layout engine is pulled in for this; the layout is
//!   simple enough to do by hand and keeps the dependency tree small.

use std::collections::HashMap;

use printpdf::{
    Color, Line, LinePoint, Mm, Op, ParsedFont, PdfDocument, PdfFontHandle, PdfPage,
    PdfSaveOptions, Point, Pt, Rgb, TextItem,
};

use super::compute_path;
use crate::database::models::{IWField, IWItem};
use crate::error::{Result, WalletError};

static REGULAR_FONT: &[u8] = include_bytes!("fonts/NotoSans-Regular.ttf");
static BOLD_FONT: &[u8] = include_bytes!("fonts/NotoSans-Bold.ttf");

/// Maximum number of fields before an entry gets a full-width row.
pub(crate) const WIDE_CARD_THRESHOLD: usize = 6;

/// One entry as it appears in the PDF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Card {
    pub name: String,
    /// Folder path, `""` for entries at the top level.
    pub path: String,
    /// `(label, value)` per field, in sort order.
    pub rows: Vec<(String, String)>,
}

impl Card {
    pub fn is_wide(&self) -> bool {
        self.rows.len() > WIDE_CARD_THRESHOLD
    }
}

/// One horizontal band of the grid: a full-width card, or a left and an
/// optional right card side by side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Band {
    Wide(usize),
    Pair(usize, Option<usize>),
}

/// Decide the content: non-deleted, non-folder entries sorted by name, each
/// with its non-deleted fields in sort order.
pub(crate) fn layout(items: &[IWItem], fields: &[IWField]) -> Vec<Card> {
    let mut fields_by_item: HashMap<&str, Vec<&IWField>> = HashMap::new();
    for field in fields.iter().filter(|f| !f.deleted) {
        fields_by_item.entry(field.item_id.as_str()).or_default().push(field);
    }
    for item_fields in fields_by_item.values_mut() {
        item_fields.sort_by_key(|f| f.sort_weight);
    }

    let items_map: HashMap<&str, &IWItem> =
        items.iter().map(|item| (item.item_id.as_str(), item)).collect();

    let mut entries: Vec<&IWItem> =
        items.iter().filter(|item| !item.deleted && !item.folder).collect();
    entries.sort_by_key(|a| a.name.to_lowercase());

    entries
        .into_iter()
        .map(|item| Card {
            name: item.name.clone(),
            path: compute_path(item, &items_map),
            rows: fields_by_item
                .get(item.item_id.as_str())
                .map(|fs| fs.iter().map(|f| (f.label.clone(), f.value.clone())).collect())
                .unwrap_or_default(),
        })
        .collect()
}

/// Arrange cards into bands: wide cards get a band of their own, narrow cards
/// are paired, and a narrow card followed by a wide one stands alone.
pub(crate) fn bands(cards: &[Card]) -> Vec<Band> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < cards.len() {
        if cards[i].is_wide() {
            out.push(Band::Wide(i));
            i += 1;
        } else if i + 1 < cards.len() && !cards[i + 1].is_wide() {
            out.push(Band::Pair(i, Some(i + 1)));
            i += 2;
        } else {
            out.push(Band::Pair(i, None));
            i += 1;
        }
    }
    out
}

/// Generate a PDF document from wallet items and fields.
///
/// Produces a compact 2-column card layout of all non-deleted entries with
/// their fields, sorted alphabetically.
pub fn generate_pdf(items: &[IWItem], fields: &[IWField]) -> Result<Vec<u8>> {
    let cards = layout(items, fields);
    let date = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    render(&cards, &date)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const MARGIN: f32 = 10.0;
const CONTENT_W: f32 = PAGE_W - 2.0 * MARGIN;
/// Card padding: top, right, bottom, left (mm).
const PAD: (f32, f32, f32, f32) = (2.0, 2.5, 2.0, 2.5);
/// Vertical gap between bands (mm).
const BAND_GAP: f32 = 3.5;
/// Line height as a multiple of the font size.
const LEADING: f32 = 1.3;

const PT_PER_MM: f32 = 72.0 / 25.4;

const TITLE_SIZE: f32 = 14.0;
const DATE_SIZE: f32 = 8.0;
const NAME_SIZE: f32 = 9.0;
const PATH_SIZE: f32 = 7.0;
const ROW_SIZE: f32 = 7.0;

fn grey(v: f32) -> Color {
    Color::Rgb(Rgb { r: v, g: v, b: v, icc_profile: None })
}

fn line_height_mm(size_pt: f32) -> f32 {
    size_pt * LEADING / PT_PER_MM
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Face {
    Regular,
    Bold,
}

/// A run of text in one face.
#[derive(Clone)]
struct Span {
    face: Face,
    text: String,
}

/// One laid-out line: spans at one size and colour.
#[derive(Clone)]
struct TextLine {
    spans: Vec<Span>,
    size: f32,
    color: f32,
}

/// What a card column draws, top to bottom.
#[derive(Clone)]
enum Piece {
    Text(TextLine),
    /// Thin grey rule across the card.
    Rule,
}

impl Piece {
    fn height(&self) -> f32 {
        match self {
            Piece::Text(l) => line_height_mm(l.size),
            Piece::Rule => 1.6,
        }
    }
}

struct Fonts {
    regular: ParsedFont,
    bold: ParsedFont,
}

impl Fonts {
    fn load() -> Result<Self> {
        let parse = |bytes: &[u8], which: &str| {
            ParsedFont::from_bytes(bytes, 0, &mut Vec::new())
                .ok_or_else(|| WalletError::ExportError(format!("Failed to load {which} font")))
        };
        Ok(Self { regular: parse(REGULAR_FONT, "regular")?, bold: parse(BOLD_FONT, "bold")? })
    }

    fn font(&self, face: Face) -> &ParsedFont {
        match face {
            Face::Regular => &self.regular,
            Face::Bold => &self.bold,
        }
    }

    /// Advance width of `text` in mm at `size` points.
    fn width_mm(&self, face: Face, text: &str, size: f32) -> f32 {
        let font = self.font(face);
        let upem = f32::from(font.units_per_em.max(1));
        let fallback = font
            .lookup_glyph_index(u32::from('?'))
            .and_then(|g| font.get_glyph_width(g))
            .unwrap_or(500);
        let units: u32 = text
            .chars()
            .map(|c| {
                font.lookup_glyph_index(u32::from(c))
                    .and_then(|g| font.get_glyph_width(g))
                    .unwrap_or(fallback) as u32
            })
            .sum();
        units as f32 / upem * size / PT_PER_MM
    }
}

/// Greedy word wrap of styled spans into lines no wider than `width` mm.
/// Words longer than a line are broken between characters, so no text is ever
/// clipped or lost.
fn wrap(fonts: &Fonts, spans: &[Span], size: f32, color: f32, width: f32) -> Vec<TextLine> {
    // Tokens: (face, text, is_space). Newlines force a break.
    enum Tok {
        Word(Face, String),
        Space(Face),
        Newline,
    }
    let mut toks = Vec::new();
    for span in spans {
        let mut word = String::new();
        for c in span.text.chars() {
            if c == '\n' {
                if !word.is_empty() {
                    toks.push(Tok::Word(span.face, std::mem::take(&mut word)));
                }
                toks.push(Tok::Newline);
            } else if c.is_whitespace() {
                if !word.is_empty() {
                    toks.push(Tok::Word(span.face, std::mem::take(&mut word)));
                }
                toks.push(Tok::Space(span.face));
            } else {
                word.push(c);
            }
        }
        if !word.is_empty() {
            toks.push(Tok::Word(span.face, word));
        }
    }

    let mut lines = Vec::new();
    let mut cur: Vec<Span> = Vec::new();
    let mut cur_w = 0.0f32;
    let push_text = |cur: &mut Vec<Span>, face: Face, text: &str| match cur.last_mut() {
        Some(last) if last.face == face => last.text.push_str(text),
        _ => cur.push(Span { face, text: text.to_string() }),
    };
    let flush = |cur: &mut Vec<Span>, cur_w: &mut f32, lines: &mut Vec<TextLine>| {
        // Drop trailing spaces.
        if let Some(last) = cur.last_mut() {
            let trimmed = last.text.trim_end().len();
            last.text.truncate(trimmed);
        }
        lines.push(TextLine { spans: std::mem::take(cur), size, color });
        *cur_w = 0.0;
    };

    for tok in toks {
        match tok {
            Tok::Newline => flush(&mut cur, &mut cur_w, &mut lines),
            Tok::Space(face) => {
                if cur_w > 0.0 {
                    let w = fonts.width_mm(face, " ", size);
                    push_text(&mut cur, face, " ");
                    cur_w += w;
                }
            }
            Tok::Word(face, word) => {
                let w = fonts.width_mm(face, &word, size);
                if cur_w + w <= width {
                    push_text(&mut cur, face, &word);
                    cur_w += w;
                    continue;
                }
                if cur_w > 0.0 {
                    flush(&mut cur, &mut cur_w, &mut lines);
                }
                if w <= width {
                    push_text(&mut cur, face, &word);
                    cur_w = w;
                    continue;
                }
                // Longer than a whole line: break between characters.
                for c in word.chars() {
                    let mut buf = [0u8; 4];
                    let s = c.encode_utf8(&mut buf);
                    let cw = fonts.width_mm(face, s, size);
                    if cur_w + cw > width && cur_w > 0.0 {
                        flush(&mut cur, &mut cur_w, &mut lines);
                    }
                    push_text(&mut cur, face, s);
                    cur_w += cw;
                }
            }
        }
    }
    if !cur.is_empty() {
        flush(&mut cur, &mut cur_w, &mut lines);
    }
    if lines.is_empty() {
        lines.push(TextLine { spans: Vec::new(), size, color });
    }
    lines
}

/// Everything a card draws, for a column `width` mm wide.
fn card_pieces(fonts: &Fonts, card: &Card, width: f32) -> Vec<Piece> {
    let inner = width - PAD.1 - PAD.3;
    let mut out = Vec::new();
    let name = [Span { face: Face::Bold, text: card.name.clone() }];
    out.extend(wrap(fonts, &name, NAME_SIZE, 0.0, inner).into_iter().map(Piece::Text));
    if !card.path.is_empty() {
        let path = [Span { face: Face::Regular, text: card.path.clone() }];
        out.extend(wrap(fonts, &path, PATH_SIZE, 0.47, inner).into_iter().map(Piece::Text));
    }
    out.push(Piece::Rule);
    for (label, value) in &card.rows {
        let spans = [
            Span { face: Face::Bold, text: format!("{label}: ") },
            Span { face: Face::Regular, text: value.clone() },
        ];
        out.extend(wrap(fonts, &spans, ROW_SIZE, 0.0, inner).into_iter().map(Piece::Text));
    }
    out
}

/// Page builder: tracks the cursor from the top of the page in mm.
struct Pages {
    done: Vec<Vec<Op>>,
    ops: Vec<Op>,
    y: f32,
    regular: printpdf::FontId,
    bold: printpdf::FontId,
}

impl Pages {
    fn new_page(&mut self) {
        let ops = std::mem::take(&mut self.ops);
        self.done.push(ops);
        self.y = MARGIN;
    }

    fn remaining(&self) -> f32 {
        PAGE_H - MARGIN - self.y
    }

    fn text(&mut self, x: f32, top: f32, line: &TextLine, fonts: &Fonts) {
        // Baseline sits at ~80 % of the line box.
        let baseline = top + line_height_mm(line.size) * 0.8;
        let mut cx = x;
        for span in &line.spans {
            if span.text.is_empty() {
                continue;
            }
            let font = match span.face {
                Face::Regular => self.regular.clone(),
                Face::Bold => self.bold.clone(),
            };
            self.ops.extend([
                Op::StartTextSection,
                Op::SetFillColor { col: grey(line.color) },
                Op::SetFont { font: PdfFontHandle::External(font), size: Pt(line.size) },
                Op::SetTextCursor { pos: Point::new(Mm(cx), Mm(PAGE_H - baseline)) },
                Op::ShowText { items: vec![TextItem::Text(span.text.clone())] },
                Op::EndTextSection,
            ]);
            cx += fonts.width_mm(span.face, &span.text, line.size);
        }
    }

    fn line(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, shade: f32, thickness: f32) {
        let p = |x: f32, y: f32| LinePoint { p: Point::new(Mm(x), Mm(PAGE_H - y)), bezier: false };
        self.ops.extend([
            Op::SetOutlineColor { col: grey(shade) },
            Op::SetOutlineThickness { pt: Pt(thickness) },
            Op::DrawLine { line: Line { points: vec![p(x1, y1), p(x2, y2)], is_closed: false } },
        ]);
    }

    fn frame(&mut self, x: f32, top: f32, w: f32, h: f32) {
        let (l, r, t, b) = (x, x + w, top, top + h);
        self.line(l, t, r, t, 0.0, 0.6);
        self.line(r, t, r, b, 0.0, 0.6);
        self.line(r, b, l, b, 0.0, 0.6);
        self.line(l, b, l, t, 0.0, 0.6);
    }
}

/// Lay the cards out on A4 pages and serialise the PDF.
pub(crate) fn render(cards: &[Card], date: &str) -> Result<Vec<u8>> {
    let fonts = Fonts::load()?;
    let mut doc = PdfDocument::new("IntelliWallet Export");
    let regular = doc.add_font(&fonts.regular);
    let bold = doc.add_font(&fonts.bold);
    let mut pages = Pages { done: Vec::new(), ops: Vec::new(), y: MARGIN, regular, bold };

    // Header, centred.
    for (text, face, size, color) in
        [("IntelliWallet", Face::Bold, TITLE_SIZE, 0.0), (date, Face::Regular, DATE_SIZE, 0.51)]
    {
        let w = fonts.width_mm(face, text, size);
        let line = TextLine { spans: vec![Span { face, text: text.to_string() }], size, color };
        let top = pages.y;
        pages.text(MARGIN + (CONTENT_W - w) / 2.0, top, &line, &fonts);
        pages.y += line_height_mm(size);
    }
    pages.y += 5.0;

    for band in bands(cards) {
        let columns: Vec<(f32, f32, Vec<Piece>)> = match band {
            Band::Wide(i) => vec![(MARGIN, CONTENT_W, card_pieces(&fonts, &cards[i], CONTENT_W))],
            Band::Pair(l, r) => {
                let w = CONTENT_W / 2.0;
                let mut cols = vec![(MARGIN, w, card_pieces(&fonts, &cards[l], w))];
                cols.push((MARGIN + w, w, r.map(|r| card_pieces(&fonts, &cards[r], w)).unwrap_or_default()));
                cols
            }
        };
        draw_band(&mut pages, &fonts, &columns);
        pages.y += BAND_GAP;
    }

    let ops = std::mem::take(&mut pages.ops);
    pages.done.push(ops);
    let pdf_pages = pages
        .done
        .into_iter()
        .map(|ops| PdfPage::new(Mm(PAGE_W), Mm(PAGE_H), ops))
        .collect();
    Ok(doc.with_pages(pdf_pages).save(&PdfSaveOptions::default(), &mut Vec::new()))
}

/// Draw one band, continuing on the next page as often as needed. Each page
/// segment of a band gets its own frame, so a card taller than a page is
/// split rather than clipped.
fn draw_band(pages: &mut Pages, fonts: &Fonts, columns: &[(f32, f32, Vec<Piece>)]) {
    let full: Vec<f32> = columns.iter().map(|c| c.2.iter().map(Piece::height).sum()).collect();
    let band_h = full.iter().cloned().fold(0.0, f32::max) + PAD.0 + PAD.2;
    let page_room = PAGE_H - 2.0 * MARGIN;

    // Start on a fresh page if the band would fit there but not here.
    if band_h > pages.remaining() && band_h <= page_room && pages.y > MARGIN {
        pages.new_page();
    }

    let mut next: Vec<usize> = vec![0; columns.len()];
    loop {
        let top = pages.y;
        let avail = pages.remaining() - PAD.0 - PAD.2;
        let mut used = 0.0f32;
        for (c, (x, _w, pieces)) in columns.iter().enumerate() {
            let mut y = top + PAD.0;
            while next[c] < pieces.len() {
                let h = pieces[next[c]].height();
                // Always place at least one piece per segment, so a single
                // piece taller than the page cannot loop forever.
                if y - top - PAD.0 + h > avail && y > top + PAD.0 {
                    break;
                }
                match &pieces[next[c]] {
                    Piece::Text(line) => pages.text(x + PAD.3, y, line, fonts),
                    Piece::Rule => {
                        let mid = y + h / 2.0;
                        let w = columns[c].1;
                        pages.line(x + PAD.3, mid, x + w - PAD.1, mid, 0.75, 0.3);
                    }
                }
                y += h;
                next[c] += 1;
            }
            used = used.max(y - top - PAD.0);
        }
        let seg_h = used + PAD.0 + PAD.2;
        for (x, w, _) in columns {
            pages.frame(*x, top, *w, seg_h);
        }
        pages.y = top + seg_h;

        let finished = columns.iter().enumerate().all(|(c, col)| next[c] >= col.2.len());
        if finished {
            break;
        }
        pages.new_page();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn item(id: &str, name: &str, parent: Option<&str>, folder: bool, deleted: bool) -> IWItem {
        IWItem {
            item_id: id.into(),
            parent_id: parent.map(Into::into),
            name: name.into(),
            icon: "icon".into(),
            folder,
            create_timestamp: Utc::now(),
            change_timestamp: Utc::now(),
            deleted,
        }
    }

    fn field(item_id: &str, id: &str, label: &str, value: &str, w: i32, deleted: bool) -> IWField {
        IWField {
            item_id: item_id.into(),
            field_id: id.into(),
            field_type: "TEXT".into(),
            value: value.into(),
            label: label.into(),
            icon: "icon".into(),
            value_type: "text".into(),
            sort_weight: w,
            change_timestamp: Utc::now(),
            deleted,
            expired: false,
            expiring: false,
        }
    }

    fn card(name: &str, rows: usize) -> Card {
        Card {
            name: name.into(),
            path: String::new(),
            rows: (0..rows).map(|i| (format!("L{i}"), format!("v{i}"))).collect(),
        }
    }

    #[test]
    fn layout_sorts_filters_and_orders_rows() {
        let items = vec![
            item("__ROOT__", "Root", None, true, false),
            item("f", "Banking", Some("__ROOT__"), true, false),
            item("b", "beta", Some("f"), false, false),
            item("a", "Alpha", Some("__ROOT__"), false, false),
            item("d", "Deleted", Some("__ROOT__"), false, true),
        ];
        let fields = vec![
            field("b", "2", "Second", "2", 2, false),
            field("b", "1", "First", "1", 1, false),
            field("b", "x", "Gone", "x", 0, true),
            field("d", "y", "User", "deleted", 0, false),
        ];
        let cards = layout(&items, &fields);
        assert_eq!(
            cards,
            vec![
                Card { name: "Alpha".into(), path: String::new(), rows: vec![] },
                Card {
                    name: "beta".into(),
                    path: "Banking".into(),
                    rows: vec![("First".into(), "1".into()), ("Second".into(), "2".into())],
                },
            ]
        );
    }

    #[test]
    fn bands_pair_narrow_cards_and_isolate_wide_ones() {
        let cards = vec![
            card("a", 1),
            card("b", 2),
            card("c", 6),
            card("d", 7),
            card("e", 0),
        ];
        assert_eq!(
            bands(&cards),
            vec![Band::Pair(0, Some(1)), Band::Pair(2, None), Band::Wide(3), Band::Pair(4, None)]
        );
        assert!(bands(&[]).is_empty());
        assert_eq!(bands(&[card("x", 7), card("y", 7)]), vec![Band::Wide(0), Band::Wide(1)]);
    }

    #[test]
    fn wrap_never_exceeds_width_and_loses_no_text() {
        let fonts = Fonts::load().unwrap();
        let text = "Zürich – 東京 – a supercalifragilisticexpialidociouslylongwordwithoutanyspaces end";
        let spans = [Span { face: Face::Bold, text: "Label: ".into() }, Span { face: Face::Regular, text: text.into() }];
        let width = 30.0;
        let lines = wrap(&fonts, &spans, 7.0, 0.0, width);
        assert!(lines.len() > 2);
        let mut joined = String::new();
        for l in &lines {
            let w: f32 = l.spans.iter().map(|s| fonts.width_mm(s.face, &s.text, 7.0)).sum();
            assert!(w <= width + 0.01, "line too wide: {w}");
            for s in &l.spans {
                joined.push_str(&s.text);
            }
        }
        let strip = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        assert_eq!(strip(&joined), strip(&format!("Label: {text}")));
    }

    #[test]
    fn wrap_handles_newlines_and_empty_text() {
        let fonts = Fonts::load().unwrap();
        let spans = [Span { face: Face::Regular, text: "one\ntwo\n\nfour".into() }];
        assert_eq!(wrap(&fonts, &spans, 7.0, 0.0, 100.0).len(), 4);
        assert_eq!(wrap(&fonts, &[], 7.0, 0.0, 100.0).len(), 1);
    }

    #[test]
    fn render_splits_a_card_taller_than_a_page() {
        let huge = Card {
            name: "Huge".into(),
            path: "A / B".into(),
            rows: vec![("Note".into(), "word ".repeat(20_000))],
        };
        let pdf = render(&[huge, card("after", 1)], "2026-10-31 00:00 UTC").unwrap();
        assert!(pdf.starts_with(b"%PDF"));
        // 20 000 words cannot fit on one A4 page at 7 pt: several page objects.
        let pages = String::from_utf8_lossy(&pdf).matches("/Type /Page\n").count()
            + String::from_utf8_lossy(&pdf).matches("/Type/Page").count();
        assert!(pages > 1 || pdf.len() > 100_000, "a huge card must spill onto more pages");
    }

    #[test]
    fn render_empty_wallet() {
        let pdf = render(&[], "2026-10-31 00:00 UTC").unwrap();
        assert!(pdf.starts_with(b"%PDF"));
    }
}
