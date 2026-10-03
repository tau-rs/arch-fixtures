//! The invariant harness: one function per invariant, each over the smallest input it needs.
//!
//! This crate does **not** define the shape of `facts.json` or the view files — `arch` owns those and
//! publishes `schemas/facts.schema.json`. It defines only [`Input`], the harness's own minimal model, and a
//! loader seam ([`load_golden`]) that maps a golden directory onto it once arch's schema exists. Until then the
//! harness is runnable (see the unit tests at the bottom) and the golden test reports "awaiting data".
//!
//! Each check carries its testable statement in its doc comment. Numbering follows the V1 spec §5 where the
//! spec gives a number; ADR n means spec §13 decision n.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------------------------
// Input model (harness-owned, minimal)
// ---------------------------------------------------------------------------------------------

pub type ItemId = String;
pub type LinkId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColumnRule {
    Hexagon,
    Layers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Resolved,
    Guessed,
    Declared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Block,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub id: ItemId,
    pub krate: String,
    /// Column name under the active rule; `None` when the item is not placed (e.g. an external).
    pub column: Option<String>,
    /// On the crate's public surface (pub item, pub use, registered route/rpc/topic).
    pub public: bool,
    /// Content hash of the facts that place this item; equal hashes ⇒ "unchanged" for MAP-1.
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub id: LinkId,
    pub from: ItemId,
    pub to: ItemId,
    pub confidence: Confidence,
    /// `Some(reason)` when the analyzer could not resolve the target (dyn, spawn, …).
    pub unresolved: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Position {
    pub item: ItemId,
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FoldState {
    pub visible_items: usize,
    pub scale: f64,
    pub areas_folded: bool,
    pub label_px: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OverlayKind {
    Sessions,
    Plan,
    Findings,
    Delta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Outline,
    Fill,
    Fade,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverlayRow {
    pub kind: OverlayKind,
    pub item: ItemId,
    pub channel: Channel,
    /// True if the row carries any geometry (x, y, w, h, group box). Must be false.
    pub has_geometry: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pill {
    pub item: ItemId,
    pub kind: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule: String,
    pub link: Option<LinkId>,
    pub level: Level,
    pub gates_merge: bool,
    pub origin: String,
}

/// A facts/views pair reduced to what the invariants read.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Input {
    pub rule: Option<ColumnRule>,
    /// Column names left → right under `rule`.
    pub columns: Vec<String>,
    pub items: Vec<Item>,
    pub links: Vec<Link>,
    /// The candidate positions (the view under test).
    pub positions: Vec<Position>,
    /// Positions from the previous save (the golden), for MAP-1.
    pub baseline_positions: Option<Vec<Position>>,
    /// Baseline items, to know which were unchanged.
    pub baseline_items: Option<Vec<Item>>,
    /// Positions computed with every overlay on; must equal `positions` (MAP-3/24).
    pub positions_with_overlays: Option<Vec<Position>>,
    /// Fold states observed while folding, first is the opening state.
    pub fold: Vec<FoldState>,
    pub overlays: Vec<OverlayRow>,
    pub pills: Vec<Pill>,
    pub findings: Vec<Finding>,
}

// ---------------------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub invariant: &'static str,
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.invariant, self.message)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub violations: Vec<Violation>,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.violations.is_empty() {
            return write!(f, "all invariants hold");
        }
        for v in &self.violations {
            writeln!(f, "{v}")?;
        }
        Ok(())
    }
}

/// Above this many visible items, areas fold to chips (spec §5: "above ~80").
pub const FOLD_ITEM_THRESHOLD: usize = 80;
/// The fold keeps the footprint with a floor at this fraction of the opening scale (MAP-4 amended).
pub const FOLD_SCALE_FLOOR: f64 = 0.7;

/// Run every check. The only entry point `arch`'s CI needs.
pub fn check_all(input: &Input) -> Report {
    let mut v = Vec::new();
    v.extend(positions_stable(input));
    v.extend(no_state_relayout(input));
    v.extend(fold_floor(input));
    v.extend(overlay_stacking(input));
    v.extend(unresolved_one_pill(input));
    v.extend(cross_unit_on_public_surface(input));
    v.extend(direction_left_to_right(input));
    v.extend(finding_confidence(input));
    v.extend(origin_is_core(input));
    Report { violations: v }
}

fn viol(invariant: &'static str, message: impl Into<String>) -> Violation {
    Violation { invariant, message: message.into() }
}

fn by_item(positions: &[Position]) -> HashMap<&str, &Position> {
    positions.iter().map(|p| (p.item.as_str(), p)).collect()
}

fn same_coords(a: &Position, b: &Position) -> bool {
    a.x.to_bits() == b.x.to_bits() && a.y.to_bits() == b.y.to_bits()
}

// ---------------------------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------------------------

/// MAP-1 · Positions inside a unit come from facts and are byte-identical between saves for unchanged
/// items. Testable: for every item present in baseline and candidate with the same content hash, the
/// candidate position equals the baseline position bit for bit. Skipped when no baseline is given.
pub fn positions_stable(input: &Input) -> Vec<Violation> {
    let (Some(base_pos), Some(base_items)) = (&input.baseline_positions, &input.baseline_items) else {
        return Vec::new();
    };
    let base_hash: HashMap<&str, &str> = base_items.iter().map(|i| (i.id.as_str(), i.content_hash.as_str())).collect();
    let base = by_item(base_pos);
    let cand = by_item(&input.positions);
    let mut out = Vec::new();
    for item in &input.items {
        if base_hash.get(item.id.as_str()) != Some(&item.content_hash.as_str()) {
            continue;
        }
        match (base.get(item.id.as_str()), cand.get(item.id.as_str())) {
            (Some(b), Some(c)) if !same_coords(b, c) => {
                out.push(viol("MAP-1", format!("{} moved from ({}, {}) to ({}, {}) with unchanged facts", item.id, b.x, b.y, c.x, c.y)));
            }
            (Some(_), None) => out.push(viol("MAP-1", format!("{} lost its position with unchanged facts", item.id))),
            _ => {}
        }
    }
    out
}

/// MAP-3 / MAP-24 · The map never re-layouts for state. Testable: positions with every overlay on equal the
/// positions with none; no overlay row carries geometry.
pub fn no_state_relayout(input: &Input) -> Vec<Violation> {
    let mut out = Vec::new();
    if let Some(with) = &input.positions_with_overlays {
        let plain = by_item(&input.positions);
        for p in with {
            match plain.get(p.item.as_str()) {
                Some(q) if same_coords(p, q) => {}
                Some(q) => out.push(viol("MAP-3", format!("{} is at ({}, {}) with overlays but ({}, {}) without", p.item, p.x, p.y, q.x, q.y))),
                None => out.push(viol("MAP-3", format!("{} appears only when overlays are on", p.item))),
            }
        }
        if with.len() != input.positions.len() {
            out.push(viol("MAP-3", format!("{} positions with overlays, {} without", with.len(), input.positions.len())));
        }
    }
    for row in input.overlays.iter().filter(|r| r.has_geometry) {
        out.push(viol("MAP-24", format!("{:?} overlay row on {} carries geometry", row.kind, row.item)));
    }
    out
}

/// MAP-4 (amended) · Fold, never shrink. Testable: one label size across every fold state; every state's
/// scale ≥ 0.7 × the opening scale; a state with more than ~80 visible items has its areas folded.
pub fn fold_floor(input: &Input) -> Vec<Violation> {
    let Some(opening) = input.fold.first() else { return Vec::new() };
    let mut out = Vec::new();
    for (i, s) in input.fold.iter().enumerate() {
        if s.label_px.to_bits() != opening.label_px.to_bits() {
            out.push(viol("MAP-4", format!("fold state {i} changes label size {} → {}", opening.label_px, s.label_px)));
        }
        if s.scale < FOLD_SCALE_FLOOR * opening.scale {
            out.push(viol("MAP-4", format!("fold state {i} scale {} is below the floor {} × {}", s.scale, FOLD_SCALE_FLOOR, opening.scale)));
        }
        if s.visible_items > FOLD_ITEM_THRESHOLD && !s.areas_folded {
            out.push(viol("MAP-4", format!("fold state {i} shows {} items with areas unfolded", s.visible_items)));
        }
    }
    out
}

/// Overlay stacking (spec §5) · Outline = session, fill = plan or finding, delta fades; no overlay groups
/// items spatially. Testable: every overlay row's channel matches its kind.
pub fn overlay_stacking(input: &Input) -> Vec<Violation> {
    input
        .overlays
        .iter()
        .filter_map(|r| {
            let expected = match r.kind {
                OverlayKind::Sessions => Channel::Outline,
                OverlayKind::Plan | OverlayKind::Findings => Channel::Fill,
                OverlayKind::Delta => Channel::Fade,
            };
            (r.channel != expected).then(|| viol("OVERLAY", format!("{:?} overlay on {} uses {:?}, expected {:?}", r.kind, r.item, r.channel, expected)))
        })
        .collect()
}

/// MAP-16 / MAP-28 · Unresolved paths are folded to one pill per item. Testable: an item with n > 0
/// unresolved outgoing links has exactly one `unresolved` pill with count n; an item with none has no such pill.
pub fn unresolved_one_pill(input: &Input) -> Vec<Violation> {
    let mut unresolved: BTreeMap<&str, usize> = BTreeMap::new();
    for l in input.links.iter().filter(|l| l.unresolved.is_some()) {
        *unresolved.entry(l.from.as_str()).or_default() += 1;
    }
    let mut pills: HashMap<&str, Vec<&Pill>> = HashMap::new();
    for p in input.pills.iter().filter(|p| p.kind == "unresolved") {
        pills.entry(p.item.as_str()).or_default().push(p);
    }
    let mut out = Vec::new();
    for item in &input.items {
        let n = unresolved.get(item.id.as_str()).copied().unwrap_or(0);
        let ps = pills.get(item.id.as_str()).map(Vec::as_slice).unwrap_or(&[]);
        match (n, ps) {
            (0, []) => {}
            (0, _) => out.push(viol("MAP-16", format!("{} has an unresolved pill but no unresolved links", item.id))),
            (_, [p]) if p.count == n => {}
            (_, [p]) => out.push(viol("MAP-16", format!("{} pill says {} unresolved, facts say {}", item.id, p.count, n))),
            (_, ps) => out.push(viol("MAP-16", format!("{} has {} unresolved pills, expected one", item.id, ps.len()))),
        }
    }
    out
}

/// Cross-unit links land on public surfaces (spec §3, §7). Testable: for every link whose endpoints are in
/// different crates, the target item is on its crate's public surface. V1 has one unit; crates stand in.
pub fn cross_unit_on_public_surface(input: &Input) -> Vec<Violation> {
    let items: HashMap<&str, &Item> = input.items.iter().map(|i| (i.id.as_str(), i)).collect();
    input
        .links
        .iter()
        .filter(|l| l.unresolved.is_none())
        .filter_map(|l| {
            let (from, to) = (items.get(l.from.as_str())?, items.get(l.to.as_str())?);
            (from.krate != to.krate && !to.public)
                .then(|| viol("SURFACE", format!("link {} crosses {} → {} onto non-public {}", l.id, from.krate, to.krate, to.id)))
        })
        .collect()
}

/// MAP-26 · "Uses" points left → right in both rules; a right-to-left link is drawn as a smell. Testable: for
/// every resolved link between placed items, column(from) ≤ column(to), or a `direction` finding names the link.
pub fn direction_left_to_right(input: &Input) -> Vec<Violation> {
    if input.rule.is_none() {
        return Vec::new();
    }
    let col_index: HashMap<&str, usize> = input.columns.iter().enumerate().map(|(i, c)| (c.as_str(), i)).collect();
    let items: HashMap<&str, &Item> = input.items.iter().map(|i| (i.id.as_str(), i)).collect();
    let smells: HashMap<&str, &Finding> = input.findings.iter().filter(|f| f.rule == "direction").filter_map(|f| Some((f.link.as_deref()?, f))).collect();
    let mut out = Vec::new();
    for l in input.links.iter().filter(|l| l.unresolved.is_none()) {
        let (Some(from), Some(to)) = (items.get(l.from.as_str()), items.get(l.to.as_str())) else { continue };
        let (Some(cf), Some(ct)) = (from.column.as_deref().and_then(|c| col_index.get(c)), to.column.as_deref().and_then(|c| col_index.get(c))) else {
            continue;
        };
        if cf > ct && !smells.contains_key(l.id.as_str()) {
            out.push(viol("MAP-26", format!("link {} goes right → left ({} → {}) under {:?} and no direction finding marks it", l.id, from.column.as_deref().unwrap_or("?"), to.column.as_deref().unwrap_or("?"), input.rule.unwrap())));
        }
    }
    out
}

/// ADR 9 · Confidence rule. Testable: a finding on a `guessed` link warns and never blocks; a finding on a
/// `declared` link cannot gate a merge.
pub fn finding_confidence(input: &Input) -> Vec<Violation> {
    let links: HashMap<&str, &Link> = input.links.iter().map(|l| (l.id.as_str(), l)).collect();
    let mut out = Vec::new();
    for f in &input.findings {
        let Some(link) = f.link.as_deref().and_then(|id| links.get(id)) else { continue };
        match link.confidence {
            Confidence::Guessed if f.level == Level::Block || f.gates_merge => {
                out.push(viol("ADR-9", format!("finding {} on guessed link {} blocks or gates", f.id, link.id)));
            }
            Confidence::Declared if f.gates_merge => out.push(viol("ADR-9", format!("finding {} on declared link {} gates a merge", f.id, link.id))),
            _ => {}
        }
    }
    out
}

/// Spec §3 · In V1 every finding's origin is `core`. Testable as written.
pub fn origin_is_core(input: &Input) -> Vec<Violation> {
    input.findings.iter().filter(|f| f.origin != "core").map(|f| viol("ORIGIN", format!("finding {} has origin {:?}", f.id, f.origin))).collect()
}

// ---------------------------------------------------------------------------------------------
// Loader seam
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
pub enum LoadError {
    /// No `facts.json` in the directory: golden data not generated yet.
    AwaitingData,
    /// `facts.json` is present but is not a JSON document the loader can read.
    AwaitingSchema(String),
    Io(std::io::Error),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::AwaitingData => write!(f, "awaiting data: no facts.json (generated by arch-analyze)"),
            LoadError::AwaitingSchema(p) => write!(f, "facts.json is not readable as arch's facts document: {p}"),
            LoadError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Map a `golden/<repo>/` directory (facts.json + views/) onto [`Input`].
///
/// Returns [`LoadError::AwaitingData`] while the golden files do not exist. Once `arch` publishes its facts
/// schema this is the one function to write; the checks above do not change.
pub fn load_golden(dir: &Path) -> Result<Input, LoadError> {
    let facts = dir.join("facts.json");
    if !facts.exists() {
        return Err(LoadError::AwaitingData);
    }
    let text = std::fs::read_to_string(&facts).map_err(LoadError::Io)?;
    let doc: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| LoadError::AwaitingSchema(format!("{}: {e}", facts.display())))?;
    Ok(input_from_facts(&doc))
}

/// The part of [`Input`] that `facts.json` alone determines: items and the links between them.
///
/// Columns, positions, fold states, overlays, pills and findings come from `views/`, which
/// `arch-views` does not emit yet; they stay empty, so the checks that read them hold trivially
/// until the view files land (issue 4). Field names follow arch's `schemas/facts.schema.json`.
pub fn input_from_facts(doc: &serde_json::Value) -> Input {
    let list = |key: &str| doc.get(key).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let text = |v: &serde_json::Value, key: &str| v.get(key).and_then(|x| x.as_str()).unwrap_or_default().to_string();
    let entries: std::collections::BTreeSet<String> = list("entries").iter().map(|e| text(e, "item")).collect();
    let items = list("items")
        .iter()
        .map(|i| {
            let id = text(i, "id");
            let reexported = i.get("reexported").and_then(|x| x.as_bool()).unwrap_or(false);
            Item {
                krate: text(i, "crate"),
                column: None,
                // Public surface: pub items, pub use, registered routes (the framework-held entries).
                public: text(i, "visibility") == "pub" || reexported || entries.contains(&id),
                // The facts that place an item are the item's own; its serialization stands for them.
                content_hash: i.to_string(),
                id,
            }
        })
        .collect();
    let links = list("links")
        .iter()
        .filter_map(|l| {
            // Only item → item links are drawn between placed items; ports, externals and tables are rails.
            let to = l.get("to")?.get("item")?.as_str()?.to_string();
            let (from, kind) = (text(l, "from"), text(l, "kind"));
            let member = l.get("member").and_then(|m| m.as_str()).map(|m| format!(".{m}")).unwrap_or_default();
            let confidence = match text(l, "confidence").as_str() {
                "resolved" => Confidence::Resolved,
                "declared" => Confidence::Declared,
                _ => Confidence::Guessed,
            };
            Some(Link { id: format!("{from} -{kind}{member}-> {to}"), from, to, confidence, unresolved: None })
        })
        .collect();
    Input { items, links, ..Input::default() }
}

// ---------------------------------------------------------------------------------------------
// Unit tests: the harness is runnable now, on hand-built inputs. These are not golden data.
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, krate: &str, column: &str, public: bool) -> Item {
        Item { id: id.into(), krate: krate.into(), column: Some(column.into()), public, content_hash: format!("h-{id}") }
    }

    fn link(id: &str, from: &str, to: &str, confidence: Confidence) -> Link {
        Link { id: id.into(), from: from.into(), to: to.into(), confidence, unresolved: None }
    }

    fn pos(item: &str, x: f64, y: f64) -> Position {
        Position { item: item.into(), x, y }
    }

    fn finding(id: &str, rule: &str, link: Option<&str>, level: Level, gates_merge: bool) -> Finding {
        Finding { id: id.into(), rule: rule.into(), link: link.map(Into::into), level, gates_merge, origin: "core".into() }
    }

    fn hexagon() -> Input {
        Input {
            rule: Some(ColumnRule::Hexagon),
            columns: ["driving", "domain", "driven", "externals"].map(String::from).to_vec(),
            items: vec![item("h", "svc", "driving", true), item("d", "svc", "domain", false), item("a", "svc", "driven", false)],
            links: vec![link("l1", "h", "d", Confidence::Resolved), link("l2", "d", "a", Confidence::Resolved)],
            positions: vec![pos("h", 0.0, 0.0), pos("d", 380.0, 0.0), pos("a", 760.0, 0.0)],
            fold: vec![FoldState { visible_items: 3, scale: 1.0, areas_folded: false, label_px: 12.0 }],
            ..Default::default()
        }
    }

    #[test]
    fn clean_input_passes_everything() {
        let report = check_all(&hexagon());
        assert!(report.is_clean(), "{report}");
    }

    #[test]
    fn empty_input_passes_everything() {
        assert!(check_all(&Input::default()).is_clean());
    }

    #[test]
    fn positions_stable_flags_a_moved_unchanged_item() {
        let mut i = hexagon();
        i.baseline_items = Some(i.items.clone());
        i.baseline_positions = Some(i.positions.clone());
        i.positions[1].y = 1.0;
        let v = positions_stable(&i);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].invariant, "MAP-1");
    }

    #[test]
    fn positions_stable_allows_a_changed_item_to_move() {
        let mut i = hexagon();
        i.baseline_items = Some(i.items.clone());
        i.baseline_positions = Some(i.positions.clone());
        i.items[1].content_hash = "edited".into();
        i.positions[1].y = 1.0;
        assert!(positions_stable(&i).is_empty());
    }

    #[test]
    fn overlays_must_not_move_or_carry_geometry() {
        let mut i = hexagon();
        let mut with = i.positions.clone();
        with[0].x = 5.0;
        i.positions_with_overlays = Some(with);
        i.overlays.push(OverlayRow { kind: OverlayKind::Plan, item: "d".into(), channel: Channel::Fill, has_geometry: true });
        let v = no_state_relayout(&i);
        assert_eq!(v.iter().map(|v| v.invariant).collect::<Vec<_>>(), ["MAP-3", "MAP-24"]);
    }

    #[test]
    fn fold_floor_label_and_threshold() {
        let mut i = hexagon();
        i.fold.push(FoldState { visible_items: 200, scale: 0.69, areas_folded: false, label_px: 11.0 });
        let v = fold_floor(&i);
        assert_eq!(v.len(), 3, "{v:?}");
        i.fold[1] = FoldState { visible_items: 200, scale: 0.7, areas_folded: true, label_px: 12.0 };
        assert!(fold_floor(&i).is_empty());
    }

    #[test]
    fn overlay_channels_by_kind() {
        let mut i = hexagon();
        i.overlays = vec![
            OverlayRow { kind: OverlayKind::Sessions, item: "d".into(), channel: Channel::Outline, has_geometry: false },
            OverlayRow { kind: OverlayKind::Findings, item: "d".into(), channel: Channel::Outline, has_geometry: false },
        ];
        let v = overlay_stacking(&i);
        assert_eq!(v.len(), 1);
        assert!(v[0].message.contains("Findings"));
    }

    #[test]
    fn unresolved_links_fold_to_exactly_one_pill() {
        let mut i = hexagon();
        i.links.push(Link { id: "u1".into(), from: "d".into(), to: "?".into(), confidence: Confidence::Guessed, unresolved: Some("dyn".into()) });
        i.links.push(Link { id: "u2".into(), from: "d".into(), to: "?".into(), confidence: Confidence::Guessed, unresolved: Some("spawn".into()) });
        assert_eq!(unresolved_one_pill(&i).len(), 1, "missing pill");
        i.pills.push(Pill { item: "d".into(), kind: "unresolved".into(), count: 2 });
        assert!(unresolved_one_pill(&i).is_empty());
        i.pills.push(Pill { item: "d".into(), kind: "unresolved".into(), count: 1 });
        assert_eq!(unresolved_one_pill(&i).len(), 1, "two pills");
    }

    #[test]
    fn cross_crate_link_needs_public_target() {
        let mut i = hexagon();
        i.items.push(item("x", "other", "domain", false));
        i.links.push(link("l3", "h", "x", Confidence::Resolved));
        let v = cross_unit_on_public_surface(&i);
        assert_eq!(v.len(), 1);
        i.items[3].public = true;
        assert!(cross_unit_on_public_surface(&i).is_empty());
    }

    #[test]
    fn right_to_left_needs_a_direction_finding() {
        let mut i = hexagon();
        i.links.push(link("back", "a", "h", Confidence::Resolved));
        assert_eq!(direction_left_to_right(&i).len(), 1);
        i.findings.push(finding("f1", "direction", Some("back"), Level::Warn, false));
        assert!(direction_left_to_right(&i).is_empty());
        i.rule = Some(ColumnRule::Layers);
        i.columns = ["public", "internals", "leaves"].map(String::from).to_vec();
        i.items[0].column = Some("public".into());
        i.items[1].column = Some("internals".into());
        i.items[2].column = Some("leaves".into());
        assert!(direction_left_to_right(&i).is_empty(), "same rule holds under layers");
    }

    #[test]
    fn guessed_warns_declared_never_gates() {
        let mut i = hexagon();
        i.links[0].confidence = Confidence::Guessed;
        i.links[1].confidence = Confidence::Declared;
        i.findings = vec![
            finding("g", "domain-must-not", Some("l1"), Level::Block, false),
            finding("d", "domain-must-not", Some("l2"), Level::Warn, true),
            finding("ok", "domain-must-not", Some("l2"), Level::Warn, false),
        ];
        let v = finding_confidence(&i);
        assert_eq!(v.len(), 2, "{v:?}");
    }

    #[test]
    fn origin_must_be_core_in_v1() {
        let mut i = hexagon();
        i.findings.push(Finding { origin: "plugin:x".into(), ..finding("p", "r", None, Level::Warn, false) });
        assert_eq!(origin_is_core(&i).len(), 1);
    }

    #[test]
    fn loader_reports_awaiting_data_on_an_empty_dir() {
        let dir = std::env::temp_dir().join("arch-fixtures-empty-golden");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(matches!(load_golden(&dir), Err(LoadError::AwaitingData)));
    }
}
