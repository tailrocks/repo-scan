//! Interactive live terminal view (goal Step 13; cases 24/25).
//!
//! [`Session`] renders grouped scan results (account/org > repository >
//! local store > checkout) in the terminal's alternate screen, updating
//! rows in place as new snapshots arrive. The view separates state from
//! rendering so tests drive scripted key streams against fixture
//! snapshots with no PTY: [`ViewState`] + [`apply_key`] evolve the
//! state, [`render_lines`] produces the frame as plain text rows.
//!
//! Pinned key table (also in `docs/GOAL_CONTRACTS.md` and the `h`/`?`
//! help overlay):
//!
//! | Key | Action |
//! |---|---|
//! | up / down, `k` / `j` | move selection |
//! | left / right | collapse / expand (left on a collapsed row moves to parent) |
//! | enter / space | expand/collapse a group, store, or checkout with branches; open detail on a leaf |
//! | `/` | search (account, repo, path, branch); type to filter, enter keeps, esc clears |
//! | `f` | cycle filter: dirty > conflicted > ahead > behind > diverged > pending > failed > off |
//! | `s` | cycle sort: group > path > state |
//! | `v` | open detail view (full paths + state explanations) |
//! | `h` or `?` | help overlay |
//! | `q` | quit (from anywhere, including overlays) |
//! | esc | close overlay / stop search, or quit when nothing is open |
//!
//! Data enters through [`TuiSnapshot`], built either from a retained
//! [`Report`][crate::report::model::Report] ([`TuiSnapshot::from_report`])
//! or folded live from journal envelopes
//! ([`TuiSnapshot::apply_envelope`]); the scan loop additionally
//! refreshes rows from committed catalog state
//! ([`load_live_snapshot`], bounded queries, main thread only).
//!
//! Terminal discipline: [`TermGuard`] enters the alternate screen and
//! raw mode on open and restores both on drop (RAII), so completion,
//! interruption, and failure all restore the terminal. Color follows
//! [`ColorMode`] with `NO_COLOR`/`TERM=dumb` honored; every colored
//! row also carries a text label, so the view stays readable with
//! color disabled.

use crate::report::encode::escape_display;
use crate::report::model::Report;
use crate::scan_events::{Envelope, EventType};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::time::Instant;

/// Sane minimum terminal width: below this the frame degrades to a
/// truncated header plus a narrow-terminal notice instead of the row
/// table. Rendering never panics at any width, including 0.
pub const MIN_WIDTH: usize = 40;
/// Sane minimum terminal height: below this only as many rows fit as
/// the screen holds (header first, then rows, footer last).
pub const MIN_HEIGHT: usize = 8;
/// Minimum redraw interval: the view renders at most ~10fps no matter
/// how fast snapshots or keys arrive.
pub const REDRAW_MIN_INTERVAL_MS: u64 = 100;
/// Minimum interval between live catalog row refreshes during a scan
/// (main thread only; workers never run aggregate queries).
pub const ROWS_REFRESH_MIN_MS: u64 = 2_000;
/// Bounds for one live catalog refresh: groups, group edges, stores,
/// checkouts, statuses, refs. The live view is a window, never an
/// unbounded dump; the retained snapshot carries the full inventory.
pub const LIVE_MAX_GROUPS: i64 = 500;
pub const LIVE_MAX_GROUP_EDGES: i64 = 5_000;
pub const LIVE_MAX_STORES: i64 = 1_000;
pub const LIVE_MAX_CHECKOUTS: i64 = 2_000;
pub const LIVE_MAX_STATUSES: i64 = 2_000;
pub const LIVE_MAX_REFS: i64 = 2_000;

// ---------------------------------------------------------------------------
// Unicode width + truncation (no new dependencies)
// ---------------------------------------------------------------------------

/// Combining/zero-width ranges (subset of Markus Kuhn's `wcwidth`
/// table plus zero-width format characters): characters that occupy
/// no terminal column.
const ZERO_WIDTH_RANGES: &[(u32, u32)] = &[
    (0x0300, 0x036F),
    (0x0483, 0x0489),
    (0x0591, 0x05BD),
    (0x05BF, 0x05BF),
    (0x05C1, 0x05C2),
    (0x05C4, 0x05C5),
    (0x05C7, 0x05C7),
    (0x0600, 0x0605),
    (0x0610, 0x061A),
    (0x064B, 0x065F),
    (0x0670, 0x0670),
    (0x06D6, 0x06DC),
    (0x06DF, 0x06E4),
    (0x06E7, 0x06E8),
    (0x06EA, 0x06ED),
    (0x0E31, 0x0E31),
    (0x0E34, 0x0E3A),
    (0x0E47, 0x0E4E),
    (0x0F18, 0x0F19),
    (0x0F35, 0x0F35),
    (0x0F37, 0x0F37),
    (0x0F39, 0x0F39),
    (0x0F71, 0x0F84),
    (0x0F86, 0x0F87),
    (0x0F8D, 0x0F97),
    (0x0F99, 0x0FBC),
    (0x0FC6, 0x0FC6),
    (0x102B, 0x103E),
    (0x1050, 0x109D),
    (0x1160, 0x11FF),
    (0x135D, 0x135F),
    (0x1712, 0x1714),
    (0x1732, 0x1734),
    (0x1752, 0x1753),
    (0x1772, 0x1773),
    (0x17B4, 0x17D3),
    (0x17DD, 0x17DD),
    (0x180B, 0x180D),
    (0x18A9, 0x18A9),
    (0x1920, 0x192B),
    (0x1930, 0x193B),
    (0x19A0, 0x19A0),
    (0x19A0, 0x19A9),
    (0x1A17, 0x1A1B),
    (0x1A55, 0x1A5E),
    (0x1A60, 0x1A7C),
    (0x1A7F, 0x1A7F),
    (0x1AB0, 0x1AFF),
    (0x1B00, 0x1B04),
    (0x1B34, 0x1B44),
    (0x1B6B, 0x1B73),
    (0x1B80, 0x1B81),
    (0x1BA1, 0x1BA1),
    (0x1BA6, 0x1BA7),
    (0x1BE6, 0x1BF3),
    (0x1C24, 0x1C37),
    (0x1CD0, 0x1CD2),
    (0x1CD4, 0x1CE8),
    (0x1CED, 0x1CED),
    (0x1CF2, 0x1CF3),
    (0x1DC0, 0x1DE6),
    (0x1DFC, 0x1DFF),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0x20D0, 0x20F0),
    (0x2CEF, 0x2CF1),
    (0x2D7F, 0x2D7F),
    (0x2DE0, 0x2DFF),
    (0x302A, 0x302F),
    (0x3099, 0x309A),
    (0xA66F, 0xA672),
    (0xA674, 0xA67D),
    (0xA69E, 0xA69F),
    (0xA6F0, 0xA6F1),
    (0xA802, 0xA802),
    (0xA806, 0xA806),
    (0xA80B, 0xA80B),
    (0xA825, 0xA826),
    (0xA827, 0xA827),
    (0xA82C, 0xA82C),
    (0xA8C4, 0xA8C5),
    (0xA8E0, 0xA8F1),
    (0xA8FF, 0xA8FF),
    (0xA926, 0xA92D),
    (0xA947, 0xA951),
    (0xAA29, 0xAA36),
    (0xAA43, 0xAA43),
    (0xAA4C, 0xAA4C),
    (0xAA7C, 0xAA7C),
    (0xAAB0, 0xAAB0),
    (0xAAB2, 0xAAB4),
    (0xAAB7, 0xAAB8),
    (0xAABE, 0xAABF),
    (0xAAC1, 0xAAC1),
    (0xAAEC, 0xAAED),
    (0xAAF6, 0xAAF6),
    (0xABE5, 0xABE5),
    (0xABE8, 0xABE8),
    (0xABED, 0xABED),
    (0xFB1E, 0xFB1E),
    (0xFE00, 0xFE0F),
    (0xFE20, 0xFE2F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x101FD, 0x101FD),
    (0x102E0, 0x102E0),
    (0x10376, 0x1037A),
    (0x10A01, 0x10A03),
    (0x10A05, 0x10A06),
    (0x10A0C, 0x10A0F),
    (0x10A38, 0x10A3A),
    (0x10A3F, 0x10A3F),
    (0x10AE5, 0x10AE6),
    (0x10D24, 0x10D27),
    (0x10EAB, 0x10EAC),
    (0x10EFD, 0x10F00),
    (0x10F46, 0x10F50),
    (0x11000, 0x11002),
    (0x11038, 0x11046),
    (0x1107F, 0x11082),
    (0x110B0, 0x110BA),
    (0x11100, 0x11102),
    (0x11127, 0x11134),
    (0x11145, 0x11146),
    (0x11173, 0x11173),
    (0x11180, 0x11182),
    (0x111B6, 0x111C0),
    (0x111C9, 0x111CC),
    (0x1122C, 0x11237),
    (0x112DF, 0x112EA),
    (0x112F0, 0x112F1),
    (0x11300, 0x11303),
    (0x1133B, 0x1133C),
    (0x1133E, 0x11344),
    (0x11347, 0x11348),
    (0x1134B, 0x1134D),
    (0x11357, 0x11357),
    (0x11362, 0x11363),
    (0x11366, 0x1136C),
    (0x11370, 0x11374),
    (0x11435, 0x11446),
    (0x1145E, 0x1145E),
    (0x11461, 0x11461),
    (0x114B0, 0x114C3),
    (0x115AF, 0x115B5),
    (0x115B8, 0x115C0),
    (0x115DC, 0x115DD),
    (0x11630, 0x11640),
    (0x116AB, 0x116B7),
    (0x1171D, 0x1172B),
    (0x1182C, 0x1183A),
    (0x11930, 0x11935),
    (0x11937, 0x11938),
    (0x1193B, 0x1193C),
    (0x1193E, 0x1193E),
    (0x11943, 0x11943),
    (0x119D1, 0x119D7),
    (0x119DA, 0x119DB),
    (0x119E0, 0x119E0),
    (0x11A01, 0x11A0A),
    (0x11A33, 0x11A38),
    (0x11A3B, 0x11A3E),
    (0x11A47, 0x11A47),
    (0x11A51, 0x11A56),
    (0x11A59, 0x11A5B),
    (0x11A8A, 0x11A96),
    (0x11A98, 0x11A99),
    (0x11C2F, 0x11C36),
    (0x11C38, 0x11C3D),
    (0x11C3F, 0x11C3F),
    (0x11C92, 0x11CA7),
    (0x11CAA, 0x11CB0),
    (0x11CB2, 0x11CB3),
    (0x11CB5, 0x11CB6),
    (0x11D31, 0x11D36),
    (0x11D3A, 0x11D3A),
    (0x11D3C, 0x11D3D),
    (0x11D3F, 0x11D45),
    (0x11D47, 0x11D47),
    (0x11D8A, 0x11D8E),
    (0x11D90, 0x11D91),
    (0x11D93, 0x11D94),
    (0x11D96, 0x11D96),
    (0x11D97, 0x11D97),
    (0x11EF3, 0x11EF6),
    (0x11F00, 0x11F01),
    (0x11F34, 0x11F3A),
    (0x11F3E, 0x11F42),
    (0x13430, 0x13438),
    (0x16AF0, 0x16AF4),
    (0x16B30, 0x16B36),
    (0x16F4F, 0x16F4F),
    (0x16F8F, 0x16F92),
    (0x1BCA0, 0x1BCA3),
    (0x1CF00, 0x1CF2D),
    (0x1CF30, 0x1CF46),
    (0x1D165, 0x1D169),
    (0x1D16D, 0x1D172),
    (0x1D17B, 0x1D182),
    (0x1D185, 0x1D18B),
    (0x1D1AA, 0x1D1AD),
    (0x1D242, 0x1D244),
    (0x1DA00, 0x1DA36),
    (0x1DA3B, 0x1DA6C),
    (0x1DA75, 0x1DA75),
    (0x1DA84, 0x1DA84),
    (0x1DA9B, 0x1DA9F),
    (0x1DAA1, 0x1DAAF),
    (0x1E000, 0x1E006),
    (0x1E008, 0x1E018),
    (0x1E01B, 0x1E021),
    (0x1E023, 0x1E024),
    (0x1E026, 0x1E02A),
    (0x1E130, 0x1E136),
    (0x1E2AE, 0x1E2AE),
    (0x1E2EC, 0x1E2EF),
    (0x1E8D0, 0x1E8D6),
    (0x1E944, 0x1E94A),
    (0xE0000, 0xE0FFF),
    (0xE0100, 0xE01EF),
];

/// Wide (double-column) ranges: East Asian Wide/Fullwidth blocks plus
/// the emoji blocks terminals commonly render double-width.
const WIDE_RANGES: &[(u32, u32)] = &[
    (0x1100, 0x115F),
    (0x231A, 0x231B),
    (0x2329, 0x232A),
    (0x23E9, 0x23EC),
    (0x23F0, 0x23F0),
    (0x23F3, 0x23F3),
    (0x25FD, 0x25FE),
    (0x2614, 0x2615),
    (0x2648, 0x2653),
    (0x267F, 0x267F),
    (0x2693, 0x2693),
    (0x26A1, 0x26A1),
    (0x26AA, 0x26AB),
    (0x26BD, 0x26BE),
    (0x26C4, 0x26C5),
    (0x26CE, 0x26CE),
    (0x26D4, 0x26D4),
    (0x26EA, 0x26EA),
    (0x26F2, 0x26F3),
    (0x26F5, 0x26F5),
    (0x26FA, 0x26FA),
    (0x26FD, 0x26FD),
    (0x2705, 0x2705),
    (0x270A, 0x270B),
    (0x2728, 0x2728),
    (0x274C, 0x274C),
    (0x274E, 0x274E),
    (0x2753, 0x2755),
    (0x2757, 0x2757),
    (0x2795, 0x2797),
    (0x27B0, 0x27B0),
    (0x27BF, 0x27BF),
    (0x2B1B, 0x2B1C),
    (0x2B50, 0x2B50),
    (0x2B55, 0x2B55),
    (0x2C00, 0x2CE4),
    (0x2CEF, 0x2CF1),
    (0x2CF2, 0x2CF2),
    (0x2D00, 0x2D65),
    (0x2D6F, 0x2D6F),
    (0x2E80, 0x2E99),
    (0x2E9B, 0x2EF3),
    (0x2F00, 0x2FD5),
    (0x2FF0, 0x2FFB),
    (0x3000, 0x3029),
    (0x302E, 0x303E),
    (0x3041, 0x3096),
    (0x3099, 0x30FF),
    (0x3105, 0x312D),
    (0x3131, 0x318E),
    (0x3190, 0x31BA),
    (0x31C0, 0x31E3),
    (0x31F0, 0x321E),
    (0x3220, 0x3247),
    (0x3250, 0x32FE),
    (0x3300, 0x4DBF),
    (0x4E00, 0xA48C),
    (0xA490, 0xA4C6),
    (0xA960, 0xA97C),
    (0xAC00, 0xD7A3),
    (0xF900, 0xFAFF),
    (0xFE10, 0xFE19),
    (0xFE30, 0xFE52),
    (0xFE54, 0xFE66),
    (0xFE68, 0xFE6B),
    (0xFF00, 0xFF60),
    (0xFFE0, 0xFFE6),
    (0x16FE0, 0x16FE0),
    (0x17000, 0x187EC),
    (0x18800, 0x18AF2),
    (0x18AF3, 0x18AF3),
    (0x18B00, 0x18CD5),
    (0x18D00, 0x18D08),
    (0x1AFF0, 0x1AFF3),
    (0x1AFF5, 0x1AFFB),
    (0x1AFFD, 0x1AFFE),
    (0x1B000, 0x1B001),
    (0x1F004, 0x1F004),
    (0x1F0CF, 0x1F0CF),
    (0x1F18E, 0x1F18E),
    (0x1F191, 0x1F19A),
    (0x1F200, 0x1F202),
    (0x1F210, 0x1F23B),
    (0x1F240, 0x1F248),
    (0x1F250, 0x1F251),
    (0x1F300, 0x1F320),
    (0x1F32D, 0x1F335),
    (0x1F337, 0x1F37C),
    (0x1F37E, 0x1F393),
    (0x1F3A0, 0x1F3CA),
    (0x1F3CF, 0x1F3D3),
    (0x1F3E0, 0x1F3F0),
    (0x1F3F4, 0x1F3F4),
    (0x1F3F8, 0x1F43E),
    (0x1F440, 0x1F440),
    (0x1F442, 0x1F4F7),
    (0x1F4F9, 0x1F4FC),
    (0x1F4FF, 0x1F53D),
    (0x1F54B, 0x1F54E),
    (0x1F550, 0x1F567),
    (0x1F57A, 0x1F57A),
    (0x1F595, 0x1F596),
    (0x1F5A4, 0x1F5A4),
    (0x1F5FB, 0x1F64F),
    (0x1F680, 0x1F6C5),
    (0x1F6CC, 0x1F6CC),
    (0x1F6D0, 0x1F6D2),
    (0x1F6D5, 0x1F6D7),
    (0x1F6EB, 0x1F6EC),
    (0x1F6F4, 0x1F6FA),
    (0x1F7E0, 0x1F7EB),
    (0x1F90D, 0x1F971),
    (0x1F973, 0x1F976),
    (0x1F97A, 0x1F9A2),
    (0x1F9A5, 0x1F9AA),
    (0x1F9AE, 0x1F9CA),
    (0x1F9CD, 0x1F9FF),
    (0x1FA70, 0x1FA73),
    (0x1FA78, 0x1FA7A),
    (0x1FA80, 0x1FA82),
    (0x1FA90, 0x1FA95),
    (0x20000, 0x2FFFD),
    (0x30000, 0x3FFFD),
];

fn in_ranges(value: u32, ranges: &[(u32, u32)]) -> bool {
    ranges.iter().any(|(lo, hi)| value >= *lo && value <= *hi)
}

/// Terminal column width of one character: 0 for control and
/// combining characters, 2 for wide characters, 1 otherwise.
pub fn char_width(c: char) -> usize {
    if c.is_control() {
        return 0;
    }
    let value = c as u32;
    if in_ranges(value, ZERO_WIDTH_RANGES) {
        return 0;
    }
    if in_ranges(value, WIDE_RANGES) {
        return 2;
    }
    1
}

/// Terminal column width of a string (sum of [`char_width`]).
pub fn display_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

/// Truncate `text` to at most `max` terminal columns, appending `…`
/// (U+2026, one column) when anything was cut. Never splits a
/// character; a wide character that does not fit the remaining
/// columns is dropped with the ellipsis. `max == 0` yields `""`;
/// `max == 1` with an over-long string yields `"…"`.
pub fn truncate_to_width(text: &str, max: usize) -> String {
    if display_width(text) <= max {
        return text.to_string();
    }
    if max == 0 {
        return String::new();
    }
    if max == 1 {
        return "…".to_string();
    }
    let budget = max - 1; // room for the ellipsis
    let mut out = String::new();
    let mut width = 0;
    for c in text.chars() {
        let w = char_width(c);
        if width + w > budget {
            break;
        }
        out.push(c);
        width += w;
    }
    out.push('…');
    out
}

/// Truncate a long path to at most `max` columns keeping the TAIL
/// (the filename end users recognize), prefixed with `…`. Short
/// paths pass through; `max == 0` yields `""`.
pub fn truncate_path_tail(text: &str, max: usize) -> String {
    if display_width(text) <= max {
        return text.to_string();
    }
    if max == 0 {
        return String::new();
    }
    if max == 1 {
        return "…".to_string();
    }
    let budget = max - 1; // room for the ellipsis
    let mut chars: Vec<char> = Vec::new();
    let mut width = 0;
    for c in text.chars().rev() {
        let w = char_width(c);
        if width + w > budget {
            break;
        }
        chars.push(c);
        width += w;
    }
    let mut out = String::from("…");
    for c in chars.iter().rev() {
        out.push(*c);
    }
    out
}

// ---------------------------------------------------------------------------
// Color
// ---------------------------------------------------------------------------

/// Terminal color control, mirroring `cli::ColorChoice` (the TUI maps
/// the CLI value at the wiring site so this module stays dependency-free).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMode {
    /// Color when stdout is a TTY and neither `NO_COLOR` nor
    /// `TERM=dumb` disables it.
    #[default]
    Auto,
    /// Color even when redirected; `NO_COLOR`/`TERM=dumb` still win.
    Always,
    /// Never emit ANSI escapes (labels still render as text).
    Never,
}

/// Resolve whether ANSI escapes are emitted, reading the process
/// environment (`NO_COLOR` presence, `TERM=dumb`) directly.
pub fn resolve_color(mode: ColorMode, stdout_is_tty: bool) -> bool {
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let term_dumb = std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false);
    resolve_color_with(mode, stdout_is_tty, no_color, term_dumb)
}

/// [`resolve_color`] with explicit environment inputs (deterministic
/// for tests): `NO_COLOR` set or `TERM=dumb` disables color under
/// every mode; otherwise `Always` forces it on, `Never` forces it
/// off, and `Auto` follows the TTY.
pub fn resolve_color_with(
    mode: ColorMode,
    stdout_is_tty: bool,
    no_color: bool,
    term_dumb: bool,
) -> bool {
    if no_color || term_dumb {
        return false;
    }
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => stdout_is_tty,
    }
}

/// ANSI SGR codes used by the renderer (each row also carries a text
/// label, so color is never the only signal).
pub mod ansi {
    /// Reset all attributes.
    pub const RESET: &str = "\x1b[0m";
    /// Bold.
    pub const BOLD: &str = "\x1b[1m";
    /// Dim.
    pub const DIM: &str = "\x1b[2m";
    /// Reversed (selection cursor).
    pub const REVERSE: &str = "\x1b[7m";
    /// Red (failed / conflicted / gaps).
    pub const RED: &str = "\x1b[31m";
    /// Green (clean / equal / complete).
    pub const GREEN: &str = "\x1b[32m";
    /// Yellow (dirty / pending / ahead / behind).
    pub const YELLOW: &str = "\x1b[33m";
    /// Blue (headers / group rows).
    pub const BLUE: &str = "\x1b[34m";
    /// Magenta (diverged).
    pub const MAGENTA: &str = "\x1b[35m";
    /// Cyan (detail overlay / info).
    pub const CYAN: &str = "\x1b[36m";
}

/// Wrap `text` in `code` + reset when `color` is on; plain text otherwise.
pub fn paint(code: &str, text: &str, color: bool) -> String {
    if color {
        format!("{code}{text}{}", ansi::RESET)
    } else {
        text.to_string()
    }
}

// ---------------------------------------------------------------------------
// Snapshot model (grouped view data)
// ---------------------------------------------------------------------------

/// Live header: phase, elapsed, and discovery/completion counters.
/// Never a percentage: the discovery total is unknown mid-scan.
#[derive(Debug, Clone, Default)]
pub struct TuiHeader {
    /// Scan id.
    pub scan_id: String,
    /// `running`, `complete`, `incomplete`, `interrupted`, `failed`.
    pub scan_state: String,
    /// `discovery`, `analysis`, `fetch`, `done`, or `unknown`.
    pub phase: String,
    /// Elapsed run seconds.
    pub elapsed_s: u64,
    /// Locations discovered so far.
    pub discovered: u64,
    /// Locations fully analyzed.
    pub completed: u64,
    /// Frontier tasks still pending.
    pub pending: u64,
    /// Open coverage gaps.
    pub gaps: u64,
    /// True when the snapshot comes from retained/cached bytes rather
    /// than a live scan.
    pub cached: bool,
    /// Snapshot age in seconds (cached snapshots only).
    pub snapshot_age_s: Option<u64>,
    /// True when a cached snapshot still has pending analysis: the
    /// rows are readable now and refresh on the next scan.
    pub pending_refresh: bool,
    /// Scan target as supplied (`--all` for target-free scans).
    pub target: String,
}

/// One branch row (leaf).
#[derive(Debug, Clone, Default)]
pub struct TuiBranch {
    /// Stable record id (`branch:<report branch id>`).
    pub id: String,
    /// Branch display name (escaped).
    pub name: String,
    /// Full refname when it differs from the display name.
    pub full_name: Option<String>,
    /// `local`, `remote_tracking`, or `other`.
    pub kind: String,
    /// Comparison state (`equal|ahead|behind|diverged|no_upstream|
    /// `upstream_missing|pending|incomplete_history|error`).
    pub comparison: String,
    /// Commits ahead of the upstream (counted states only).
    pub ahead: Option<u64>,
    /// Commits behind the upstream (counted states only).
    pub behind: Option<u64>,
    /// Resolved upstream ref, when known.
    pub upstream: Option<String>,
    /// Tip oid hex, when known.
    pub oid: Option<String>,
    /// Attached error record ids.
    pub error_ids: Vec<String>,
}

/// One checkout row (expandable when it carries branches).
#[derive(Debug, Clone, Default)]
pub struct TuiCheckout {
    /// Stable record id (`checkout:<id>`).
    pub id: String,
    /// Worktree root path (escaped display form).
    pub path: String,
    /// Git directory path (escaped display form).
    pub git_path: String,
    /// `main`, `linked`, `submodule`, or `unknown`.
    pub kind: String,
    /// `present`, `missing`, `inaccessible`, `broken`, or `unknown`.
    pub availability: String,
    /// HEAD state (`branch|detached|unborn|invalid|unknown`).
    pub head_state: String,
    /// HEAD ref display name, when on a branch.
    pub head_ref: Option<String>,
    /// HEAD oid hex, when known.
    pub head_oid: Option<String>,
    /// Status observation state (`complete|partial|pending|
    /// `not_requested|unsupported|unstable|error`).
    pub status_state: String,
    /// Working-state vocabulary (`clean|dirty|conflicted|pending|
    /// `partial|unstable|unknown|error|not_applicable`).
    pub working_state: String,
    /// Staged/unstaged/untracked/conflict counts (unknown stays null).
    pub staged: Option<u64>,
    pub unstaged: Option<u64>,
    pub untracked: Option<u64>,
    pub conflicts: Option<u64>,
    /// True while analysis has not finished this checkout: the row is
    /// visible before analysis completes.
    pub analysis_pending: bool,
    /// Attached error record ids.
    pub error_ids: Vec<String>,
    /// Branches scoped to this checkout (empty for store-scoped rows).
    pub branches: Vec<TuiBranch>,
}

/// One local store row (a `git_instances` row: one common dir +
/// physical identity; independent clones stay separate).
#[derive(Debug, Clone, Default)]
pub struct TuiStore {
    /// Stable record id (`store:<repository id>`).
    pub id: String,
    /// Common-dir path (escaped display form).
    pub path: String,
    /// Git-dir path when it differs from the common dir.
    pub git_path: Option<String>,
    /// `confirmed|related|probable|nonmatch|unresolvable_identity`.
    pub match_disposition: String,
    /// Bare flag, when known.
    pub bare: Option<bool>,
    /// Attached error record ids.
    pub error_ids: Vec<String>,
    /// Checkouts of this store.
    pub checkouts: Vec<TuiCheckout>,
    /// Store-level branches (no checkout scope).
    pub branches: Vec<TuiBranch>,
}

/// One account/org > repository group row.
#[derive(Debug, Clone, Default)]
pub struct TuiGroup {
    /// Stable record id (`group:<lower(host/account/repo)>` or
    /// `group:ungrouped`).
    pub id: String,
    /// Normalized host (`github.com`), if grouped.
    pub host: Option<String>,
    /// Normalized account/org login, if grouped.
    pub account: Option<String>,
    /// Normalized repository name, if grouped.
    pub repo: Option<String>,
    /// Stores associated with this group.
    pub stores: Vec<TuiStore>,
}

impl TuiGroup {
    /// Display label: `account/repo` or `ungrouped`.
    pub fn label(&self) -> String {
        match (&self.account, &self.repo) {
            (Some(account), Some(repo)) => format!("{account}/{repo}"),
            _ => "ungrouped".to_string(),
        }
    }
}

/// One full view snapshot: aggregate header plus grouped rows.
#[derive(Debug, Clone, Default)]
pub struct TuiSnapshot {
    /// Aggregate header (rendered before any row).
    pub header: TuiHeader,
    /// Groups in canonical order (account, repo; ungrouped last).
    pub groups: Vec<TuiGroup>,
}

impl TuiSnapshot {
    /// Empty snapshot with a blank header (live sessions start here
    /// and fill in as events arrive).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Aggregate counts over the grouped rows: (groups, stores,
    /// checkouts, branches, pending rows, failed rows).
    pub fn counts(&self) -> (usize, usize, usize, usize, usize, usize) {
        let mut stores = 0;
        let mut checkouts = 0;
        let mut branches = 0;
        let mut pending = 0;
        let mut failed = 0;
        for group in &self.groups {
            for store in &group.stores {
                stores += 1;
                failed += usize::from(store_failed(store));
                for branch in &store.branches {
                    branches += 1;
                    pending += usize::from(branch_pending(branch));
                    failed += usize::from(branch_failed(branch));
                }
                for checkout in &store.checkouts {
                    checkouts += 1;
                    pending += usize::from(checkout_pending(checkout));
                    failed += usize::from(checkout_failed(checkout));
                    for branch in &checkout.branches {
                        branches += 1;
                        pending += usize::from(branch_pending(branch));
                        failed += usize::from(branch_failed(branch));
                    }
                }
            }
        }
        (
            self.groups.len(),
            stores,
            checkouts,
            branches,
            pending,
            failed,
        )
    }

    /// Find a group by id, mutably.
    fn group_mut(&mut self, id: &str) -> Option<&mut TuiGroup> {
        self.groups.iter_mut().find(|g| g.id == id)
    }

    /// Ensure a group row exists (appended ungrouped-last when new).
    fn ensure_group(
        &mut self,
        id: &str,
        host: Option<String>,
        account: Option<String>,
        repo: Option<String>,
    ) {
        if self.group_mut(id).is_none() {
            let group = TuiGroup {
                id: id.to_string(),
                host,
                account,
                repo,
                stores: Vec::new(),
            };
            // Ungrouped sorts last; grouped rows insert before it.
            if id == UNGROUPED_ID {
                self.groups.push(group);
            } else if let Some(pos) = self.groups.iter().position(|g| g.id == UNGROUPED_ID) {
                self.groups.insert(pos, group);
            } else {
                self.groups.push(group);
            }
        }
    }

    /// Find a store by id across groups, mutably.
    fn store_mut(&mut self, id: &str) -> Option<&mut TuiStore> {
        self.groups
            .iter_mut()
            .flat_map(|g| g.stores.iter_mut())
            .find(|s| s.id == id)
    }

    /// Find a checkout by id across groups, mutably.
    fn checkout_mut(&mut self, id: &str) -> Option<&mut TuiCheckout> {
        self.groups
            .iter_mut()
            .flat_map(|g| g.stores.iter_mut())
            .flat_map(|s| s.checkouts.iter_mut())
            .find(|c| c.id == id)
    }
}

/// Stable id of the fallback group for stores without a parsed
/// account/repo association.
pub const UNGROUPED_ID: &str = "group:ungrouped";

// ---------------------------------------------------------------------------
// Row predicates (filters, counts, sort severities share these)
// ---------------------------------------------------------------------------

/// True when the checkout carries failed state: an error status, an
/// error working state, attached error records, or a failed
/// availability (`missing|broken|inaccessible`).
pub fn checkout_failed(checkout: &TuiCheckout) -> bool {
    checkout.status_state == "error"
        || checkout.working_state == "error"
        || !checkout.error_ids.is_empty()
        || matches!(
            checkout.availability.as_str(),
            "missing" | "broken" | "inaccessible"
        )
        || checkout.branches.iter().any(branch_failed)
}

/// True while the checkout still awaits analysis.
pub fn checkout_pending(checkout: &TuiCheckout) -> bool {
    checkout.analysis_pending
        || checkout.status_state == "pending"
        || checkout.working_state == "pending"
        || checkout.branches.iter().any(branch_pending)
}

/// True when the branch carries failed state.
pub fn branch_failed(branch: &TuiBranch) -> bool {
    branch.comparison == "error" || !branch.error_ids.is_empty()
}

/// True while the branch comparison is still pending.
pub fn branch_pending(branch: &TuiBranch) -> bool {
    branch.comparison == "pending"
}

/// True when the store carries failed state (own errors or any
/// failed descendant).
fn store_failed(store: &TuiStore) -> bool {
    !store.error_ids.is_empty()
        || store.branches.iter().any(branch_failed)
        || store
            .checkouts
            .iter()
            .any(|c| checkout_failed(c) || c.branches.iter().any(branch_failed))
}

/// Severity rank for `state` sort (lower sorts first): failed,
/// conflicted, dirty, diverged, ahead/behind, pending, clean,
/// everything else.
pub fn checkout_severity(checkout: &TuiCheckout) -> u8 {
    if checkout_failed(checkout) {
        return 0;
    }
    if checkout.working_state == "conflicted" || checkout.conflicts.unwrap_or(0) > 0 {
        return 1;
    }
    if checkout.working_state == "dirty" {
        return 2;
    }
    let comparisons: Vec<&str> = checkout
        .branches
        .iter()
        .map(|b| b.comparison.as_str())
        .collect();
    if comparisons.contains(&"diverged") {
        return 3;
    }
    if comparisons.contains(&"ahead") || comparisons.contains(&"behind") {
        return 4;
    }
    if checkout_pending(checkout) {
        return 5;
    }
    if checkout.working_state == "clean" {
        return 6;
    }
    7
}

/// Severity rank for branch rows (same scale as checkouts).
pub fn branch_severity(branch: &TuiBranch) -> u8 {
    if branch_failed(branch) {
        return 0;
    }
    match branch.comparison.as_str() {
        "diverged" => 3,
        "ahead" | "behind" => 4,
        "pending" => 5,
        "equal" => 6,
        _ => 7,
    }
}

// ---------------------------------------------------------------------------
// Snapshot from a retained report
// ---------------------------------------------------------------------------

/// Parse `host/account/repo` from a canonical remote URL
/// (`https://host/account/repo[.git]`, any scheme). Returns the group
/// id plus parts, all lowercased per the D1 group-id rule. `None`
/// when the URL has no account/repo path.
pub fn group_parts_for_url(url: &str) -> Option<(String, String, String, String)> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let mut segments = after_scheme.split('/').filter(|s| !s.is_empty());
    let host = segments.next()?.to_lowercase();
    let account = segments.next()?.to_lowercase();
    let mut repo = segments.next()?.to_lowercase();
    if repo.ends_with(".git") {
        repo.truncate(repo.len() - 4);
    }
    if host.is_empty() || account.is_empty() || repo.is_empty() {
        return None;
    }
    let id = format!("group:{host}/{account}/{repo}");
    Some((id, host, account, repo))
}

/// Parse an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SS`, optional
/// fractional seconds and `Z` suffix) to unix milliseconds. `None`
/// on any shape or range violation (never panics, never guesses).
pub fn parse_rfc3339_ms(text: &str) -> Option<i64> {
    let date_time = text.strip_suffix('Z').unwrap_or(text);
    let (date, time) = date_time.split_once('T')?;
    let time = time.split('.').next()?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some()
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..60).contains(&second)
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    secs.checked_mul(1_000)
}

/// Days since the unix epoch (Howard Hinnant's days-from-civil).
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = ((month + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + (day as i64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Human age for a cached snapshot (`45s`, `12m`, `3h`, `5d`).
pub fn format_age(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

/// Human elapsed time (`45s`, `12m03s`, `3h12m`). Never a percentage.
pub fn format_elapsed(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h{:02}m", seconds / 3_600, (seconds % 3_600) / 60)
    }
}

impl TuiSnapshot {
    /// Build a view snapshot from a retained [`Report`]: stores group
    /// by the account/repo parsed from their first canonical remote
    /// URL (fetch role preferred), or land in `ungrouped`; checkouts
    /// attach to their store; branches attach to their checkout
    /// scope when present, else to their store. `now_ms` dates the
    /// snapshot age for cached reports.
    pub fn from_report(report: &Report, now_ms: i64) -> Self {
        let paths: HashMap<&str, &str> = report
            .paths
            .iter()
            .map(|p| (p.id.as_str(), p.display.as_str()))
            .collect();
        let show_path = |id: &str| -> String {
            paths
                .get(id)
                .map(|d| escape_display(d))
                .unwrap_or_else(|| format!("<missing path {}>", escape_display(id)))
        };
        // First canonical URL per store (fetch role wins ties).
        let mut store_group: HashMap<&str, (String, String, String, String)> = HashMap::new();
        for remote in &report.remotes {
            let Some(canonical) = remote.canonical_url.as_deref() else {
                continue;
            };
            let Some(parts) = group_parts_for_url(canonical) else {
                continue;
            };
            match store_group.get(remote.repository_id.as_str()) {
                None => {
                    store_group.insert(remote.repository_id.as_str(), parts);
                }
                Some(_) if remote.role == "fetch" => {
                    store_group.insert(remote.repository_id.as_str(), parts);
                }
                Some(_) => {}
            }
        }
        let mut snapshot = TuiSnapshot::empty();
        snapshot.header.scan_id = report.scan.id.clone();
        snapshot.header.scan_state = report.scan.state.clone();
        snapshot.header.target = if report.scan.target_url.is_empty() {
            "--all".to_string()
        } else {
            report.scan.target_url.clone()
        };
        snapshot.header.phase = match report.scan.state.as_str() {
            "running" => "discovery".to_string(),
            "complete" | "incomplete" | "interrupted" | "failed" => "done".to_string(),
            _ => "unknown".to_string(),
        };
        snapshot.header.gaps = report.coverage.gaps;
        snapshot.header.pending = report.coverage.tasks_pending;
        snapshot.header.cached = report.scan.cached;
        if report.scan.cached {
            snapshot.header.snapshot_age_s = parse_rfc3339_ms(&report.created_at)
                .and_then(|created| now_ms.checked_sub(created))
                .map(|age_ms| u64::try_from(age_ms).unwrap_or(0) / 1_000);
        }
        let mut checkouts_by_store: HashMap<&str, Vec<TuiCheckout>> = HashMap::new();
        for checkout in &report.checkouts {
            let pending =
                checkout.status.state == "pending" || checkout.status.working_state == "pending";
            checkouts_by_store
                .entry(checkout.repository_id.as_str())
                .or_default()
                .push(TuiCheckout {
                    id: format!("checkout:{}", checkout.id),
                    path: checkout
                        .root_path_id
                        .as_deref()
                        .map(&show_path)
                        .unwrap_or_else(|| show_path(&checkout.git_path_id)),
                    git_path: show_path(&checkout.git_path_id),
                    kind: checkout.kind.clone(),
                    availability: checkout.availability.clone(),
                    head_state: checkout.head.state.clone(),
                    head_ref: checkout
                        .head
                        .ref_name
                        .as_ref()
                        .map(|n| escape_display(&n.display)),
                    head_oid: checkout.head.oid.as_ref().map(|o| o.hex.clone()),
                    status_state: checkout.status.state.clone(),
                    working_state: checkout.status.working_state.clone(),
                    staged: checkout.status.staged,
                    unstaged: checkout.status.unstaged,
                    untracked: checkout.status.untracked,
                    conflicts: checkout.status.conflicts,
                    analysis_pending: pending,
                    error_ids: checkout.error_ids.clone(),
                    branches: Vec::new(),
                });
        }
        let mut store_branches: HashMap<&str, Vec<TuiBranch>> = HashMap::new();
        let mut checkout_branches: HashMap<&str, Vec<TuiBranch>> = HashMap::new();
        for branch in &report.branches {
            let record = TuiBranch {
                id: format!("branch:{}", branch.id),
                name: escape_display(&branch.name.display),
                full_name: None,
                kind: branch.kind.clone(),
                comparison: branch.comparison.clone(),
                ahead: branch.ahead,
                behind: branch.behind,
                upstream: branch.upstream.as_ref().map(|u| escape_display(&u.display)),
                oid: branch.oid.as_ref().map(|o| o.hex.clone()),
                error_ids: branch.error_ids.clone(),
            };
            match branch.checkout_scope_id.as_deref() {
                Some(scope) => checkout_branches.entry(scope).or_default().push(record),
                None => store_branches
                    .entry(branch.repository_id.as_str())
                    .or_default()
                    .push(record),
            }
        }
        // Attach checkout-scoped branches (unknown scopes fall back to
        // their store so no branch is silently dropped).
        let mut orphan_branches: HashMap<&str, Vec<TuiBranch>> = HashMap::new();
        for (scope, mut list) in checkout_branches {
            let mut attached = false;
            for checkouts in checkouts_by_store.values_mut() {
                for checkout in checkouts.iter_mut() {
                    if checkout.id == format!("checkout:{scope}") {
                        checkout.branches.append(&mut list);
                        attached = true;
                        break;
                    }
                }
            }
            if !attached {
                // Scope names a checkout id not in this report; keep
                // the branches visible at the store level instead of
                // dropping them. The scope id doubles as a store hint
                // only when it matches; otherwise they join ungrouped
                // handling below via the empty key.
                orphan_branches.entry(scope).or_default().append(&mut list);
            }
        }
        for repo in &report.repositories {
            let (group_id, host, account, repo_name) = store_group
                .get(repo.id.as_str())
                .map(|(id, host, account, repo_name)| {
                    (
                        id.clone(),
                        Some(host.clone()),
                        Some(account.clone()),
                        Some(repo_name.clone()),
                    )
                })
                .unwrap_or_else(|| (UNGROUPED_ID.to_string(), None, None, None));
            snapshot.ensure_group(&group_id, host, account, repo_name);
            let common = show_path(&repo.common_path_id);
            let git = show_path(&repo.git_path_id);
            let mut store = TuiStore {
                id: format!("store:{}", repo.id),
                path: common,
                git_path: (git != show_path(&repo.common_path_id)).then_some(git),
                match_disposition: repo.match_disposition.clone(),
                bare: repo.bare,
                error_ids: repo.error_ids.clone(),
                checkouts: checkouts_by_store
                    .remove(repo.id.as_str())
                    .unwrap_or_default(),
                branches: store_branches.remove(repo.id.as_str()).unwrap_or_default(),
            };
            if let Some(extra) = orphan_branches.remove(repo.id.as_str()) {
                store.branches.extend(extra);
            }
            for checkout in &mut store.checkouts {
                checkout.branches.sort_by(|a, b| {
                    branch_kind_order(&a.kind)
                        .cmp(&branch_kind_order(&b.kind))
                        .then_with(|| a.name.cmp(&b.name))
                });
            }
            store.checkouts.sort_by(|a, b| a.path.cmp(&b.path));
            store.branches.sort_by(|a, b| {
                branch_kind_order(&a.kind)
                    .cmp(&branch_kind_order(&b.kind))
                    .then_with(|| a.name.cmp(&b.name))
            });
            if let Some(group) = snapshot.group_mut(&group_id) {
                group.stores.push(store);
            }
        }
        // Orphan checkouts (repository missing from the report) stay
        // visible under ungrouped rather than vanishing.
        let orphans: Vec<TuiCheckout> = checkouts_by_store.into_values().flatten().collect();
        if !orphans.is_empty() {
            snapshot.ensure_group(UNGROUPED_ID, None, None, None);
            if let Some(group) = snapshot.group_mut(UNGROUPED_ID) {
                group.stores.push(TuiStore {
                    id: "store:orphan-checkouts".to_string(),
                    path: "<missing store>".to_string(),
                    match_disposition: "unknown".to_string(),
                    checkouts: orphans,
                    ..TuiStore::default()
                });
            }
        }
        for group in &mut snapshot.groups {
            group.stores.sort_by(|a, b| a.path.cmp(&b.path));
        }
        snapshot
            .groups
            .sort_by_key(|a| (a.id == UNGROUPED_ID, a.label()));
        // Completed = checkouts no longer pending; discovered = all rows.
        let (_, _, checkouts, branches, pending, _) = snapshot.counts();
        snapshot.header.discovered = (checkouts + branches) as u64;
        snapshot.header.completed = (checkouts + branches).saturating_sub(pending) as u64;
        snapshot.header.pending_refresh =
            snapshot.header.cached && (pending > 0 || snapshot.header.scan_state == "running");
        snapshot
    }
}

/// Branch kind order for the default sort: local first, then
/// remote-tracking, then everything else.
fn branch_kind_order(kind: &str) -> u8 {
    match kind {
        "local" => 0,
        "remote_tracking" => 1,
        _ => 2,
    }
}

// ---------------------------------------------------------------------------
// Live folding of journal envelopes
// ---------------------------------------------------------------------------

fn json_str(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_string)
}

fn json_u64(value: &serde_json::Value, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}

impl TuiSnapshot {
    /// Fold one committed journal envelope into the live snapshot
    /// (idempotent on re-delivery: same ids replace in place, gauges
    /// overwrite). Unknown or malformed payloads are ignored field by
    /// field — a partial envelope still updates what it can — so old
    /// and new journals both fold without version gates.
    pub fn apply_envelope(&mut self, env: &Envelope) {
        if self.header.scan_id.is_empty() {
            self.header.scan_id = env.scan_id.clone();
        }
        match env.event_type {
            EventType::ScanStarted => {
                self.header.scan_state = "running".to_string();
                self.header.phase = "discovery".to_string();
                if let Some(target) = json_str(&env.records, "target")
                    .or_else(|| json_str(&env.records, "target_url"))
                {
                    self.header.target = target;
                }
            }
            EventType::DiscoveryProgress => {
                if let Some(phase) = json_str(&env.records, "phase") {
                    self.header.phase = phase;
                }
                if let Some(elapsed) = json_u64(&env.records, "elapsed_s") {
                    self.header.elapsed_s = elapsed;
                }
                if let Some(pending) = json_u64(&env.records, "pending") {
                    self.header.pending = pending;
                }
                if let Some(discovered) = env
                    .records
                    .get("discovered")
                    .and_then(|d| d.get("tasks_done"))
                    .and_then(serde_json::Value::as_u64)
                {
                    self.header.discovered = discovered;
                }
                if let Some(gaps) = env
                    .records
                    .get("gaps")
                    .and_then(|g| g.get("open"))
                    .and_then(serde_json::Value::as_u64)
                {
                    self.header.gaps = gaps;
                }
            }
            EventType::RepositoryFound => {
                let Some(store_id) = json_str(&env.records, "store_id") else {
                    return;
                };
                let id = format!("store:{store_id}");
                if self.store_mut(&id).is_none() {
                    let (group_id, host, account, repo) = first_group_in(&env.records);
                    self.ensure_group(&group_id, host, account, repo);
                    let store = TuiStore {
                        id: id.clone(),
                        path: "<discovering>".to_string(),
                        match_disposition: "unknown".to_string(),
                        ..TuiStore::default()
                    };
                    if let Some(group) = self.group_mut(&group_id) {
                        group.stores.push(store);
                        group.stores.sort_by(|a, b| a.path.cmp(&b.path));
                    }
                }
            }
            EventType::LocationFound => {
                let (Some(checkout_id), Some(store_id)) = (
                    json_str(&env.records, "checkout_id"),
                    json_str(&env.records, "store_id"),
                ) else {
                    return;
                };
                let id = format!("checkout:{checkout_id}");
                if self.checkout_mut(&id).is_some() {
                    return; // idempotent re-delivery
                }
                let store_key = format!("store:{store_id}");
                if self.store_mut(&store_key).is_none() {
                    let (group_id, host, account, repo) = first_group_in(&env.records);
                    self.ensure_group(&group_id, host, account, repo);
                    if let Some(group) = self.group_mut(&group_id) {
                        group.stores.push(TuiStore {
                            id: store_key.clone(),
                            path: json_str(&env.records, "git_path")
                                .map(|p| escape_display(&p))
                                .unwrap_or_else(|| "<discovering>".to_string()),
                            match_disposition: "unknown".to_string(),
                            ..TuiStore::default()
                        });
                    }
                }
                let checkout = TuiCheckout {
                    id,
                    path: json_str(&env.records, "path")
                        .map(|p| escape_display(&p))
                        .unwrap_or_else(|| "<discovering>".to_string()),
                    git_path: json_str(&env.records, "git_path")
                        .map(|p| escape_display(&p))
                        .unwrap_or_default(),
                    kind: "unknown".to_string(),
                    availability: "present".to_string(),
                    head_state: "unknown".to_string(),
                    status_state: "pending".to_string(),
                    working_state: "pending".to_string(),
                    analysis_pending: true,
                    ..TuiCheckout::default()
                };
                if let Some(store) = self.store_mut(&store_key) {
                    store.checkouts.push(checkout);
                    store.checkouts.sort_by(|a, b| a.path.cmp(&b.path));
                }
                self.header.discovered += 1;
            }
            EventType::InventoryReady => {
                self.header.phase = "analysis".to_string();
                if let Some(pending) = json_u64(&env.records, "pending") {
                    self.header.pending = pending;
                }
            }
            EventType::BranchBatch => {
                let store_id = json_str(&env.records, "store_id").unwrap_or_default();
                let store_key = format!("store:{store_id}");
                let branches = env
                    .records
                    .get("branches")
                    .and_then(|b| b.as_array())
                    .cloned()
                    .unwrap_or_default();
                for value in &branches {
                    let Some(branch_id) = json_str(value, "id") else {
                        continue;
                    };
                    let id = format!("branch:{branch_id}");
                    let record = TuiBranch {
                        id: id.clone(),
                        name: json_str(value, "name")
                            .map(|n| escape_display(&n))
                            .unwrap_or_else(|| branch_id.clone()),
                        kind: json_str(value, "kind").unwrap_or_else(|| "other".to_string()),
                        comparison: json_str(value, "comparison")
                            .unwrap_or_else(|| "pending".to_string()),
                        ahead: value.get("ahead").and_then(serde_json::Value::as_u64),
                        behind: value.get("behind").and_then(serde_json::Value::as_u64),
                        upstream: json_str(value, "upstream"),
                        oid: json_str(value, "oid"),
                        ..TuiBranch::default()
                    };
                    if !self.replace_branch(&id, &record) && !store_id.is_empty() {
                        // New branch: attach to its store (checkout
                        // scopes arrive with the final snapshot; the
                        // live view keeps them store-level).
                        if self.store_mut(&store_key).is_none() {
                            self.ensure_group(UNGROUPED_ID, None, None, None);
                            if let Some(group) = self.group_mut(UNGROUPED_ID) {
                                group.stores.push(TuiStore {
                                    id: store_key.clone(),
                                    path: "<discovering>".to_string(),
                                    match_disposition: "unknown".to_string(),
                                    ..TuiStore::default()
                                });
                            }
                        }
                        if let Some(store) = self.store_mut(&store_key) {
                            store.branches.push(record);
                        }
                    }
                }
                // Keep branch order canonical after each batch.
                for group in &mut self.groups {
                    for store in &mut group.stores {
                        store.branches.sort_by(|a, b| {
                            branch_kind_order(&a.kind)
                                .cmp(&branch_kind_order(&b.kind))
                                .then_with(|| a.name.cmp(&b.name))
                        });
                    }
                }
            }
            EventType::LocationUpdated => {
                let Some(checkout_id) = json_str(&env.records, "checkout_id") else {
                    return;
                };
                let id = format!("checkout:{checkout_id}");
                let Some(checkout) = self.checkout_mut(&id) else {
                    return;
                };
                let mut finished_one = false;
                if let Some(state) = json_str(&env.records, "status_state") {
                    checkout.status_state = state.clone();
                    // A finished status observation ends the pending
                    // marker; failures keep working_state honest.
                    if state == "complete" || state == "partial" {
                        checkout.analysis_pending = false;
                        if checkout.working_state == "pending" {
                            checkout.working_state = "unknown".to_string();
                        }
                        finished_one = true;
                    } else if state == "error" {
                        checkout.analysis_pending = false;
                        checkout.working_state = "error".to_string();
                    }
                }
                if let Some(working) = json_str(&env.records, "working_state") {
                    checkout.working_state = working;
                }
                for (key, slot) in [
                    ("staged", &mut checkout.staged),
                    ("unstaged", &mut checkout.unstaged),
                    ("untracked", &mut checkout.untracked),
                    ("conflicts", &mut checkout.conflicts),
                ] {
                    if let Some(n) = env.records.get(key).and_then(serde_json::Value::as_u64) {
                        *slot = Some(n);
                    }
                }
                if let Some(avail) = json_str(&env.records, "availability") {
                    checkout.availability = avail;
                }
                if let Some(head) = json_str(&env.records, "head_state") {
                    checkout.head_state = head;
                }
                if finished_one {
                    self.header.completed += 1;
                }
            }
            EventType::CoverageUpdated => {
                let opened = env
                    .records
                    .get("opened")
                    .and_then(|v| v.as_array())
                    .map(Vec::len)
                    .unwrap_or(0) as u64;
                let closed = env
                    .records
                    .get("closed")
                    .and_then(|v| v.as_array())
                    .map(Vec::len)
                    .unwrap_or(0) as u64;
                self.header.gaps = self
                    .header
                    .gaps
                    .saturating_add(opened)
                    .saturating_sub(closed);
            }
            EventType::Error => {
                self.header.gaps += 1;
            }
            EventType::RemoteUpdated => {
                self.header.phase = "fetch".to_string();
            }
            EventType::ScanCompleted => {
                self.header.scan_state = "complete".to_string();
                self.header.phase = "done".to_string();
                self.header.pending = 0;
            }
            EventType::ScanIncomplete => {
                self.header.scan_state = "incomplete".to_string();
                self.header.phase = "done".to_string();
            }
            EventType::ScanInterrupted => {
                self.header.scan_state = "interrupted".to_string();
                self.header.phase = "done".to_string();
            }
            EventType::ScanFailed => {
                self.header.scan_state = "failed".to_string();
                self.header.phase = "done".to_string();
            }
        }
    }

    /// Replace a branch row in place by stable id (re-delivery with
    /// the same id updates, never duplicates). True when replaced.
    fn replace_branch(&mut self, id: &str, record: &TuiBranch) -> bool {
        for group in &mut self.groups {
            for store in &mut group.stores {
                for slot in store.branches.iter_mut().chain(
                    store
                        .checkouts
                        .iter_mut()
                        .flat_map(|c| c.branches.iter_mut()),
                ) {
                    if slot.id == id {
                        *slot = record.clone();
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// First `github_groups` entry of a found-event payload as a group
/// key (`group:<host/account/repo>` + parts), or ungrouped when the
/// payload names none.
fn first_group_in(
    records: &serde_json::Value,
) -> (String, Option<String>, Option<String>, Option<String>) {
    let entry = records
        .get("github_groups")
        .and_then(|v| v.as_array())
        .and_then(|list| list.first())
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let mut parts = entry.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(host), Some(account), Some(repo))
            if !host.is_empty() && !account.is_empty() && !repo.is_empty() =>
        {
            (
                format!("group:{entry}"),
                Some(host.to_string()),
                Some(account.to_string()),
                Some(repo.to_string()),
            )
        }
        _ => (UNGROUPED_ID.to_string(), None, None, None),
    }
}

// ---------------------------------------------------------------------------
// Live catalog snapshot (scan loop refresh, bounded, main thread only)
// ---------------------------------------------------------------------------

/// Read committed catalog rows into a view snapshot: groups, group
/// edges, stores, checkouts, latest statuses, and refs — each query
/// bounded by its `LIVE_MAX_*` cap and ordered by id so the live
/// window is deterministic. Statuses resolve latest-per-checkout by
/// `observed_rev`; refs carry their comparison triple when the
/// catalog is v6 (older catalogs read `pending`/null). Header fields
/// stay blank for the caller (the scan loop owns elapsed/pending
/// from its in-memory counters, never from extra queries here).
pub async fn load_live_snapshot(store: &crate::store::TursoStore) -> crate::Result<TuiSnapshot> {
    let mut snapshot = TuiSnapshot::empty();
    let conn = store.connection();
    // Groups (bounded, id-ordered).
    let mut groups: HashMap<String, (String, String, String)> = HashMap::new();
    let mut rows = conn
        .query(
            "SELECT id, host, account, repo FROM github_groups ORDER BY id ASC LIMIT ?1",
            vec![turso::Value::Integer(LIVE_MAX_GROUPS)],
        )
        .await
        .map_err(|e| crate::Error::Store(e.to_string()))?;
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        let id = live_text(&row, 0)?;
        let host = live_text(&row, 1)?;
        let account = live_text(&row, 2)?;
        let repo = live_text(&row, 3)?;
        groups.insert(id.clone(), (host.clone(), account.clone(), repo.clone()));
        snapshot.ensure_group(
            &format!("group:{id}"),
            Some(host),
            Some(account),
            Some(repo),
        );
    }
    // Group edges (bounded): first group wins per store.
    let mut store_group: HashMap<String, String> = HashMap::new();
    let mut rows = conn
        .query(
            "SELECT group_id, instance_id FROM group_members ORDER BY group_id ASC LIMIT ?1",
            vec![turso::Value::Integer(LIVE_MAX_GROUP_EDGES)],
        )
        .await
        .map_err(|e| crate::Error::Store(e.to_string()))?;
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        let group_id = live_text(&row, 0)?;
        let instance_id = live_text(&row, 1)?;
        let key = format!("group:{group_id}");
        if groups.contains_key(&group_id) {
            store_group.entry(instance_id).or_insert(key);
        }
    }
    // Stores (bounded, id-ordered).
    let mut rows = conn
        .query(
            "SELECT id, git_path, common_path, bare, disposition FROM git_instances \
             ORDER BY id ASC LIMIT ?1",
            vec![turso::Value::Integer(LIVE_MAX_STORES)],
        )
        .await
        .map_err(|e| crate::Error::Store(e.to_string()))?;
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        let id = live_text(&row, 0)?;
        let git_path = escape_display(&String::from_utf8_lossy(&live_blob(&row, 1)?));
        let common_path = escape_display(&String::from_utf8_lossy(&live_blob(&row, 2)?));
        let bare = live_opt_int(&row, 3)?.map(|flag| flag != 0);
        let disposition = live_text(&row, 4)?;
        let group_key = store_group
            .get(&id)
            .cloned()
            .unwrap_or_else(|| UNGROUPED_ID.to_string());
        snapshot.ensure_group(&group_key, None, None, None);
        let store = TuiStore {
            id: format!("store:{id}"),
            path: common_path.clone(),
            git_path: (git_path != common_path).then_some(git_path),
            match_disposition: disposition,
            bare,
            ..TuiStore::default()
        };
        if let Some(group) = snapshot.group_mut(&group_key) {
            // `ensure_group` with `None` parts must not clobber a
            // grouped row created above (it only inserts when absent).
            group.stores.push(store);
        }
    }
    // Latest status per checkout (bounded): newest `observed_rev`
    // wins; v5 columns (`working_state`, `conflicts`) fall back to
    // unknown/null on older catalogs.
    // (status state, working state, staged, unstaged, untracked, conflicts).
    type LiveStatus = (
        String,
        String,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
    );
    let mut statuses: HashMap<String, LiveStatus> = HashMap::new();
    let status_sql_full =
        "SELECT checkout_id, state, working_state, staged, unstaged, untracked, conflicts \
         FROM status_observations ORDER BY checkout_id ASC, observed_rev DESC LIMIT ?1";
    let status_sql_legacy = "SELECT checkout_id, state, staged, unstaged, untracked \
         FROM status_observations ORDER BY checkout_id ASC, observed_rev DESC LIMIT ?1";
    let mut rows = match conn
        .query(
            status_sql_full,
            vec![turso::Value::Integer(LIVE_MAX_STATUSES)],
        )
        .await
    {
        Ok(rows) => (rows, true),
        Err(_) => (
            conn.query(
                status_sql_legacy,
                vec![turso::Value::Integer(LIVE_MAX_STATUSES)],
            )
            .await
            .map_err(|e| crate::Error::Store(e.to_string()))?,
            false,
        ),
    };
    while let Some(row) = rows
        .0
        .next()
        .await
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        let checkout_id = live_text(&row, 0)?;
        if statuses.contains_key(&checkout_id) {
            continue; // newest rev already kept (DESC order)
        }
        if rows.1 {
            statuses.insert(
                checkout_id,
                (
                    live_text(&row, 1)?,
                    live_text(&row, 2)?,
                    live_opt_int(&row, 3)?.and_then(|n| u64::try_from(n).ok()),
                    live_opt_int(&row, 4)?.and_then(|n| u64::try_from(n).ok()),
                    live_opt_int(&row, 5)?.and_then(|n| u64::try_from(n).ok()),
                    live_opt_int(&row, 6)?.and_then(|n| u64::try_from(n).ok()),
                ),
            );
        } else {
            statuses.insert(
                checkout_id,
                (
                    live_text(&row, 1)?,
                    "unknown".to_string(),
                    live_opt_int(&row, 2)?.and_then(|n| u64::try_from(n).ok()),
                    live_opt_int(&row, 3)?.and_then(|n| u64::try_from(n).ok()),
                    live_opt_int(&row, 4)?.and_then(|n| u64::try_from(n).ok()),
                    None,
                ),
            );
        }
    }
    // Checkouts (bounded, id-ordered).
    let mut rows = conn
        .query(
            "SELECT id, instance_id, root_path, git_path, relationship, availability, \
             head_state, head_ref FROM checkouts ORDER BY id ASC LIMIT ?1",
            vec![turso::Value::Integer(LIVE_MAX_CHECKOUTS)],
        )
        .await
        .map_err(|e| crate::Error::Store(e.to_string()))?;
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        let id = live_text(&row, 0)?;
        let instance_id = live_text(&row, 1)?;
        let root_path = live_opt_blob(&row, 2)?;
        let git_path = live_blob(&row, 3)?;
        let relationship = live_text(&row, 4)?;
        let availability = live_text(&row, 5)?;
        let head_state = live_text(&row, 6)?;
        let head_ref = live_opt_blob(&row, 7)?;
        let (status_state, working_state, staged, unstaged, untracked, conflicts) =
            statuses.remove(&id).unwrap_or_else(|| {
                (
                    "pending".to_string(),
                    "pending".to_string(),
                    None,
                    None,
                    None,
                    None,
                )
            });
        let analysis_pending = status_state == "pending" || working_state == "pending";
        let checkout = TuiCheckout {
            id: format!("checkout:{id}"),
            path: escape_display(&String::from_utf8_lossy(
                root_path.as_deref().unwrap_or(&git_path),
            )),
            git_path: escape_display(&String::from_utf8_lossy(&git_path)),
            kind: relationship,
            availability,
            head_state,
            head_ref: head_ref.map(|b| escape_display(&String::from_utf8_lossy(&b))),
            head_oid: None,
            status_state,
            working_state,
            staged,
            unstaged,
            untracked,
            conflicts,
            analysis_pending,
            error_ids: Vec::new(),
            branches: Vec::new(),
        };
        let store_key = format!("store:{instance_id}");
        if snapshot.store_mut(&store_key).is_none() {
            // Checkout whose store row is outside the live window (or
            // not yet committed): keep it visible under ungrouped.
            snapshot.ensure_group(UNGROUPED_ID, None, None, None);
            if let Some(group) = snapshot.group_mut(UNGROUPED_ID) {
                group.stores.push(TuiStore {
                    id: store_key.clone(),
                    path: "<discovering>".to_string(),
                    match_disposition: "unknown".to_string(),
                    ..TuiStore::default()
                });
            }
        }
        if let Some(store) = snapshot.store_mut(&store_key) {
            store.checkouts.push(checkout);
        }
    }
    // Refs (bounded): v6 comparison triple, legacy `pending`/null.
    let refs_sql_full = "SELECT id, instance_id, kind, name, comparison_state, ahead, behind \
         FROM refs ORDER BY id ASC LIMIT ?1";
    let refs_sql_legacy = "SELECT id, instance_id, kind, name FROM refs ORDER BY id ASC LIMIT ?1";
    let mut rows = match conn
        .query(refs_sql_full, vec![turso::Value::Integer(LIVE_MAX_REFS)])
        .await
    {
        Ok(rows) => (rows, true),
        Err(_) => (
            conn.query(refs_sql_legacy, vec![turso::Value::Integer(LIVE_MAX_REFS)])
                .await
                .map_err(|e| crate::Error::Store(e.to_string()))?,
            false,
        ),
    };
    while let Some(row) = rows
        .0
        .next()
        .await
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        let id = live_text(&row, 0)?;
        let instance_id = live_text(&row, 1)?;
        let kind = live_text(&row, 2)?;
        let name = escape_display(&String::from_utf8_lossy(&live_blob(&row, 3)?));
        let (comparison, ahead, behind) = if rows.1 {
            (
                live_opt_text(&row, 4)?.unwrap_or_else(|| "pending".to_string()),
                live_opt_int(&row, 5)?.and_then(|n| u64::try_from(n).ok()),
                live_opt_int(&row, 6)?.and_then(|n| u64::try_from(n).ok()),
            )
        } else {
            ("pending".to_string(), None, None)
        };
        let branch = TuiBranch {
            id: format!("branch:{id}"),
            name,
            kind,
            comparison,
            ahead,
            behind,
            ..TuiBranch::default()
        };
        let store_key = format!("store:{instance_id}");
        if let Some(store) = snapshot.store_mut(&store_key) {
            store.branches.push(branch);
        }
    }
    for group in &mut snapshot.groups {
        for store in &mut group.stores {
            store.checkouts.sort_by(|a, b| a.path.cmp(&b.path));
            store.branches.sort_by(|a, b| {
                branch_kind_order(&a.kind)
                    .cmp(&branch_kind_order(&b.kind))
                    .then_with(|| a.name.cmp(&b.name))
            });
        }
        group.stores.sort_by(|a, b| a.path.cmp(&b.path));
    }
    snapshot
        .groups
        .sort_by_key(|a| (a.id == UNGROUPED_ID, a.label()));
    Ok(snapshot)
}

/// Read a required TEXT column (live refresh helper).
fn live_text(row: &turso::Row, idx: usize) -> crate::Result<String> {
    match row
        .get_value(idx)
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        turso::Value::Text(value) => Ok(value),
        other => Err(crate::Error::Store(format!(
            "tui refresh: column {idx} expected TEXT, got {other:?}"
        ))),
    }
}

/// Read an optional TEXT column (live refresh helper).
fn live_opt_text(row: &turso::Row, idx: usize) -> crate::Result<Option<String>> {
    match row
        .get_value(idx)
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        turso::Value::Null => Ok(None),
        turso::Value::Text(value) => Ok(Some(value)),
        other => Err(crate::Error::Store(format!(
            "tui refresh: column {idx} expected TEXT or NULL, got {other:?}"
        ))),
    }
}

/// Read a required BLOB column (live refresh helper).
fn live_blob(row: &turso::Row, idx: usize) -> crate::Result<Vec<u8>> {
    match row
        .get_value(idx)
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        turso::Value::Blob(value) => Ok(value),
        other => Err(crate::Error::Store(format!(
            "tui refresh: column {idx} expected BLOB, got {other:?}"
        ))),
    }
}

/// Read an optional BLOB column (live refresh helper).
fn live_opt_blob(row: &turso::Row, idx: usize) -> crate::Result<Option<Vec<u8>>> {
    match row
        .get_value(idx)
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        turso::Value::Null => Ok(None),
        turso::Value::Blob(value) => Ok(Some(value)),
        other => Err(crate::Error::Store(format!(
            "tui refresh: column {idx} expected BLOB or NULL, got {other:?}"
        ))),
    }
}

/// Read an optional INTEGER column (live refresh helper).
fn live_opt_int(row: &turso::Row, idx: usize) -> crate::Result<Option<i64>> {
    match row
        .get_value(idx)
        .map_err(|e| crate::Error::Store(e.to_string()))?
    {
        turso::Value::Null => Ok(None),
        turso::Value::Integer(value) => Ok(Some(value)),
        other => Err(crate::Error::Store(format!(
            "tui refresh: column {idx} expected INTEGER or NULL, got {other:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// View state (selection, expansion, filter, sort, search, overlays)
// ---------------------------------------------------------------------------

/// Row filter cycled by `f` (pinned order): dirty, conflicted, ahead,
/// behind, diverged, pending, failed, off. Matching leaves render
/// with their ancestors for context; ancestors that match nothing
/// hide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Filter {
    /// Show every row.
    #[default]
    Off,
    /// Checkouts with uncommitted changes (`working_state == dirty`).
    Dirty,
    /// Checkouts with unmerged paths (`conflicted` or conflicts > 0).
    Conflicted,
    /// Branches ahead of (or diverged from) their upstream.
    Ahead,
    /// Branches behind (or diverged from) their upstream.
    Behind,
    /// Branches diverged from their upstream.
    Diverged,
    /// Rows still awaiting analysis.
    Pending,
    /// Rows carrying error state or attached error records.
    Failed,
}

impl Filter {
    /// Pinned `f` cycle order.
    pub const CYCLE: [Filter; 8] = [
        Filter::Dirty,
        Filter::Conflicted,
        Filter::Ahead,
        Filter::Behind,
        Filter::Diverged,
        Filter::Pending,
        Filter::Failed,
        Filter::Off,
    ];

    /// Next filter in the pinned cycle.
    pub fn next(self) -> Filter {
        match self {
            Filter::Off => Filter::Dirty,
            Filter::Dirty => Filter::Conflicted,
            Filter::Conflicted => Filter::Ahead,
            Filter::Ahead => Filter::Behind,
            Filter::Behind => Filter::Diverged,
            Filter::Diverged => Filter::Pending,
            Filter::Pending => Filter::Failed,
            Filter::Failed => Filter::Off,
        }
    }

    /// Short label rendered in the footer.
    pub fn label(self) -> &'static str {
        match self {
            Filter::Off => "off",
            Filter::Dirty => "dirty",
            Filter::Conflicted => "conflicted",
            Filter::Ahead => "ahead",
            Filter::Behind => "behind",
            Filter::Diverged => "diverged",
            Filter::Pending => "pending",
            Filter::Failed => "failed",
        }
    }
}

/// Sibling sort cycled by `s` (pinned order): group, path, state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    /// Canonical hierarchy: account, repo, store path, checkout
    /// path, branch kind then name.
    #[default]
    Group,
    /// Siblings ordered by path/name text.
    Path,
    /// Problems first (failed, conflicted, dirty, diverged,
    /// ahead/behind, pending, clean, rest), ties by label.
    State,
}

impl Sort {
    /// Next sort in the pinned cycle.
    pub fn next(self) -> Sort {
        match self {
            Sort::Group => Sort::Path,
            Sort::Path => Sort::State,
            Sort::State => Sort::Group,
        }
    }

    /// Short label rendered in the footer.
    pub fn label(self) -> &'static str {
        match self {
            Sort::Group => "group",
            Sort::Path => "path",
            Sort::State => "state",
        }
    }
}

/// Overlay open above the row table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Overlay {
    /// No overlay: the row table owns the screen.
    #[default]
    None,
    /// Detail view for one record id (full paths + explanations).
    Detail(String),
    /// Pinned key help.
    Help,
}

/// One input key (parsed from terminal bytes by [`parse_key`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Up arrow or `k`.
    Up,
    /// Down arrow or `j`.
    Down,
    /// Left arrow (collapse / move to parent).
    Left,
    /// Right arrow (expand).
    Right,
    /// Enter (`CR` or `LF`).
    Enter,
    /// Space.
    Space,
    /// `/` (search).
    Slash,
    /// Printable character (search input, `f`/`s`/`v`/`h`/`?`/`q`/`j`/`k`).
    Char(char),
    /// Escape (close overlay / stop search, or quit).
    Esc,
    /// Backspace (search editing).
    Backspace,
    /// Ctrl-C (interrupt: the scan saves and exits 130; follow exits 130).
    Interrupt,
}

/// Parse the first key from `buf`, returning the key plus bytes
/// consumed. Returns `None` when `buf` is empty or holds an
/// incomplete escape sequence (the caller reads more bytes).
pub fn parse_key(buf: &[u8]) -> Option<(Key, usize)> {
    let first = *buf.first()?;
    match first {
        0x03 => Some((Key::Interrupt, 1)),
        0x0d | 0x0a => Some((Key::Enter, 1)),
        0x1b => {
            if buf.len() == 1 {
                return Some((Key::Esc, 1));
            }
            let second = buf[1];
            if second == b'[' || second == b'O' {
                if buf.len() < 3 {
                    return None; // incomplete sequence: read more
                }
                let key = match buf[2] {
                    b'A' => Key::Up,
                    b'B' => Key::Down,
                    b'C' => Key::Right,
                    b'D' => Key::Left,
                    _ => Key::Esc,
                };
                return Some((key, 3));
            }
            Some((Key::Esc, 1))
        }
        0x7f | 0x08 => Some((Key::Backspace, 1)),
        0x20 => Some((Key::Space, 1)),
        b'/' => Some((Key::Slash, 1)),
        0x00..=0x1f => None, // other controls: no binding
        _ => {
            let text = std::str::from_utf8(buf).ok()?;
            let c = text.chars().next()?;
            Some((Key::Char(c), c.len_utf8()))
        }
    }
}

/// What [`apply_key`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyAction {
    /// State changed (or nothing was bound): redraw.
    #[default]
    Redraw,
    /// Quit the view (scan/catalog untouched).
    Quit,
    /// Interrupt (Ctrl-C): restore the terminal and unwind.
    Interrupt,
}

/// One flattened visible row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Stable record id (selection + scroll anchor).
    pub id: String,
    /// Tree depth (group 0, store 1, checkout 2, branch 3).
    pub depth: usize,
    /// Row kind label (`group`, `store`, `checkout`, `branch`).
    pub kind: &'static str,
    /// Main label (already escaped, untruncated).
    pub label: String,
    /// State label (already escaped, untruncated).
    pub state: String,
    /// True for groups, stores, and checkouts carrying branches.
    pub expandable: bool,
    /// True when an expandable row is currently expanded.
    pub expanded: bool,
}

/// Full interactive state: the current snapshot plus selection,
/// expansion, filter, sort, search, overlay, and scroll position.
/// Selection and scroll anchor to stable record ids, so live updates
/// never reset either.
#[derive(Debug, Clone)]
pub struct ViewState {
    /// Current snapshot (replaced wholesale on each update).
    pub snapshot: TuiSnapshot,
    /// Expanded record ids (groups/stores start expanded).
    pub expanded: HashSet<String>,
    /// Selected record id (stable across updates).
    pub selected: Option<String>,
    /// First visible row index.
    pub scroll_top: usize,
    /// Row filter (`f` cycles).
    pub filter: Filter,
    /// Sibling sort (`s` cycles).
    pub sort: Sort,
    /// Active search query (case-insensitive substring over
    /// account, repo, path, branch).
    pub search: String,
    /// True while the user is typing a query.
    pub searching: bool,
    /// Open overlay, if any.
    pub overlay: Overlay,
}

impl ViewState {
    /// New state over `snapshot`: groups and stores expanded,
    /// selection on the first row, no filter/sort/search/overlay.
    pub fn new(snapshot: TuiSnapshot) -> Self {
        let mut expanded = HashSet::new();
        for group in &snapshot.groups {
            expanded.insert(group.id.clone());
            for store in &group.stores {
                expanded.insert(store.id.clone());
            }
        }
        let mut state = Self {
            snapshot,
            expanded,
            selected: None,
            scroll_top: 0,
            filter: Filter::Off,
            sort: Sort::Group,
            search: String::new(),
            searching: false,
            overlay: Overlay::None,
        };
        let rows = state.visible_rows();
        state.selected = rows.first().map(|r| r.id.clone());
        state
    }

    /// Replace the snapshot, preserving selection and scroll by
    /// stable record id: the selected id stays selected when it is
    /// still visible (otherwise the nearest visible row takes over),
    /// and the scroll anchor (the id at `scroll_top`) stays at the
    /// top when it is still visible.
    pub fn apply_snapshot(&mut self, snapshot: TuiSnapshot) {
        let anchor = self
            .visible_rows()
            .get(self.scroll_top)
            .map(|r| r.id.clone());
        self.snapshot = snapshot;
        // New groups/stores default to expanded; checkouts expand on
        // demand. Removal of stale ids keeps the set bounded.
        let mut live = HashSet::new();
        for group in &self.snapshot.groups {
            live.insert(group.id.clone());
            self.expanded.insert(group.id.clone());
            for store in &group.stores {
                live.insert(store.id.clone());
                self.expanded.insert(store.id.clone());
                for checkout in &store.checkouts {
                    live.insert(checkout.id.clone());
                    for branch in checkout.branches.iter().chain(store.branches.iter()) {
                        live.insert(branch.id.clone());
                    }
                }
            }
        }
        self.expanded.retain(|id| live.contains(id));
        let rows = self.visible_rows();
        if rows.is_empty() {
            self.selected = None;
            self.scroll_top = 0;
            return;
        }
        if self
            .selected
            .as_ref()
            .is_some_and(|id| rows.iter().any(|r| &r.id == id))
        {
            // Selection survives: keep it.
        } else if let Some(selected) = self.selected.clone() {
            // Nearest visible row to the vanished id keeps the cursor
            // stable instead of jumping to the top.
            self.selected = Some(nearest_row_id(&rows, &selected));
        } else {
            self.selected = rows.first().map(|r| r.id.clone());
        }
        // Scroll anchor first, then make sure the selection is visible.
        if let Some(anchor) = anchor {
            if let Some(pos) = rows.iter().position(|r| r.id == anchor) {
                self.scroll_top = pos;
            } else {
                self.scroll_top = self.scroll_top.min(rows.len().saturating_sub(1));
            }
        }
        self.ensure_selected_visible(usize::MAX);
    }

    /// Keep `scroll_top` so the selected row is inside a `height`-row
    /// window (`usize::MAX` preserves position without windowing).
    pub fn ensure_selected_visible(&mut self, height: usize) {
        let rows = self.visible_rows();
        let Some(selected) = self.selected.clone() else {
            return;
        };
        let Some(pos) = rows.iter().position(|r| r.id == selected) else {
            return;
        };
        if height == usize::MAX {
            return; // no window: anchor already placed scroll_top
        }
        if pos < self.scroll_top {
            self.scroll_top = pos;
        } else if pos >= self.scroll_top + height {
            self.scroll_top = pos + 1 - height.min(1.max(rows.len()));
        }
    }

    /// Flatten the snapshot into visible rows under the current
    /// expansion, filter, search, and sort.
    pub fn visible_rows(&self) -> Vec<Row> {
        let query = self.search.to_lowercase();
        let mut groups: Vec<&TuiGroup> = self.snapshot.groups.iter().collect();
        sort_groups(&mut groups, self.sort);
        let mut rows = Vec::new();
        for group in groups {
            let mut stores: Vec<&TuiStore> = group.stores.iter().collect();
            sort_stores(&mut stores, self.sort);
            // Filter/search prune bottom-up; ancestors render only
            // when they keep at least one visible descendant.
            let mut store_rows: Vec<Vec<Row>> = Vec::new();
            for store in stores {
                if let Some(block) = self.store_block(group, store, &query) {
                    store_rows.push(block);
                }
            }
            if store_rows.is_empty() {
                continue;
            }
            let expanded = self.expanded.contains(&group.id);
            rows.push(Row {
                id: group.id.clone(),
                depth: 0,
                kind: "group",
                label: group.label(),
                state: group_state_label(group),
                expandable: true,
                expanded,
            });
            if expanded {
                for block in store_rows {
                    rows.extend(block);
                }
            }
        }
        rows
    }

    /// Visible rows for one store (its row plus expanded children),
    /// or `None` when the filter/search hides the whole subtree.
    fn store_block(&self, group: &TuiGroup, store: &TuiStore, query: &str) -> Option<Vec<Row>> {
        let mut checkouts: Vec<&TuiCheckout> = store.checkouts.iter().collect();
        sort_checkouts(&mut checkouts, self.sort);
        let mut branches: Vec<&TuiBranch> = store.branches.iter().collect();
        sort_branches(&mut branches, self.sort);
        let mut children: Vec<Row> = Vec::new();
        for checkout in checkouts {
            let mut checkout_branches: Vec<&TuiBranch> = checkout.branches.iter().collect();
            sort_branches(&mut checkout_branches, self.sort);
            let kept_branches: Vec<&&TuiBranch> = checkout_branches
                .iter()
                .filter(|b| {
                    branch_visible(b, self.filter)
                        && branch_matches_query(group, store, checkout, b, query)
                })
                .collect();
            let checkout_self = checkout_self_visible(checkout, self.filter)
                && checkout_matches_query(group, store, checkout, query);
            if !checkout_self && kept_branches.is_empty() {
                continue;
            }
            let expanded = self.expanded.contains(&checkout.id);
            children.push(Row {
                id: checkout.id.clone(),
                depth: 2,
                kind: "checkout",
                label: checkout.path.clone(),
                state: checkout_state_label(checkout),
                expandable: !checkout.branches.is_empty(),
                expanded,
            });
            if expanded {
                for branch in kept_branches {
                    children.push(Row {
                        id: branch.id.clone(),
                        depth: 3,
                        kind: "branch",
                        label: branch.name.clone(),
                        state: branch_state_label(branch),
                        expandable: false,
                        expanded: false,
                    });
                }
            }
        }
        for branch in branches {
            if !branch_visible(branch, self.filter)
                || !branch_matches_query(group, store, store_checkout_none(), branch, query)
            {
                continue;
            }
            children.push(Row {
                id: branch.id.clone(),
                depth: 2,
                kind: "branch",
                label: branch.name.clone(),
                state: branch_state_label(branch),
                expandable: false,
                expanded: false,
            });
        }
        let store_self =
            store_self_visible(store, self.filter) && store_matches_query(group, store, query);
        if !store_self && children.is_empty() {
            return None;
        }
        let expanded = self.expanded.contains(&store.id);
        let mut block = vec![Row {
            id: store.id.clone(),
            depth: 1,
            kind: "store",
            label: store.path.clone(),
            state: store_state_label(store),
            expandable: true,
            expanded,
        }];
        if expanded {
            block.extend(children);
        } else if !children.is_empty() {
            // Collapsed stores still count as visible (their subtree
            // exists under the filter); children simply do not render.
        }
        Some(block)
    }

    /// Move selection by `delta` visible rows (clamped, never wraps).
    pub fn move_selection(&mut self, delta: isize) {
        let rows = self.visible_rows();
        if rows.is_empty() {
            self.selected = None;
            return;
        }
        let current = self
            .selected
            .as_ref()
            .and_then(|id| rows.iter().position(|r| &r.id == id))
            .unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, rows.len() as isize - 1) as usize;
        self.selected = Some(rows[next].id.clone());
    }

    /// Toggle expansion of the selected row. True when the row was
    /// expandable.
    pub fn toggle_selected(&mut self) -> bool {
        let rows = self.visible_rows();
        let Some(selected) = self.selected.clone() else {
            return false;
        };
        let Some(row) = rows.iter().find(|r| r.id == selected) else {
            return false;
        };
        if !row.expandable {
            return false;
        }
        if self.expanded.contains(&row.id) {
            self.expanded.remove(&row.id);
        } else {
            self.expanded.insert(row.id.clone());
        }
        true
    }

    /// Collapse the selected row, or move to its parent when already
    /// collapsed (left-arrow behavior).
    pub fn collapse_or_parent(&mut self) {
        let rows = self.visible_rows();
        let Some(selected) = self.selected.clone() else {
            return;
        };
        let Some(pos) = rows.iter().position(|r| r.id == selected) else {
            return;
        };
        let row = &rows[pos];
        if row.expandable && self.expanded.contains(&row.id) {
            self.expanded.remove(&row.id);
            return;
        }
        // Move to the nearest visible ancestor (lower depth above).
        for candidate in rows[..pos].iter().rev() {
            if candidate.depth < row.depth {
                self.selected = Some(candidate.id.clone());
                return;
            }
        }
    }

    /// Expand the selected row (right-arrow behavior).
    pub fn expand_selected(&mut self) {
        let rows = self.visible_rows();
        if let Some(selected) = self.selected.clone() {
            if rows.iter().any(|r| r.id == selected && r.expandable) {
                self.expanded.insert(selected);
            }
        }
    }
}

/// Placeholder checkout for store-level branch search matching (the
/// branch carries its own searchable text; no checkout constrains it).
fn store_checkout_none() -> &'static TuiCheckout {
    static NONE: std::sync::OnceLock<TuiCheckout> = std::sync::OnceLock::new();
    NONE.get_or_init(TuiCheckout::default)
}

/// Nearest visible row id to a vanished selection (numeric-suffix
/// aware so `checkout:co-12` lands near `co-11`, not row zero).
fn nearest_row_id(rows: &[Row], missing: &str) -> String {
    let (prefix, number) = split_trailing_number(missing);
    let mut best: Option<(u64, &Row)> = None;
    for row in rows {
        let (row_prefix, row_number) = split_trailing_number(&row.id);
        let distance = match (number, row_number) {
            (Some(a), Some(b)) if prefix == row_prefix => a.abs_diff(b),
            _ => u64::MAX / 2,
        };
        let closer = best.map(|(d, _)| distance < d).unwrap_or(true);
        if closer {
            best = Some((distance, row));
        }
    }
    best.map(|(_, row)| row.id.clone())
        .unwrap_or_else(|| rows.first().map(|r| r.id.clone()).unwrap_or_default())
}

/// Split `checkout:co-12` into (`checkout:co-`, `Some(12)`).
fn split_trailing_number(id: &str) -> (&str, Option<u64>) {
    let digits = id.bytes().rev().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return (id, None);
    }
    let (prefix, number) = id.split_at(id.len() - digits);
    (prefix, number.parse().ok())
}

/// Apply one key to the view state. Overlay keys first (`q` quits
/// from anywhere; esc steps back), then search editing, then browse
/// keys per the pinned table.
pub fn apply_key(state: &mut ViewState, key: Key) -> KeyAction {
    match &state.overlay {
        Overlay::Help => {
            return match key {
                Key::Interrupt => KeyAction::Interrupt,
                Key::Char('q' | 'Q') => KeyAction::Quit,
                _ => {
                    state.overlay = Overlay::None;
                    KeyAction::Redraw
                }
            };
        }
        Overlay::Detail(_) => {
            return match key {
                Key::Interrupt => KeyAction::Interrupt,
                Key::Char('q' | 'Q') => KeyAction::Quit,
                Key::Esc => {
                    state.overlay = Overlay::None;
                    KeyAction::Redraw
                }
                Key::Up | Key::Down => KeyAction::Redraw, // reserved: detail scroll
                _ => KeyAction::Redraw,
            };
        }
        Overlay::None => {}
    }
    if state.searching {
        return match key {
            Key::Interrupt => KeyAction::Interrupt,
            Key::Esc => {
                state.search.clear();
                state.searching = false;
                KeyAction::Redraw
            }
            Key::Enter => {
                state.searching = false;
                KeyAction::Redraw
            }
            Key::Backspace => {
                state.search.pop();
                KeyAction::Redraw
            }
            Key::Char(c) => {
                state.search.push(c);
                KeyAction::Redraw
            }
            Key::Space => {
                state.search.push(' ');
                KeyAction::Redraw
            }
            _ => KeyAction::Redraw,
        };
    }
    match key {
        Key::Interrupt => KeyAction::Interrupt,
        Key::Up | Key::Char('k' | 'K') => {
            state.move_selection(-1);
            KeyAction::Redraw
        }
        Key::Down | Key::Char('j' | 'J') => {
            state.move_selection(1);
            KeyAction::Redraw
        }
        Key::Left => {
            state.collapse_or_parent();
            KeyAction::Redraw
        }
        Key::Right => {
            state.expand_selected();
            KeyAction::Redraw
        }
        Key::Enter | Key::Space => {
            if !state.toggle_selected() {
                // Leaf row: enter/space opens detail.
                if let Some(selected) = state.selected.clone() {
                    state.overlay = Overlay::Detail(selected);
                }
            }
            KeyAction::Redraw
        }
        Key::Slash => {
            state.searching = true;
            KeyAction::Redraw
        }
        Key::Char('f' | 'F') => {
            state.filter = state.filter.next();
            KeyAction::Redraw
        }
        Key::Char('s' | 'S') => {
            state.sort = state.sort.next();
            KeyAction::Redraw
        }
        Key::Char('v' | 'V') => {
            if let Some(selected) = state.selected.clone() {
                state.overlay = Overlay::Detail(selected);
            }
            KeyAction::Redraw
        }
        Key::Char('h' | 'H' | '?') => {
            state.overlay = Overlay::Help;
            KeyAction::Redraw
        }
        Key::Char('q' | 'Q') | Key::Esc => KeyAction::Quit,
        Key::Char(_) | Key::Backspace => KeyAction::Redraw,
    }
}

// ---------------------------------------------------------------------------
// Filter, search, sort, and row labels
// ---------------------------------------------------------------------------

/// True when a checkout matches the filter on its own states (branch
/// filters match via descendants at the block level).
fn checkout_self_visible(checkout: &TuiCheckout, filter: Filter) -> bool {
    match filter {
        Filter::Off => true,
        Filter::Dirty => checkout.working_state == "dirty",
        Filter::Conflicted => {
            checkout.working_state == "conflicted" || checkout.conflicts.unwrap_or(0) > 0
        }
        Filter::Ahead => checkout
            .branches
            .iter()
            .any(|b| matches!(b.comparison.as_str(), "ahead" | "diverged")),
        Filter::Behind => checkout
            .branches
            .iter()
            .any(|b| matches!(b.comparison.as_str(), "behind" | "diverged")),
        Filter::Diverged => checkout.branches.iter().any(|b| b.comparison == "diverged"),
        Filter::Pending => checkout_pending(checkout),
        Filter::Failed => checkout_failed(checkout),
    }
}

/// True when a branch matches the filter on its own comparison.
fn branch_visible(branch: &TuiBranch, filter: Filter) -> bool {
    match filter {
        Filter::Off => true,
        Filter::Dirty | Filter::Conflicted => false, // working-state filters hide branch leaves
        Filter::Ahead => matches!(branch.comparison.as_str(), "ahead" | "diverged"),
        Filter::Behind => matches!(branch.comparison.as_str(), "behind" | "diverged"),
        Filter::Diverged => branch.comparison == "diverged",
        Filter::Pending => branch_pending(branch),
        Filter::Failed => branch_failed(branch),
    }
}

/// True when a store matches the filter on its own errors (rows with
/// matching descendants render regardless).
fn store_self_visible(store: &TuiStore, filter: Filter) -> bool {
    match filter {
        Filter::Off => true,
        Filter::Failed => store_failed(store),
        Filter::Pending => {
            store.checkouts.iter().any(checkout_pending)
                || store.branches.iter().any(branch_pending)
        }
        Filter::Dirty | Filter::Conflicted | Filter::Ahead | Filter::Behind | Filter::Diverged => {
            false
        } // descendant filters only
    }
}

/// True when the checkout or its group/store context matches the
/// search query (empty query matches everything).
fn checkout_matches_query(
    group: &TuiGroup,
    store: &TuiStore,
    checkout: &TuiCheckout,
    query: &str,
) -> bool {
    if query.is_empty() {
        return true;
    }
    group.label().to_lowercase().contains(query)
        || store.path.to_lowercase().contains(query)
        || checkout.path.to_lowercase().contains(query)
        || checkout.git_path.to_lowercase().contains(query)
}

/// True when the branch or its group/store/checkout context matches.
fn branch_matches_query(
    group: &TuiGroup,
    store: &TuiStore,
    checkout: &TuiCheckout,
    branch: &TuiBranch,
    query: &str,
) -> bool {
    if query.is_empty() {
        return true;
    }
    branch.name.to_lowercase().contains(query)
        || group.label().to_lowercase().contains(query)
        || store.path.to_lowercase().contains(query)
        || checkout.path.to_lowercase().contains(query)
}

/// True when the store or its group context matches.
fn store_matches_query(group: &TuiGroup, store: &TuiStore, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    group.label().to_lowercase().contains(query) || store.path.to_lowercase().contains(query)
}

/// Sort groups in place (ungrouped always last).
fn sort_groups(groups: &mut Vec<&TuiGroup>, sort: Sort) {
    match sort {
        Sort::Group | Sort::Path => {
            groups.sort_by_key(|a| (a.id == UNGROUPED_ID, a.label()));
        }
        Sort::State => {
            groups.sort_by_key(|g| group_severity(g));
        }
    }
}

/// Sort stores in place.
fn sort_stores(stores: &mut Vec<&TuiStore>, sort: Sort) {
    match sort {
        Sort::Group | Sort::Path => stores.sort_by(|a, b| a.path.cmp(&b.path)),
        Sort::State => stores.sort_by(|a, b| {
            store_severity(a)
                .cmp(&store_severity(b))
                .then_with(|| a.path.cmp(&b.path))
        }),
    }
}

/// Sort checkouts in place.
fn sort_checkouts(checkouts: &mut Vec<&TuiCheckout>, sort: Sort) {
    match sort {
        Sort::Group | Sort::Path => checkouts.sort_by(|a, b| a.path.cmp(&b.path)),
        Sort::State => checkouts.sort_by(|a, b| {
            checkout_severity(a)
                .cmp(&checkout_severity(b))
                .then_with(|| a.path.cmp(&b.path))
        }),
    }
}

/// Sort branches in place.
fn sort_branches(branches: &mut Vec<&TuiBranch>, sort: Sort) {
    match sort {
        Sort::Group => branches.sort_by(|a, b| {
            branch_kind_order(&a.kind)
                .cmp(&branch_kind_order(&b.kind))
                .then_with(|| a.name.cmp(&b.name))
        }),
        Sort::Path => branches.sort_by(|a, b| a.name.cmp(&b.name)),
        Sort::State => branches.sort_by(|a, b| {
            branch_severity(a)
                .cmp(&branch_severity(b))
                .then_with(|| a.name.cmp(&b.name))
        }),
    }
}

/// Worst descendant severity (state sort for groups/stores).
fn group_severity(group: &TuiGroup) -> u8 {
    group.stores.iter().map(store_severity).min().unwrap_or(7)
}

/// Worst descendant severity for one store.
fn store_severity(store: &TuiStore) -> u8 {
    let checkout = store.checkouts.iter().map(checkout_severity).min();
    let branch = store.branches.iter().map(branch_severity).min();
    match (checkout, branch) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) if store_failed(store) => 0,
        (None, None) => 7,
    }
}

/// Aggregate state label for a group row.
fn group_state_label(group: &TuiGroup) -> String {
    let stores = group.stores.len();
    let checkouts: usize = group.stores.iter().map(|s| s.checkouts.len()).sum();
    format!("stores={stores} checkouts={checkouts}")
}

/// Aggregate state label for a store row.
fn store_state_label(store: &TuiStore) -> String {
    let mut parts = vec![format!("match={}", store.match_disposition)];
    if store.bare == Some(true) {
        parts.push("bare".to_string());
    }
    if store_failed(store) {
        parts.push("failed".to_string());
    }
    parts.join(" ")
}

/// State label for a checkout row (text labels always render;
/// color only emphasizes).
fn checkout_state_label(checkout: &TuiCheckout) -> String {
    let mut parts = Vec::new();
    if checkout.analysis_pending
        || checkout.status_state == "pending"
        || checkout.working_state == "pending"
    {
        parts.push("pending".to_string());
    }
    match checkout.working_state.as_str() {
        "clean" => parts.push("clean".to_string()),
        "dirty" => parts.push("dirty".to_string()),
        "conflicted" => parts.push("conflicted".to_string()),
        "error" => parts.push("error".to_string()),
        "unknown" => parts.push("unknown".to_string()),
        other => parts.push(other.to_string()),
    }
    if checkout_failed(checkout) && !parts.iter().any(|p| p == "error") {
        parts.push("failed".to_string());
    }
    if checkout.availability != "present" {
        parts.push(checkout.availability.clone());
    }
    if parts.is_empty() {
        parts.push("unknown".to_string());
    }
    parts.join(" ")
}

/// State label for a branch row.
fn branch_state_label(branch: &TuiBranch) -> String {
    let mut label = branch.comparison.clone();
    match (branch.ahead, branch.behind) {
        (Some(a), Some(b)) => label.push_str(&format!(" +{a}/-{b}")),
        (Some(a), None) => label.push_str(&format!(" +{a}")),
        (None, Some(b)) => label.push_str(&format!(" -{b}")),
        (None, None) => {}
    }
    label
}

// ---------------------------------------------------------------------------
// State explanations (detail view)
// ---------------------------------------------------------------------------

/// One-line explanation of a working state.
pub fn explain_working_state(state: &str) -> &'static str {
    match state {
        "clean" => "no local modifications observed",
        "dirty" => "uncommitted changes present (staged, unstaged, or untracked)",
        "conflicted" => "unmerged paths need resolution before committing",
        "pending" => "analysis has not finished this checkout yet",
        "partial" => "only part of the working tree was observed",
        "unstable" => "the tree changed during observation; counts may be mixed",
        "unknown" => "never observed as clean; state not proven",
        "error" => "status observation failed; see error records",
        "not_applicable" => "working state does not apply (bare store or metadata-only)",
        _ => "unrecognized state value",
    }
}

/// One-line explanation of a branch comparison state.
pub fn explain_comparison(state: &str) -> &'static str {
    match state {
        "equal" => "branch tip matches its upstream",
        "ahead" => "branch has commits its upstream lacks",
        "behind" => "upstream has commits this branch lacks",
        "diverged" => "both sides have commits the other lacks",
        "no_upstream" => "no upstream configured; nothing to compare against",
        "upstream_missing" => "the configured upstream ref does not exist locally",
        "pending" => "comparison has not run yet",
        "incomplete_history" => "shallow or grafted history; the walk cannot complete",
        "error" => "comparison failed; see error records",
        _ => "unrecognized comparison value",
    }
}

/// One-line explanation of a HEAD state.
pub fn explain_head_state(state: &str) -> &'static str {
    match state {
        "branch" => "HEAD points at a local branch",
        "detached" => "HEAD points directly at a commit (detached)",
        "unborn" => "HEAD names a branch with no commits yet",
        "invalid" => "HEAD is unreadable or corrupt",
        "unknown" => "HEAD was not observed",
        _ => "unrecognized HEAD value",
    }
}

/// One-line explanation of a checkout availability.
pub fn explain_availability(state: &str) -> &'static str {
    match state {
        "present" => "checkout is on disk and readable",
        "missing" => "checkout path no longer exists",
        "inaccessible" => "checkout exists but cannot be read (permissions or lock)",
        "broken" => "checkout metadata is inconsistent",
        "unknown" => "availability was not observed",
        _ => "unrecognized availability value",
    }
}

/// One-line explanation of a status observation state.
pub fn explain_status_state(state: &str) -> &'static str {
    match state {
        "complete" => "status observation finished",
        "partial" => "status observation covered part of the tree",
        "pending" => "status observation has not run yet",
        "not_requested" => "status was not requested for this scan",
        "unsupported" => "status is unsupported for this checkout shape",
        "unstable" => "status raced concurrent modification",
        "error" => "status observation failed",
        _ => "unrecognized status value",
    }
}

/// Detail overlay lines for one record id (full paths, never
/// truncated to an ellipsis except by the overlay width wrap).
pub fn detail_lines(snapshot: &TuiSnapshot, id: &str) -> Vec<String> {
    for group in &snapshot.groups {
        if group.id == id {
            return group_detail(group);
        }
        for store in &group.stores {
            if store.id == id {
                return store_detail(group, store);
            }
            for branch in &store.branches {
                if branch.id == id {
                    return branch_detail(group, store, None, branch);
                }
            }
            for checkout in &store.checkouts {
                if checkout.id == id {
                    return checkout_detail(group, store, checkout);
                }
                for branch in &checkout.branches {
                    if branch.id == id {
                        return branch_detail(group, store, Some(checkout), branch);
                    }
                }
            }
        }
    }
    vec![format!("no such record: {}", escape_display(id))]
}

fn group_detail(group: &TuiGroup) -> Vec<String> {
    let mut lines = vec![
        format!("group {}", group.label()),
        format!("id: {}", group.id),
    ];
    if let (Some(host), Some(account), Some(repo)) = (&group.host, &group.account, &group.repo) {
        lines.push(format!("host: {host} account: {account} repo: {repo}"));
    } else {
        lines.push("stores without a parsed account/repo association".to_string());
    }
    let checkouts: usize = group.stores.iter().map(|s| s.checkouts.len()).sum();
    let branches: usize = group
        .stores
        .iter()
        .map(|s| s.branches.len() + s.checkouts.iter().map(|c| c.branches.len()).sum::<usize>())
        .sum();
    lines.push(format!(
        "stores: {} checkouts: {checkouts} branches: {branches}",
        group.stores.len()
    ));
    lines
}

fn store_detail(group: &TuiGroup, store: &TuiStore) -> Vec<String> {
    let mut lines = vec![
        "store".to_string(),
        format!("id: {}", store.id),
        format!("group: {}", group.label()),
        format!("common dir: {}", store.path),
    ];
    if let Some(git) = &store.git_path {
        lines.push(format!("git dir: {git}"));
    }
    lines.push(format!("match: {}", store.match_disposition));
    if let Some(bare) = store.bare {
        lines.push(format!("bare: {bare}"));
    }
    lines.push(format!(
        "checkouts: {} branches: {}",
        store.checkouts.len(),
        store.branches.len()
    ));
    if !store.error_ids.is_empty() {
        lines.push(format!("errors: {}", store.error_ids.join(", ")));
    }
    lines
}

fn checkout_detail(group: &TuiGroup, store: &TuiStore, checkout: &TuiCheckout) -> Vec<String> {
    let mut lines = vec![
        format!("checkout ({})", checkout.kind),
        format!("id: {}", checkout.id),
        format!("group: {}", group.label()),
        format!("store: {}", store.path),
        format!("path: {}", checkout.path),
        format!("git dir: {}", checkout.git_path),
        format!(
            "availability: {} ({})",
            checkout.availability,
            explain_availability(&checkout.availability)
        ),
        format!(
            "HEAD: {} ({})",
            checkout.head_state,
            explain_head_state(&checkout.head_state)
        ),
    ];
    if let Some(head_ref) = &checkout.head_ref {
        lines.push(format!("HEAD ref: {head_ref}"));
    }
    if let Some(oid) = &checkout.head_oid {
        lines.push(format!("HEAD oid: {oid}"));
    }
    lines.push(format!(
        "status: {} ({})",
        checkout.status_state,
        explain_status_state(&checkout.status_state)
    ));
    lines.push(format!(
        "working state: {} ({})",
        checkout.working_state,
        explain_working_state(&checkout.working_state)
    ));
    lines.push(format!(
        "staged: {} unstaged: {} untracked: {} conflicts: {}",
        opt_count(checkout.staged),
        opt_count(checkout.unstaged),
        opt_count(checkout.untracked),
        opt_count(checkout.conflicts),
    ));
    if !checkout.branches.is_empty() {
        lines.push(format!("branches: {}", checkout.branches.len()));
        for branch in &checkout.branches {
            lines.push(format!(
                "  {} [{}] {}",
                branch.name,
                branch.kind,
                branch_state_label(branch),
            ));
        }
    }
    if !checkout.error_ids.is_empty() {
        lines.push(format!("errors: {}", checkout.error_ids.join(", ")));
    }
    lines
}

fn branch_detail(
    group: &TuiGroup,
    store: &TuiStore,
    checkout: Option<&TuiCheckout>,
    branch: &TuiBranch,
) -> Vec<String> {
    let mut lines = vec![
        format!("branch [{}]", branch.kind),
        format!("id: {}", branch.id),
        format!("group: {}", group.label()),
        format!("store: {}", store.path),
    ];
    if let Some(checkout) = checkout {
        lines.push(format!("checkout: {}", checkout.path));
    }
    lines.push(format!("name: {}", branch.name));
    if let Some(full) = &branch.full_name {
        lines.push(format!("full ref: {full}"));
    }
    lines.push(format!(
        "comparison: {} ({})",
        branch.comparison,
        explain_comparison(&branch.comparison)
    ));
    if branch.ahead.is_some() || branch.behind.is_some() {
        lines.push(format!(
            "ahead: {} behind: {}",
            opt_count(branch.ahead),
            opt_count(branch.behind)
        ));
    }
    if let Some(upstream) = &branch.upstream {
        lines.push(format!("upstream: {upstream}"));
    }
    if let Some(oid) = &branch.oid {
        lines.push(format!("oid: {oid}"));
    }
    if !branch.error_ids.is_empty() {
        lines.push(format!("errors: {}", branch.error_ids.join(", ")));
    }
    lines
}

fn opt_count(value: Option<u64>) -> String {
    value
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// Help overlay (pinned key table)
// ---------------------------------------------------------------------------

/// Help overlay lines: the pinned key table, filter/sort cycles, and
/// view notes. Tests assert the pinned keys appear here verbatim.
pub fn help_lines() -> Vec<String> {
    vec![
        "repo-scan live view: keys".to_string(),
        String::new(),
        "  up/down or j/k    move selection".to_string(),
        "  left/right        collapse / expand (left also moves to parent)".to_string(),
        "  enter/space       expand/collapse group or store; open detail on a leaf".to_string(),
        "  /                 search account, repo, path, branch (enter keeps, esc clears)"
            .to_string(),
        "  f                 cycle filter: dirty > conflicted > ahead > behind >".to_string(),
        "                    diverged > pending > failed > off".to_string(),
        "  s                 cycle sort: group > path > state".to_string(),
        "  v                 open detail view (full paths + state explanations)".to_string(),
        "  h or ?            this help".to_string(),
        "  q                 quit (from anywhere, including overlays)".to_string(),
        "  esc               close overlay / stop search, or quit".to_string(),
        String::new(),
        "selection and scroll follow stable record ids: live updates".to_string(),
        "never reset either. quitting the view never disturbs the".to_string(),
        "scan or the catalog.".to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Renderer (view state -> text frame)
// ---------------------------------------------------------------------------

/// Header block lines: scan/phase/elapsed/discoveries/completed/
/// pending/gaps, then aggregate counts. Never a percentage.
pub fn header_lines(snapshot: &TuiSnapshot) -> Vec<String> {
    let header = &snapshot.header;
    let mut first = format!(
        "scan {} state={} phase={} elapsed={} discovered={} completed={} pending={} gaps={}",
        escape_display(&header.scan_id),
        escape_display(&header.scan_state),
        escape_display(&header.phase),
        format_elapsed(header.elapsed_s),
        header.discovered,
        header.completed,
        header.pending,
        header.gaps,
    );
    if header.cached {
        let age = header
            .snapshot_age_s
            .map(format_age)
            .unwrap_or_else(|| "unknown".to_string());
        first.push_str(&format!(" cached age={age}"));
        if header.pending_refresh {
            first.push_str(" pending-refresh");
        }
    }
    let (groups, stores, checkouts, branches, pending_rows, failed_rows) = snapshot.counts();
    let bare: usize = snapshot
        .groups
        .iter()
        .flat_map(|g| g.stores.iter())
        .filter(|s| s.bare == Some(true))
        .count();
    let second = format!(
        "totals groups={groups} stores={stores} bare={bare} checkouts={checkouts} \
         branches={branches} pending-rows={pending_rows} failed-rows={failed_rows} \
         target={}",
        escape_display(&header.target),
    );
    vec![first, second]
}

/// Footer line: filter/sort/search state plus the one-line key hint.
pub fn footer_line(state: &ViewState) -> String {
    let mut parts = vec![
        format!("filter={}", state.filter.label()),
        format!("sort={}", state.sort.label()),
    ];
    if state.searching {
        parts.push(format!("search: {}/", escape_display(&state.search)));
    } else if !state.search.is_empty() {
        parts.push(format!("search=\"{}\"", escape_display(&state.search)));
    }
    parts.push(
        "j/k move · enter expand · / search · f filter · s sort · v detail · h help · q quit"
            .to_string(),
    );
    parts.join(" │ ")
}

/// Render the full frame as text lines (no cursor codes): header,
/// scrolled rows, footer, or the overlay when one is open. Every line
/// fits `width` columns (truncated with an ellipsis, wide characters
/// honored); at most `height` lines are returned. Never panics at any
/// width/height, including 0.
pub fn render_lines(state: &ViewState, width: usize, height: usize, color: bool) -> Vec<String> {
    if height == 0 {
        return Vec::new();
    }
    if width < MIN_WIDTH {
        return render_narrow(state, width, height, color);
    }
    let mut lines: Vec<String> = Vec::new();
    for line in header_lines(&state.snapshot) {
        lines.push(fit_plain(&line, width, color, ansi::BOLD));
    }
    match &state.overlay {
        Overlay::None => {
            let rows = state.visible_rows();
            let footer = footer_line(state);
            let room = height.saturating_sub(lines.len() + 1); // rows + footer
            let top = state.scroll_top.min(rows.len().saturating_sub(1));
            let selected = state.selected.clone().unwrap_or_default();
            for (index, row) in rows.iter().skip(top).take(room).enumerate() {
                let current = row.id == selected;
                lines.push(render_row(row, current, width, color));
                let _ = index;
            }
            if rows.is_empty() {
                lines.push(fit_plain(
                    "no rows match (filter/search hides everything)",
                    width,
                    color,
                    ansi::DIM,
                ));
            }
            lines.push(fit_plain(&footer, width, color, ansi::DIM));
        }
        Overlay::Detail(id) => {
            let detail = detail_lines(&state.snapshot, id);
            lines.push(fit_plain(
                "── detail (q quits · esc closes) ──",
                width,
                color,
                ansi::CYAN,
            ));
            let room = height.saturating_sub(lines.len() + 1);
            for line in detail.iter().take(room) {
                lines.push(fit_plain(line, width, color, ""));
            }
            lines.push(fit_plain(
                "q quits · esc closes detail",
                width,
                color,
                ansi::DIM,
            ));
        }
        Overlay::Help => {
            lines.push(fit_plain(
                "── keys (q quits · esc closes) ──",
                width,
                color,
                ansi::CYAN,
            ));
            let room = height.saturating_sub(lines.len() + 1);
            for line in help_lines().iter().take(room) {
                lines.push(fit_plain(line, width, color, ""));
            }
            lines.push(fit_plain(
                "q quits · esc closes help",
                width,
                color,
                ansi::DIM,
            ));
        }
    }
    lines.truncate(height);
    lines
}

/// Narrow-terminal frame: truncated header plus a notice (the row
/// table needs [`MIN_WIDTH`] columns to stay legible).
fn render_narrow(state: &ViewState, width: usize, height: usize, color: bool) -> Vec<String> {
    let mut lines = Vec::new();
    for line in header_lines(&state.snapshot) {
        lines.push(truncate_to_width(&line, width));
    }
    lines.push(truncate_to_width(
        &format!("terminal too narrow (need {MIN_WIDTH} cols; q quits)"),
        width,
    ));
    if color {
        lines = lines
            .iter()
            .map(|l| format!("{}{l}{}", ansi::BOLD, ansi::RESET))
            .collect();
    }
    lines.truncate(height);
    lines
}

/// Fit one plain (uncolored) line to `width` columns, painting the
/// whole line when `color` and `code` is non-empty.
fn fit_plain(line: &str, width: usize, color: bool, code: &str) -> String {
    let fitted = truncate_to_width(line, width);
    if code.is_empty() {
        fitted
    } else {
        paint(code, &fitted, color)
    }
}

/// Render one tree row: indent + expand marker + label + state, with
/// the label tail-truncated (paths) or end-truncated (names) to fit.
fn render_row(row: &Row, current: bool, width: usize, color: bool) -> String {
    let indent = "  ".repeat(row.depth.min(4));
    let marker = if row.expandable {
        if row.expanded {
            "▾ "
        } else {
            "▸ "
        }
    } else {
        "· "
    };
    let cursor = if current { ">" } else { " " };
    let prefix = format!("{cursor}{indent}{marker}");
    let prefix_width = display_width(&prefix);
    let state_text = format!(" [{}]", row.state);
    let state_width = display_width(&state_text);
    let label_budget = width.saturating_sub(prefix_width + state_width);
    let label = if row.kind == "checkout" || row.kind == "store" {
        truncate_path_tail(&row.label, label_budget.max(1))
    } else {
        truncate_to_width(&row.label, label_budget.max(1))
    };
    let mut line = format!("{prefix}{label}{state_text}");
    // Pad-or-cut to the exact width so full redraws erase stale cells.
    let line_width = display_width(&line);
    if line_width < width {
        line.push_str(&" ".repeat(width - line_width));
    } else if line_width > width {
        line = truncate_to_width(&line, width);
    }
    if !color {
        return line;
    }
    let state_code = state_color(row);
    let mut painted = prefix;
    painted.push_str(&label);
    painted.push_str(&format!("{state_code}{state_text}{}", ansi::RESET));
    let painted_width = display_width(&painted);
    if painted_width < width {
        painted.push_str(&" ".repeat(width - painted_width));
    }
    if current {
        format!("{}{painted}{}", ansi::REVERSE, ansi::RESET)
    } else {
        painted
    }
}

/// State color for a row (labels always carry the same signal as text).
fn state_color(row: &Row) -> &'static str {
    let state = row.state.as_str();
    if state.contains("failed") || state.contains("error") || state.contains("conflicted") {
        ansi::RED
    } else if state.contains("diverged") {
        ansi::MAGENTA
    } else if state.contains("dirty")
        || state.contains("pending")
        || state.contains("ahead")
        || state.contains("behind")
    {
        ansi::YELLOW
    } else if state.contains("clean") || state.contains("equal") {
        ansi::GREEN
    } else if row.kind == "group" {
        ansi::BLUE
    } else {
        ansi::RESET
    }
}

/// Render a full terminal frame: cursor-home + clear-eos, then lines
/// joined for the alternate screen. The caller writes the bytes to
/// stdout and flushes.
pub fn render_frame(state: &ViewState, width: usize, height: usize, color: bool) -> String {
    let mut out = String::from("\x1b[H\x1b[J");
    let lines = render_lines(state, width, height, color);
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            out.push_str("\r\n");
        }
        out.push_str(line);
    }
    // Clear any stale rows below the frame.
    out.push_str("\x1b[J");
    out
}

// ---------------------------------------------------------------------------
// Redraw throttle (bounded redraw: ~10fps)
// ---------------------------------------------------------------------------

/// Token timer: admits a redraw at most once per interval. The clock
/// is injected (`now_ms`) so tests assert the bound deterministically.
#[derive(Debug, Clone)]
pub struct RedrawThrottle {
    /// Minimum milliseconds between redraws.
    min_interval_ms: u64,
    /// Last admitted redraw time, if any.
    last_ms: Option<u64>,
}

impl RedrawThrottle {
    /// Throttle admitting at most one redraw per `min_interval_ms`.
    pub fn new(min_interval_ms: u64) -> Self {
        Self {
            min_interval_ms,
            last_ms: None,
        }
    }

    /// Default ~10fps throttle ([`REDRAW_MIN_INTERVAL_MS`]).
    pub fn ten_fps() -> Self {
        Self::new(REDRAW_MIN_INTERVAL_MS)
    }

    /// True when a redraw at `now_ms` is admitted (the first call
    /// always admits).
    pub fn admit(&mut self, now_ms: u64) -> bool {
        match self.last_ms {
            None => {
                self.last_ms = Some(now_ms);
                true
            }
            Some(last) if now_ms.saturating_sub(last) >= self.min_interval_ms => {
                self.last_ms = Some(now_ms);
                true
            }
            Some(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal control (libc termios + ANSI, std+libc only)
// ---------------------------------------------------------------------------

/// Bytes written entering the view: alternate screen + hide cursor.
pub fn enter_sequence() -> &'static str {
    "\x1b[?1049h\x1b[?25l"
}

/// Bytes written leaving the view: show cursor + exit alternate
/// screen. Tests assert these restore bytes are emitted on quit.
pub fn exit_sequence() -> &'static str {
    "\x1b[?25h\x1b[?1049l"
}

/// RAII terminal guard: entering the view switches to the alternate
/// screen, hides the cursor, and (on a Unix TTY stdin) puts the
/// terminal in raw mode; dropping the guard restores the saved
/// termios state and leaves the alternate screen. Best-effort on
/// signals: every exit path drops the guard, and Ctrl-C in raw mode
/// arrives as a byte the key loop maps to [`Key::Interrupt`].
pub struct TermGuard {
    /// Saved termios for fd 0, when raw mode engaged.
    #[cfg(unix)]
    saved_termios: Option<libc::termios>,
    /// False after an explicit restore (drop becomes a no-op).
    active: bool,
}

impl TermGuard {
    /// Enter the view (alternate screen + raw mode). Never fails:
    /// every step is best-effort so a half-capable terminal still
    /// renders rows instead of aborting the scan.
    pub fn open() -> Self {
        #[cfg(unix)]
        let saved_termios = set_raw_mode();
        {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            let _ = lock.write_all(enter_sequence().as_bytes());
            let _ = lock.flush();
        }
        Self {
            #[cfg(unix)]
            saved_termios,
            active: true,
        }
    }

    /// Restore the terminal now (idempotent; drop repeats it safely).
    pub fn restore(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        #[cfg(unix)]
        if let Some(saved) = self.saved_termios {
            restore_termios(&saved);
        }
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let _ = lock.write_all(exit_sequence().as_bytes());
        let _ = lock.flush();
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Put fd 0 in raw mode when it is a TTY, returning the saved
/// termios for restoration. `None` when stdin is not a TTY or any
/// step fails (the view still works; keys just need cooked input).
#[cfg(unix)]
fn set_raw_mode() -> Option<libc::termios> {
    // SAFETY: `isatty`/`tcgetattr`/`tcsetattr` on fd 0 with a local
    // `termios` are async-signal-safe adjacent and mutate no shared
    // state; the zeroed struct is fully overwritten by `tcgetattr`
    // before use (failure returns None without touching the fd).
    unsafe {
        if libc::isatty(0) != 1 {
            return None;
        }
        let mut saved: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut saved) != 0 {
            return None;
        }
        let mut raw = saved;
        raw.c_iflag &= !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);
        raw.c_oflag &= !libc::OPOST;
        raw.c_cflag |= libc::CS8;
        raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 0;
        if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
            return None;
        }
        Some(saved)
    }
}

/// Restore the saved termios on fd 0 (best-effort).
#[cfg(unix)]
fn restore_termios(saved: &libc::termios) {
    // SAFETY: same contract as `set_raw_mode`; the saved struct came
    // from a successful `tcgetattr` on this fd.
    unsafe {
        libc::tcsetattr(0, libc::TCSANOW, saved);
    }
}

/// Query the current terminal size (columns, rows), re-queried on
/// every redraw so resizes take effect on the next frame. Falls back
/// to 80x24 when the ioctl fails or reports 0.
pub fn terminal_size() -> (usize, usize) {
    #[cfg(unix)]
    {
        // SAFETY: `ioctl(TIOCGWINSZ)` on fd 1 with a local
        // `winsize` writes only that struct.
        unsafe {
            let mut size: libc::winsize = std::mem::zeroed();
            if libc::ioctl(1, libc::TIOCGWINSZ, &mut size) == 0 {
                let cols = usize::from(size.ws_col);
                let rows = usize::from(size.ws_row);
                if cols > 0 && rows > 0 {
                    return (cols, rows);
                }
            }
        }
    }
    (80, 24)
}

/// Poll fd 0 for input with a `timeout_ms` wait (0 = return
/// immediately). True when bytes are ready to read.
#[cfg(unix)]
pub fn stdin_ready(timeout_ms: i32) -> bool {
    // SAFETY: `poll` on one stack `pollfd` for fd 0 touches no shared
    // state; a negative return means no input (error or interrupt).
    unsafe {
        let mut fd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        libc::poll(&mut fd, 1, timeout_ms) > 0 && fd.revents & libc::POLLIN != 0
    }
}

/// Non-Unix stdin poll: no input (the blocking loop still redraws on
/// snapshot updates; quitting falls back to external signals).
#[cfg(not(unix))]
pub fn stdin_ready(_timeout_ms: i32) -> bool {
    false
}

/// Read up to 32 bytes from fd 0 (caller must have polled first;
/// empty on error or EOF).
#[cfg(unix)]
/// Read up to 32 bytes from fd 0 (caller must have polled first).
/// `None` on EOF or error (a pty hangup/EOF ends the view; a live
/// terminal never EOFs).
#[cfg(unix)]
fn read_stdin_bytes() -> Option<Vec<u8>> {
    let mut buf = [0u8; 32];
    // SAFETY: `read` into a stack buffer touches no shared state.
    let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
    if n <= 0 {
        return None;
    }
    Some(buf[..n as usize].to_vec())
}

/// Non-Unix stdin read: no bytes, never EOF.
#[cfg(not(unix))]
fn read_stdin_bytes() -> Option<Vec<u8>> {
    Some(Vec::new())
}

// ---------------------------------------------------------------------------
// Interactive session (terminal + state + throttle)
// ---------------------------------------------------------------------------

/// What a [`Session`] poll decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    /// Keep running.
    Continue,
    /// Quit the view (terminal already restored or detached).
    Quit,
    /// Ctrl-C: restore the terminal and unwind to the caller.
    Interrupt,
}

/// One interactive view: RAII terminal guard, view state, redraw
/// throttle, and pending input bytes. Rendering runs on the calling
/// (main) thread only; the caller feeds committed snapshots in.
pub struct Session {
    /// View state (public for snapshot updates + tests).
    pub state: ViewState,
    guard: Option<TermGuard>,
    throttle: RedrawThrottle,
    color: bool,
    pending_input: Vec<u8>,
    started: Instant,
}

impl Session {
    /// Open the view over `snapshot` (enters the alternate screen
    /// immediately; the first [`Session::redraw`] paints it).
    pub fn open(snapshot: TuiSnapshot, color: bool) -> Self {
        Self {
            state: ViewState::new(snapshot),
            guard: Some(TermGuard::open()),
            throttle: RedrawThrottle::ten_fps(),
            color,
            pending_input: Vec::new(),
            started: Instant::now(),
        }
    }

    /// Replace the snapshot (selection/scroll preserved by id).
    pub fn update(&mut self, snapshot: TuiSnapshot) {
        self.state.apply_snapshot(snapshot);
    }

    /// Mutate the header in place (cheap gauge ticks without a row
    /// refresh).
    pub fn update_header(&mut self, update: impl FnOnce(&mut TuiHeader)) {
        update(&mut self.state.snapshot.header);
    }

    /// True after [`Session::detach`].
    pub fn is_detached(&self) -> bool {
        self.guard.is_none()
    }

    /// Restore the terminal and leave the alternate screen, keeping
    /// the view state (a scan continues in plain progress mode; the
    /// catalog is untouched). Idempotent.
    pub fn detach(&mut self) {
        self.guard = None; // drop restores
    }

    /// Elapsed milliseconds since the session opened (throttle clock).
    pub fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }

    /// Paint one frame now (re-queries the terminal size every call
    /// so resizes apply immediately).
    pub fn redraw(&mut self) {
        if self.is_detached() {
            return;
        }
        let (width, height) = terminal_size();
        let rows = self.state.visible_rows();
        let room = height.saturating_sub(2 + 1); // header + footer
        self.state.ensure_selected_visible(room.max(1));
        let frame = render_frame(&self.state, width, height, self.color);
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let _ = lock.write_all(frame.as_bytes());
        let _ = lock.flush();
        let _ = rows;
    }

    /// Poll input once (non-blocking) and redraw when the throttle
    /// admits: returns [`SessionAction::Quit`] on `q`/esc-in-browse
    /// or stdin EOF, [`SessionAction::Interrupt`] on Ctrl-C.
    pub fn poll(&mut self) -> SessionAction {
        if stdin_ready(0) {
            match read_stdin_bytes() {
                Some(bytes) => self.pending_input.extend(bytes),
                None => return SessionAction::Quit, // pty EOF/hangup
            }
        }
        while self.pending_input.len() > 1 || !self.pending_input.is_empty() && !stdin_ready(0) {
            let Some((key, used)) = parse_key(&self.pending_input) else {
                break;
            };
            self.pending_input.drain(..used);
            match apply_key(&mut self.state, key) {
                KeyAction::Redraw => {}
                KeyAction::Quit => return SessionAction::Quit,
                KeyAction::Interrupt => return SessionAction::Interrupt,
            }
            if self.pending_input.is_empty() {
                break;
            }
        }
        // A lone ESC byte might start an arrow sequence: when stdin
        // has no more bytes ready, treat it as a quit key now rather
        // than stalling the poll.
        if self.pending_input == [0x1b] {
            self.pending_input.clear();
            match apply_key(&mut self.state, Key::Esc) {
                KeyAction::Redraw => {}
                KeyAction::Quit => return SessionAction::Quit,
                KeyAction::Interrupt => return SessionAction::Interrupt,
            }
        }
        if self.throttle.admit(self.elapsed_ms()) {
            self.redraw();
        }
        SessionAction::Continue
    }

    /// Blocking browse loop until quit, interrupt, or stdin EOF
    /// (polls input at ~30Hz and redraws at ~10fps). Restores the
    /// terminal before returning.
    pub fn run(&mut self) -> SessionAction {
        self.redraw();
        loop {
            if stdin_ready(30) {
                match read_stdin_bytes() {
                    Some(bytes) => self.pending_input.extend(bytes),
                    None => {
                        self.detach();
                        return SessionAction::Quit; // pty EOF/hangup
                    }
                }
            }
            while let Some((key, used)) = parse_key(&self.pending_input) {
                self.pending_input.drain(..used);
                match apply_key(&mut self.state, key) {
                    KeyAction::Redraw => {}
                    KeyAction::Quit => {
                        self.detach();
                        return SessionAction::Quit;
                    }
                    KeyAction::Interrupt => {
                        self.detach();
                        return SessionAction::Interrupt;
                    }
                }
            }
            // Lone ESC with no further bytes: quit key, not a prefix.
            if self.pending_input == [0x1b] && !stdin_ready(0) {
                self.pending_input.clear();
                match apply_key(&mut self.state, Key::Esc) {
                    KeyAction::Redraw => {}
                    KeyAction::Quit => {
                        self.detach();
                        return SessionAction::Quit;
                    }
                    KeyAction::Interrupt => {
                        self.detach();
                        return SessionAction::Interrupt;
                    }
                }
            }
            if self.throttle.admit(self.elapsed_ms()) {
                self.redraw();
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.detach();
    }
}
