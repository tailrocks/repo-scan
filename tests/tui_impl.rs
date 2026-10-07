//! Wave3 live terminal TUI (Step 13, cases 24/25). No PTY: the TUI
//! splits into view-state ([`ViewState`] + [`apply_key`]) and renderer
//! ([`render_lines`]), so every test feeds scripted key streams
//! against fixture snapshots and asserts rendered frames as text.
//!
//! Case mapping:
//!
//! - Case 24 (interactive live view): `grouping_*` (account/org >
//!   repository > store > checkout grouping, aggregate counts before
//!   rows, phase/elapsed/discoveries/completed/pending/gaps header,
//!   no percentage of the unknown total), `navigation_*` (arrows +
//!   j/k, expand/collapse), `search_*`, `filter_*`, `sort_*`,
//!   `selection_*` (stable-id anchoring across scripted live
//!   updates), `detail_*`, `help_*`, `quit_*`, `resize_*`,
//!   `narrow_*`, `long_path_*`, `unicode_*`, `control_char_*`,
//!   `color_*`, `throttle_*`, `envelope_*` (locations appear before
//!   analysis completes; rows update in place; cached age +
//!   pending-refresh).
//! - Case 25 (terminal discipline): `restore_*` (RAII restore bytes,
//!   alternate-screen enter/exit), `key_parse_*` (pinned keys incl.
//!   arrows, enter/space, `/`, `f`, `s`, `v`, `h`/`?`, `q`/esc,
//!   Ctrl-C), `help_*` (help lists the pinned keys verbatim).

mod common;

use common::fixture::{tui_empty_report, tui_sample_report};
use repo_scan::report::tui::{
    self, apply_key, detail_lines, display_width, enter_sequence, exit_sequence, Filter, Key,
    KeyAction, Overlay, RedrawThrottle, Sort, TuiSnapshot, ViewState, MIN_WIDTH,
};
use repo_scan::scan_events::{Envelope, EventType};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// View state over the sample report (deterministic `now` for ages).
fn sample_state() -> ViewState {
    let snapshot = TuiSnapshot::from_report(&tui_sample_report(), 1_759_454_400_000);
    ViewState::new(snapshot)
}

/// Feed scripted keys, returning the first non-redraw action (if any).
fn feed(state: &mut ViewState, keys: &[Key]) -> Option<KeyAction> {
    for key in keys {
        match apply_key(state, *key) {
            KeyAction::Redraw => {}
            other => return Some(other),
        }
    }
    None
}

fn char_key(c: char) -> Key {
    Key::Char(c)
}

/// Rendered frame joined for substring assertions.
fn frame_text(state: &ViewState, width: usize, height: usize, color: bool) -> String {
    tui::render_lines(state, width, height, color).join("\n")
}

fn envelope(event_type: EventType, records: serde_json::Value) -> Envelope {
    Envelope::new(
        "scan-live-1".to_string(),
        1,
        1,
        0,
        event_type,
        false,
        records,
    )
}

// ---------------------------------------------------------------------------
// Case 24: grouping, header, counts
// ---------------------------------------------------------------------------

#[test]
fn grouping_nests_account_repo_store_checkout() {
    let state = sample_state();
    let rows = state.visible_rows();
    let kinds: Vec<&str> = rows.iter().map(|r| r.kind).collect();
    // groups first (depth 0), then stores (1), checkouts (2), branches (3/2).
    assert_eq!(rows[0].kind, "group");
    assert_eq!(rows[0].label, "acme/gadgets");
    assert_eq!(rows[0].depth, 0);
    assert!(kinds.contains(&"store"), "stores visible: {kinds:?}");
    assert!(kinds.contains(&"checkout"), "checkouts visible: {kinds:?}");
    assert!(kinds.contains(&"branch"), "branches visible: {kinds:?}");
    // Ungrouped sorts last.
    let last_group = rows.iter().rev().find(|r| r.kind == "group").unwrap();
    assert_eq!(last_group.label, "ungrouped");
    assert_eq!(last_group.id, "group:ungrouped");
    // Stable record ids.
    assert!(rows.iter().any(|r| r.id == "checkout:co-w1"));
    assert!(rows.iter().any(|r| r.id == "store:repo-g1"));
    assert!(rows.iter().any(|r| r.id == "branch:br-w2-feat"));
}

#[test]
fn grouping_counts_before_rows_no_percentage() {
    let state = sample_state();
    let lines = tui::render_lines(&state, 100, 30, false);
    assert!(lines.len() >= 3, "header + row + footer");
    assert!(
        lines[0].starts_with("scan scan-tui-1"),
        "header first: {}",
        lines[0]
    );
    for token in [
        "phase=",
        "elapsed=",
        "discovered=",
        "completed=",
        "pending=",
        "gaps=",
    ] {
        assert!(lines[0].contains(token), "header has {token}: {}", lines[0]);
    }
    assert!(
        lines[1].starts_with("totals "),
        "counts second: {}",
        lines[1]
    );
    for token in ["groups=3", "stores=4", "checkouts=4", "branches=5"] {
        assert!(lines[1].contains(token), "counts has {token}: {}", lines[1]);
    }
    let frame = lines.join("\n");
    assert!(!frame.contains('%'), "no percentage of unknown total");
}

#[test]
fn grouping_empty_snapshot_renders_header_only() {
    let snapshot = TuiSnapshot::from_report(&tui_empty_report(), 1_759_454_400_000);
    let state = ViewState::new(snapshot);
    assert!(state.visible_rows().is_empty());
    let lines = tui::render_lines(&state, 100, 30, false);
    assert!(lines[0].contains("scan-tui-1"));
    assert!(lines[1].contains("groups=0"));
    assert!(lines.iter().any(|l| l.contains("no rows match")));
}

// ---------------------------------------------------------------------------
// Case 24: navigation / expansion
// ---------------------------------------------------------------------------

#[test]
fn navigation_arrows_and_jk_move_selection() {
    let mut state = sample_state();
    let first = state.selected.clone().unwrap();
    feed(&mut state, &[Key::Down]);
    let second = state.selected.clone().unwrap();
    assert_ne!(first, second);
    feed(&mut state, &[Key::Char('j')]);
    let third = state.selected.clone().unwrap();
    assert_ne!(second, third);
    feed(&mut state, &[Key::Up]);
    assert_eq!(state.selected.as_ref(), Some(&second));
    feed(&mut state, &[char_key('k')]);
    assert_eq!(state.selected.as_ref(), Some(&first));
    // Clamped at the edges (never wraps, never panics).
    feed(&mut state, &[Key::Up, Key::Up]);
    assert_eq!(state.selected.as_ref(), Some(&first));
    for _ in 0..100 {
        feed(&mut state, &[Key::Down]);
    }
    let rows = state.visible_rows();
    assert_eq!(state.selected.as_ref(), rows.last().map(|r| &r.id));
}

#[test]
fn navigation_enter_space_toggle_expansion() {
    let mut state = sample_state();
    let full = state.visible_rows().len();
    assert!(full > 3);
    // First row is the gadgets group (expanded): enter collapses.
    assert_eq!(state.visible_rows()[0].kind, "group");
    feed(&mut state, &[Key::Enter]);
    assert!(state.visible_rows().len() < full);
    // Space re-expands.
    feed(&mut state, &[Key::Space]);
    assert_eq!(state.visible_rows().len(), full);
    // Left collapses, right expands.
    feed(&mut state, &[Key::Left]);
    assert!(state.visible_rows().len() < full);
    feed(&mut state, &[Key::Right]);
    assert_eq!(state.visible_rows().len(), full);
}

#[test]
fn navigation_left_on_collapsed_moves_to_parent() {
    let mut state = sample_state();
    // Move to a checkout row, then left twice: first is a no-op for
    // expansion (no branches), second moves toward the parent.
    feed(&mut state, &[Key::Down, Key::Down]);
    assert_eq!(state.visible_rows()[2].kind, "checkout");
    let before = state.selected.clone().unwrap();
    feed(&mut state, &[Key::Left]);
    let after = state.selected.clone().unwrap();
    assert_ne!(before, after, "left moves to the parent row");
    let rows = state.visible_rows();
    let pos = rows.iter().position(|r| r.id == after).unwrap();
    assert!(rows[pos].depth < 2);
}

#[test]
fn navigation_enter_on_leaf_opens_detail() {
    let mut state = sample_state();
    // Branch leaf: expand its checkout first is unnecessary here
    // (store-level branch rows are leaves already).
    let rows = state.visible_rows();
    let leaf = rows.iter().find(|r| r.kind == "branch").unwrap().clone();
    state.selected = Some(leaf.id.clone());
    feed(&mut state, &[Key::Enter]);
    assert_eq!(state.overlay, Overlay::Detail(leaf.id));
}

// ---------------------------------------------------------------------------
// Case 24: search
// ---------------------------------------------------------------------------

#[test]
fn search_filters_account_repo_path_branch() {
    let mut state = sample_state();
    let full = state.visible_rows().len();
    // Search by repo name.
    feed(&mut state, &[Key::Slash]);
    assert!(state.searching);
    for c in "gadgets".chars() {
        feed(&mut state, &[char_key(c)]);
    }
    feed(&mut state, &[Key::Enter]);
    assert!(!state.searching);
    let rows = state.visible_rows();
    assert!(!rows.is_empty() && rows.len() < full);
    assert!(rows.iter().all(|r| r.id.contains("g1")
        || r.id == "group:github.com/acme/gadgets"
        || r.kind == "group"));
    assert!(rows.iter().any(|r| r.label == "acme/gadgets"));
    // Search by path fragment.
    state.search.clear();
    state.search.push_str("scratch");
    let rows = state.visible_rows();
    assert!(rows.iter().any(|r| r.label.contains("scratch")));
    assert!(!rows.iter().any(|r| r.label.contains("widgets")));
    // Search by branch name.
    state.search.clear();
    state.search.push_str("feature");
    let rows = state.visible_rows();
    assert!(rows.iter().any(|r| r.id == "branch:br-w2-feat"));
}

#[test]
fn search_esc_clears_and_backspace_edits() {
    let mut state = sample_state();
    feed(&mut state, &[Key::Slash, char_key('x'), char_key('y')]);
    assert_eq!(state.search, "xy");
    feed(&mut state, &[Key::Backspace]);
    assert_eq!(state.search, "x");
    feed(&mut state, &[Key::Esc]);
    assert_eq!(state.search, "");
    assert!(!state.searching);
    // Quitting still works after a search session.
    assert_eq!(feed(&mut state, &[Key::Esc]), Some(KeyAction::Quit));
}

#[test]
fn search_no_match_renders_empty_note() {
    let mut state = sample_state();
    state.search.push_str("zzz-no-such-thing");
    assert!(state.visible_rows().is_empty());
    let frame = frame_text(&state, 100, 30, false);
    assert!(frame.contains("no rows match"));
}

// ---------------------------------------------------------------------------
// Case 24: filters
// ---------------------------------------------------------------------------

#[test]
fn filter_cycle_order_pinned() {
    let mut state = sample_state();
    let mut labels = Vec::new();
    for _ in 0..8 {
        feed(&mut state, &[char_key('f')]);
        labels.push(state.filter.label());
    }
    assert_eq!(
        labels,
        vec![
            "dirty",
            "conflicted",
            "ahead",
            "behind",
            "diverged",
            "pending",
            "failed",
            "off"
        ]
    );
}

#[test]
fn filter_dirty_conflicted_match_working_state() {
    let mut state = sample_state();
    feed(&mut state, &[char_key('f')]); // dirty
    let rows = state.visible_rows();
    assert!(rows.iter().any(|r| r.id == "checkout:co-w2"));
    assert!(!rows.iter().any(|r| r.id == "checkout:co-w1"));
    assert!(!rows.iter().any(|r| r.id == "checkout:co-g1"));
    feed(&mut state, &[char_key('f')]); // conflicted
    let rows = state.visible_rows();
    assert!(rows.iter().any(|r| r.id == "checkout:co-g1"));
    assert!(!rows.iter().any(|r| r.id == "checkout:co-w2"));
}

#[test]
fn filter_ahead_behind_diverged_match_comparison() {
    let mut state = sample_state();
    // ahead (dirty, conflicted, ahead).
    feed(&mut state, &[char_key('f'), char_key('f'), char_key('f')]);
    assert_eq!(state.filter, Filter::Ahead);
    let rows = state.visible_rows();
    assert!(rows.iter().any(|r| r.id == "branch:br-w2-main")); // ahead
    assert!(rows.iter().any(|r| r.id == "branch:br-w2-feat")); // diverged counts as ahead
    assert!(!rows.iter().any(|r| r.id == "branch:br-g1-main")); // behind only
    feed(&mut state, &[char_key('f')]); // behind
    let rows = state.visible_rows();
    assert!(rows.iter().any(|r| r.id == "branch:br-g1-main"));
    assert!(rows.iter().any(|r| r.id == "branch:br-w2-feat")); // diverged counts as behind
    assert!(!rows.iter().any(|r| r.id == "branch:br-w2-main"));
    feed(&mut state, &[char_key('f')]); // diverged
    let rows = state.visible_rows();
    assert!(rows.iter().any(|r| r.id == "branch:br-w2-feat"));
    assert!(!rows.iter().any(|r| r.id == "branch:br-w2-main"));
    assert!(!rows.iter().any(|r| r.id == "branch:br-g1-main"));
}

#[test]
fn filter_pending_failed_match_analysis_and_errors() {
    let mut report = tui_sample_report();
    // Attach an error record to the gadgets checkout for `failed`.
    report.checkouts[2].error_ids.push("err-1".to_string());
    let snapshot = TuiSnapshot::from_report(&report, 1_759_454_400_000);
    let mut state = ViewState::new(snapshot);
    for _ in 0..6 {
        feed(&mut state, &[char_key('f')]);
    }
    assert_eq!(state.filter, Filter::Pending);
    let rows = state.visible_rows();
    assert!(rows.iter().any(|r| r.id == "checkout:co-u1"));
    assert!(!rows.iter().any(|r| r.id == "checkout:co-w1"));
    feed(&mut state, &[char_key('f')]);
    assert_eq!(state.filter, Filter::Failed);
    let rows = state.visible_rows();
    assert!(rows.iter().any(|r| r.id == "checkout:co-g1"));
    assert!(!rows.iter().any(|r| r.id == "checkout:co-w1"));
}

#[test]
fn filter_footer_shows_active_filter() {
    let mut state = sample_state();
    feed(&mut state, &[char_key('f')]);
    let frame = frame_text(&state, 120, 30, false);
    assert!(
        frame.contains("filter=dirty"),
        "footer shows filter: {frame}"
    );
}

// ---------------------------------------------------------------------------
// Case 24: sorts
// ---------------------------------------------------------------------------

#[test]
fn sort_cycle_order_pinned() {
    let mut state = sample_state();
    let mut labels = Vec::new();
    for _ in 0..3 {
        feed(&mut state, &[char_key('s')]);
        labels.push(state.sort.label());
    }
    assert_eq!(labels, vec!["path", "state", "group"]);
}

#[test]
fn sort_state_orders_problems_first() {
    let mut state = sample_state();
    feed(&mut state, &[char_key('s'), char_key('s')]); // state
    assert_eq!(state.sort, Sort::State);
    let rows = state.visible_rows();
    // The widgets group (dirty checkout) sorts before gadgets
    // (conflicted sorts first actually: conflicted < dirty).
    let gadgets = rows.iter().position(|r| r.label == "acme/gadgets").unwrap();
    let widgets = rows.iter().position(|r| r.label == "acme/widgets").unwrap();
    assert!(gadgets < widgets, "conflicted group before dirty group");
    // Within widgets: the dirty checkout's store before the clean one.
    let dirty = rows.iter().position(|r| r.id == "checkout:co-w2").unwrap();
    let clean = rows.iter().position(|r| r.id == "checkout:co-w1").unwrap();
    assert!(dirty < clean, "dirty checkout before clean checkout");
}

// ---------------------------------------------------------------------------
// Case 24: selection correctness across live updates
// ---------------------------------------------------------------------------

#[test]
fn selection_survives_row_additions_by_id() {
    let mut state = sample_state();
    // Select the widgets-mirror checkout.
    state.selected = Some("checkout:co-w2".to_string());
    // Scripted live update: a new store + checkout appear ABOVE it.
    let mut report = tui_sample_report();
    report
        .paths
        .push(common::fixture::tui_path("p-new", "/srv/git/aaa-new"));
    report
        .repositories
        .push(repo_scan::report::model::Repository {
            id: "repo-new".to_string(),
            git_path_id: "p-new".to_string(),
            common_path_id: "p-new".to_string(),
            bare: Some(false),
            format: "common".to_string(),
            object_format: "sha1".to_string(),
            match_disposition: "confirmed".to_string(),
            evidence: vec![],
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            tool_managed: None,
            error_ids: vec![],
        });
    let snapshot = TuiSnapshot::from_report(&report, 1_759_454_400_000);
    state.apply_snapshot(snapshot);
    assert_eq!(state.selected.as_deref(), Some("checkout:co-w2"));
    // The new rows exist, but the cursor did not follow them.
    assert!(state
        .visible_rows()
        .iter()
        .any(|r| r.id == "store:repo-new"));
}

#[test]
fn selection_survives_row_changes_mid_session() {
    let mut state = sample_state();
    state.selected = Some("checkout:co-u1".to_string());
    // The pending checkout finishes analysis mid-session.
    let mut report = tui_sample_report();
    report.checkouts[3].status = common::fixture::tui_status("complete", "clean");
    let snapshot = TuiSnapshot::from_report(&report, 1_759_454_400_000);
    state.apply_snapshot(snapshot);
    assert_eq!(state.selected.as_deref(), Some("checkout:co-u1"));
    let row = state
        .visible_rows()
        .into_iter()
        .find(|r| r.id == "checkout:co-u1")
        .unwrap();
    assert!(
        row.state.contains("clean"),
        "row updated in place: {}",
        row.state
    );
    assert!(!row.state.contains("pending"));
}

#[test]
fn scroll_anchor_survives_live_updates() {
    let mut state = sample_state();
    // Scroll down several rows, then update: the anchor row stays put.
    for _ in 0..5 {
        feed(&mut state, &[Key::Down]);
    }
    state.scroll_top = 3;
    let anchor = state.visible_rows()[3].id.clone();
    let selected = state.selected.clone().unwrap();
    let mut report = tui_sample_report();
    report.checkouts[3].status = common::fixture::tui_status("complete", "clean");
    state.apply_snapshot(TuiSnapshot::from_report(&report, 1_759_454_400_000));
    assert_eq!(state.selected.as_ref(), Some(&selected));
    let rows = state.visible_rows();
    assert_eq!(rows[state.scroll_top].id, anchor);
}

#[test]
fn selection_nearest_row_when_id_vanishes() {
    let mut state = sample_state();
    state.selected = Some("checkout:co-u1".to_string());
    // The selected checkout disappears from the snapshot.
    let mut report = tui_sample_report();
    report.checkouts.pop();
    state.apply_snapshot(TuiSnapshot::from_report(&report, 1_759_454_400_000));
    assert_ne!(state.selected.as_deref(), Some("checkout:co-u1"));
    assert!(state.selected.is_some());
    // Still a valid visible row.
    let rows = state.visible_rows();
    assert!(rows.iter().any(|r| Some(&r.id) == state.selected.as_ref()));
}

// ---------------------------------------------------------------------------
// Case 24: detail view
// ---------------------------------------------------------------------------

#[test]
fn detail_view_full_paths_and_explanations() {
    let state = sample_state();
    let lines = detail_lines(&state.snapshot, "checkout:co-w2");
    let text = lines.join("\n");
    assert!(
        text.contains("/home/u/work/widgets-mirror"),
        "full path: {text}"
    );
    assert!(text.contains("/srv/git/widgets-mirror"), "git dir: {text}");
    assert!(text.contains("dirty"), "state: {text}");
    assert!(text.contains("uncommitted changes"), "explanation: {text}");
    // Branch detail carries comparison + explanation.
    let lines = detail_lines(&state.snapshot, "branch:br-w2-feat");
    let text = lines.join("\n");
    assert!(text.contains("diverged"), "comparison: {text}");
    assert!(
        text.contains("both sides have commits"),
        "explanation: {text}"
    );
    assert!(text.contains("ahead: 2 behind: 1"), "counts: {text}");
}

#[test]
fn detail_overlay_renders_and_closes() {
    let mut state = sample_state();
    state.selected = Some("checkout:co-w2".to_string());
    feed(&mut state, &[char_key('v')]);
    assert!(matches!(state.overlay, Overlay::Detail(_)));
    let frame = frame_text(&state, 100, 30, false);
    assert!(frame.contains("detail") || frame.contains("detail") || frame.contains("checkout"));
    assert!(frame.contains("/home/u/work/widgets-mirror"));
    // esc closes the overlay (does not quit).
    assert_eq!(feed(&mut state, &[Key::Esc]), None);
    assert_eq!(state.overlay, Overlay::None);
    // q from the overlay quits the view.
    feed(&mut state, &[char_key('v')]);
    assert_eq!(feed(&mut state, &[char_key('q')]), Some(KeyAction::Quit));
}

// ---------------------------------------------------------------------------
// Cases 24/25: help overlay
// ---------------------------------------------------------------------------

#[test]
fn help_lists_pinned_keys() {
    let mut state = sample_state();
    feed(&mut state, &[char_key('h')]);
    assert_eq!(state.overlay, Overlay::Help);
    let frame = frame_text(&state, 100, 40, false);
    for pinned in [
        "up/down or j/k",
        "left/right",
        "enter/space",
        "cycle filter: dirty",
        "conflicted",
        "ahead",
        "behind",
        "diverged",
        "pending",
        "failed",
        "cycle sort: group",
        "open detail view",
        "h or ?",
        "quit",
        "esc",
    ] {
        assert!(frame.contains(pinned), "help lists {pinned:?}:\n{frame}");
    }
    // `?` also opens help; any non-q key closes it.
    feed(&mut state, &[Key::Esc]);
    feed(&mut state, &[char_key('?')]);
    assert_eq!(state.overlay, Overlay::Help);
    assert_eq!(feed(&mut state, &[Key::Enter]), None);
    assert_eq!(state.overlay, Overlay::None);
}

// ---------------------------------------------------------------------------
// Cases 24/25: quit + restore
// ---------------------------------------------------------------------------

#[test]
fn quit_keys_quit_from_browse() {
    let mut state = sample_state();
    assert_eq!(feed(&mut state, &[char_key('q')]), Some(KeyAction::Quit));
    let mut state = sample_state();
    assert_eq!(feed(&mut state, &[Key::Esc]), Some(KeyAction::Quit));
    // Search input `q` does not quit.
    let mut state = sample_state();
    feed(&mut state, &[Key::Slash, char_key('q')]);
    assert_eq!(state.search, "q");
}

#[test]
fn restore_bytes_carry_cursor_and_screen() {
    // Enter: alternate screen + hide cursor. Exit (emitted on quit
    // via the RAII guard): show cursor + leave alternate screen.
    assert!(enter_sequence().contains("\x1b[?1049h"), "alt screen enter");
    assert!(enter_sequence().contains("\x1b[?25l"), "hide cursor");
    assert!(exit_sequence().contains("\x1b[?25h"), "show cursor");
    assert!(exit_sequence().contains("\x1b[?1049l"), "alt screen exit");
    assert_ne!(enter_sequence(), exit_sequence());
}

// ---------------------------------------------------------------------------
// Case 25: key parsing
// ---------------------------------------------------------------------------

#[test]
fn key_parse_pinned_bytes() {
    use repo_scan::report::tui::parse_key;
    assert_eq!(parse_key(b"\x1b[A"), Some((Key::Up, 3)));
    assert_eq!(parse_key(b"\x1b[B"), Some((Key::Down, 3)));
    assert_eq!(parse_key(b"\x1b[C"), Some((Key::Right, 3)));
    assert_eq!(parse_key(b"\x1b[D"), Some((Key::Left, 3)));
    assert_eq!(parse_key(b"\x1bOA"), Some((Key::Up, 3))); // xterm private
    assert_eq!(parse_key(b"\r"), Some((Key::Enter, 1)));
    assert_eq!(parse_key(b"\n"), Some((Key::Enter, 1)));
    assert_eq!(parse_key(b" "), Some((Key::Space, 1)));
    assert_eq!(parse_key(b"/"), Some((Key::Slash, 1)));
    assert_eq!(parse_key(b"q"), Some((Key::Char('q'), 1)));
    assert_eq!(parse_key(b"\x1b"), Some((Key::Esc, 1)));
    assert_eq!(parse_key(b"\x03"), Some((Key::Interrupt, 1)));
    assert_eq!(parse_key(b"\x7f"), Some((Key::Backspace, 1)));
    // Incomplete escape sequence: caller must read more.
    assert_eq!(parse_key(b"\x1b["), None);
    assert_eq!(parse_key(b""), None);
    // Multi-byte UTF-8 search input parses as one key.
    assert_eq!(parse_key("é".as_bytes()), Some((Key::Char('é'), 2)));
}

// ---------------------------------------------------------------------------
// Case 24: resize / narrow / long paths / unicode / control chars
// ---------------------------------------------------------------------------

#[test]
fn resize_frame_fits_any_size_without_panic() {
    let state = sample_state();
    for (width, height) in [
        (200, 60),
        (80, 24),
        (40, 8),
        (41, 9),
        (100, 1),
        (100, 0),
        (1, 24),
        (0, 24),
        (0, 0),
    ] {
        let lines = tui::render_lines(&state, width, height, false);
        assert!(
            lines.len() <= height,
            "height {height}: {} lines",
            lines.len()
        );
        for line in &lines {
            assert!(
                display_width(line) <= width,
                "width {width}: {line:?} is {} cols",
                display_width(line)
            );
        }
    }
}

#[test]
fn narrow_terminal_shows_notice_not_rows() {
    let state = sample_state();
    let lines = tui::render_lines(&state, MIN_WIDTH - 1, 24, false);
    let frame = lines.join("\n");
    assert!(frame.contains("too narrow"), "narrow notice: {frame}");
    assert!(frame.contains(&MIN_WIDTH.to_string()));
    // At the minimum width the row table renders.
    let lines = tui::render_lines(&state, MIN_WIDTH, 24, false);
    let frame = lines.join("\n");
    assert!(!frame.contains("too narrow"));
    assert!(frame.contains("acme/"));
}

#[test]
fn long_paths_truncate_with_ellipsis_keep_tail() {
    let mut report = tui_empty_report();
    let deep = "/very/long/root/segment-a/segment-b/segment-c/segment-d/repo-checkout";
    report.paths.push(common::fixture::tui_path("p-deep", deep));
    report
        .repositories
        .push(repo_scan::report::model::Repository {
            id: "repo-deep".to_string(),
            git_path_id: "p-deep".to_string(),
            common_path_id: "p-deep".to_string(),
            bare: Some(false),
            format: "common".to_string(),
            object_format: "sha1".to_string(),
            match_disposition: "confirmed".to_string(),
            evidence: vec![],
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            tool_managed: None,
            error_ids: vec![],
        });
    let state = ViewState::new(TuiSnapshot::from_report(&report, 1_759_454_400_000));
    let frame = frame_text(&state, 60, 24, false);
    assert!(frame.contains("…"), "ellipsis marks truncation: {frame}");
    assert!(frame.contains("repo-checkout"), "tail kept: {frame}");
    assert!(!frame.contains("segment-a"), "head dropped: {frame}");
    for line in tui::render_lines(&state, 60, 24, false) {
        assert!(display_width(&line) <= 60, "line fits: {line:?}");
    }
}

#[test]
fn unicode_width_counts_wide_and_combining() {
    assert_eq!(display_width("plain"), 5);
    assert_eq!(display_width("日本語"), 6); // 3 wide chars
    assert_eq!(display_width("é"), 1); // e + combining acute
    assert_eq!(display_width("a日b"), 4);
    // Truncation never splits a wide char and honors its width.
    assert_eq!(tui::truncate_to_width("日本語X", 5), "日本…");
    assert_eq!(tui::truncate_to_width("日本語X", 4), "日…");
    // Wide-char paths render within the frame width.
    let mut report = tui_empty_report();
    report.paths.push(common::fixture::tui_path(
        "p-cjk",
        "/srv/日本語リポジトリ/checkout",
    ));
    report
        .repositories
        .push(repo_scan::report::model::Repository {
            id: "repo-cjk".to_string(),
            git_path_id: "p-cjk".to_string(),
            common_path_id: "p-cjk".to_string(),
            bare: Some(false),
            format: "common".to_string(),
            object_format: "sha1".to_string(),
            match_disposition: "confirmed".to_string(),
            evidence: vec![],
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            tool_managed: None,
            error_ids: vec![],
        });
    let state = ViewState::new(TuiSnapshot::from_report(&report, 1_759_454_400_000));
    for line in tui::render_lines(&state, 50, 24, false) {
        assert!(display_width(&line) <= 50, "CJK line fits: {line:?}");
    }
}

#[test]
fn control_characters_escaped_no_raw_bytes() {
    let mut report = tui_empty_report();
    report.paths.push(common::fixture::tui_path(
        "p-evil",
        "line1\nline2\x1b[31mesc\tend\x07",
    ));
    report
        .repositories
        .push(repo_scan::report::model::Repository {
            id: "repo-evil".to_string(),
            git_path_id: "p-evil".to_string(),
            common_path_id: "p-evil".to_string(),
            bare: Some(false),
            format: "common".to_string(),
            object_format: "sha1".to_string(),
            match_disposition: "confirmed".to_string(),
            evidence: vec![],
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            tool_managed: None,
            error_ids: vec![],
        });
    let state = ViewState::new(TuiSnapshot::from_report(&report, 1_759_454_400_000));
    let frame = frame_text(&state, 120, 24, false);
    assert!(!frame.as_bytes().contains(&0x1b), "no raw ESC: {frame:?}");
    assert!(!frame.contains('\x07'), "no raw BEL");
    assert!(!frame.contains('\t'), "no raw TAB");
    assert!(frame.contains("\\n"), "newline escaped: {frame}");
    assert!(
        frame.contains("\\u{1B}") || frame.contains("\\u{1b}"),
        "ESC escaped: {frame}"
    );
    // One path still renders as one row (no injected newlines).
    let rows: Vec<&str> = frame.lines().filter(|l| l.contains("line1")).collect();
    assert_eq!(rows.len(), 1);
}

// ---------------------------------------------------------------------------
// Case 24: color
// ---------------------------------------------------------------------------

#[test]
fn color_matrix_ansi_and_labels() {
    use repo_scan::report::tui::{resolve_color_with, ColorMode};
    // auto/always/never × NO_COLOR/TERM=dumb.
    assert!(resolve_color_with(ColorMode::Auto, true, false, false));
    assert!(!resolve_color_with(ColorMode::Auto, false, false, false));
    assert!(resolve_color_with(ColorMode::Always, false, false, false));
    assert!(!resolve_color_with(ColorMode::Never, true, false, false));
    for mode in [ColorMode::Auto, ColorMode::Always, ColorMode::Never] {
        assert!(
            !resolve_color_with(mode, true, true, false),
            "NO_COLOR wins: {mode:?}"
        );
        assert!(
            !resolve_color_with(mode, true, false, true),
            "TERM=dumb wins: {mode:?}"
        );
    }
    // Rendered frames: ANSI present only when color is on, labels always.
    let state = sample_state();
    let colored = frame_text(&state, 100, 30, true);
    let plain = frame_text(&state, 100, 30, false);
    assert!(colored.contains("\x1b["), "color emits ANSI");
    assert!(!plain.contains("\x1b["), "plain emits no ANSI");
    for label in [
        "dirty",
        "clean",
        "conflicted",
        "pending",
        "ahead",
        "diverged",
    ] {
        assert!(colored.contains(label), "color keeps {label}");
        assert!(plain.contains(label), "plain keeps {label}");
    }
}

// ---------------------------------------------------------------------------
// Case 24: throttle bound
// ---------------------------------------------------------------------------

#[test]
fn throttle_bounds_rapid_updates() {
    // 100 updates inside 50ms admit exactly 1 redraw at ~10fps.
    let mut throttle = RedrawThrottle::ten_fps();
    let mut admitted = 0;
    for ms in 0..100 {
        if throttle.admit(ms / 2) {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 1, "N rapid updates collapse to one redraw");
    // One update per 100ms window each admits.
    let mut throttle = RedrawThrottle::ten_fps();
    let mut admitted = 0;
    for tick in 0..5 {
        if throttle.admit(tick * 100) {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 5);
    // Steady 1kHz updates over a second admit ~10 redraws, never 1000.
    let mut throttle = RedrawThrottle::ten_fps();
    let mut admitted = 0;
    for ms in 0..1000 {
        if throttle.admit(ms) {
            admitted += 1;
        }
    }
    assert!(admitted <= 11, "bounded redraws: {admitted}");
    assert!(admitted >= 9, "live enough: {admitted}");
}

// ---------------------------------------------------------------------------
// Case 24: live envelope folding + cached snapshots
// ---------------------------------------------------------------------------

#[test]
fn envelope_locations_appear_before_analysis() {
    let mut snapshot = TuiSnapshot::empty();
    snapshot.apply_envelope(&envelope(
        EventType::ScanStarted,
        serde_json::json!({"target": "https://github.com/acme/widgets"}),
    ));
    snapshot.apply_envelope(&envelope(
        EventType::RepositoryFound,
        serde_json::json!({
            "store_id": "store-1",
            "github_groups": ["github.com/acme/widgets"],
            "analysis": "pending",
        }),
    ));
    snapshot.apply_envelope(&envelope(
        EventType::LocationFound,
        serde_json::json!({
            "checkout_id": "co-1",
            "store_id": "store-1",
            "path": "/home/u/work/widgets",
            "git_path": "/srv/git/widgets",
            "analysis": "pending",
        }),
    ));
    let state = ViewState::new(snapshot);
    let rows = state.visible_rows();
    assert!(
        rows.iter().any(|r| r.id == "checkout:co-1"),
        "location visible pre-analysis"
    );
    let row = rows.iter().find(|r| r.id == "checkout:co-1").unwrap();
    assert!(
        row.state.contains("pending"),
        "pending label: {}",
        row.state
    );
    // Re-delivery is idempotent (no duplicate rows).
    let mut snapshot = state.snapshot.clone();
    snapshot.apply_envelope(&envelope(
        EventType::LocationFound,
        serde_json::json!({
            "checkout_id": "co-1",
            "store_id": "store-1",
            "path": "/home/u/work/widgets",
            "git_path": "/srv/git/widgets",
            "analysis": "pending",
        }),
    ));
    let again = ViewState::new(snapshot).visible_rows();
    assert_eq!(rows.len(), again.len());
}

#[test]
fn envelope_progress_and_completion_update_header() {
    let mut snapshot = TuiSnapshot::empty();
    snapshot.apply_envelope(&envelope(
        EventType::DiscoveryProgress,
        serde_json::json!({
            "phase": "discovery",
            "elapsed_s": 12,
            "discovered": {"tasks_done": 40},
            "pending": 7,
            "gaps": {"open": 1},
        }),
    ));
    assert_eq!(snapshot.header.phase, "discovery");
    assert_eq!(snapshot.header.elapsed_s, 12);
    assert_eq!(snapshot.header.pending, 7);
    assert_eq!(snapshot.header.gaps, 1);
    snapshot.apply_envelope(&envelope(EventType::InventoryReady, serde_json::json!({})));
    assert_eq!(snapshot.header.phase, "analysis");
    snapshot.apply_envelope(&envelope(EventType::ScanCompleted, serde_json::json!({})));
    assert_eq!(snapshot.header.scan_state, "complete");
    assert_eq!(snapshot.header.phase, "done");
    let frame = tui::render_lines(&ViewState::new(snapshot), 100, 24, false).join("\n");
    assert!(frame.contains("phase=done"));
    assert!(!frame.contains('%'));
}

#[test]
fn envelope_branch_batch_and_location_updated() {
    let mut snapshot = TuiSnapshot::empty();
    snapshot.apply_envelope(&envelope(
        EventType::LocationFound,
        serde_json::json!({
            "checkout_id": "co-1",
            "store_id": "store-1",
            "path": "/home/u/work/widgets",
            "git_path": "/srv/git/widgets",
            "analysis": "pending",
        }),
    ));
    snapshot.apply_envelope(&envelope(
        EventType::BranchBatch,
        serde_json::json!({
            "store_id": "store-1",
            "branches": [{"id": "br-1", "kind": "local", "name": "main",
                          "comparison": "ahead", "ahead": 2}],
        }),
    ));
    let rows = ViewState::new(snapshot.clone()).visible_rows();
    let branch = rows.iter().find(|r| r.id == "branch:br-1").unwrap();
    assert!(
        branch.state.contains("ahead"),
        "branch state: {}",
        branch.state
    );
    assert!(branch.state.contains("+2"), "counts: {}", branch.state);
    // Analysis finishes: the row updates in place (same id).
    snapshot.apply_envelope(&envelope(
        EventType::LocationUpdated,
        serde_json::json!({
            "checkout_id": "co-1",
            "status_state": "complete",
            "working_state": "dirty",
            "staged": 1,
        }),
    ));
    let rows = ViewState::new(snapshot).visible_rows();
    let checkout = rows.iter().find(|r| r.id == "checkout:co-1").unwrap();
    assert!(
        checkout.state.contains("dirty"),
        "updated: {}",
        checkout.state
    );
    assert!(!checkout.state.contains("pending"));
}

#[test]
fn cached_snapshot_shows_age_and_pending_refresh() {
    let mut report = tui_sample_report();
    report.scan.cached = true;
    report.scan.state = "complete".to_string();
    // created 3h before `now`.
    let created = repo_scan::report::tui::parse_rfc3339_ms(&report.created_at).unwrap();
    let snapshot = TuiSnapshot::from_report(&report, created + 3 * 3_600_000);
    assert!(snapshot.header.cached);
    assert_eq!(snapshot.header.snapshot_age_s, Some(3 * 3_600));
    assert!(snapshot.header.pending_refresh, "pending rows refresh");
    let frame = tui::render_lines(&ViewState::new(snapshot), 200, 30, false).join("\n");
    assert!(frame.contains("cached age=3h"), "age: {frame}");
    assert!(frame.contains("pending-refresh"), "refresh tag: {frame}");
}

#[test]
fn live_update_keeps_view_state_across_envelopes() {
    let mut snapshot = TuiSnapshot::empty();
    snapshot.apply_envelope(&envelope(
        EventType::LocationFound,
        serde_json::json!({
            "checkout_id": "co-1",
            "store_id": "store-1",
            "path": "/b",
            "git_path": "/b.git",
            "analysis": "pending",
        }),
    ));
    let mut state = ViewState::new(snapshot);
    state.selected = Some("checkout:co-1".to_string());
    // A second location arrives; selection stays on the same id.
    let mut next = state.snapshot.clone();
    next.apply_envelope(&envelope(
        EventType::LocationFound,
        serde_json::json!({
            "checkout_id": "co-2",
            "store_id": "store-1",
            "path": "/a",
            "git_path": "/a.git",
            "analysis": "pending",
        }),
    ));
    state.apply_snapshot(next);
    assert_eq!(state.selected.as_deref(), Some("checkout:co-1"));
}
