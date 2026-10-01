//! RESOURCE-RECHECK R2: `Topology.seen` must stay bounded on a full
//! scan (spec §5: no in-memory set of every path/identity). No fixtures,
//! no machine scans: pure in-memory guard behavior.

use repo_scan::walk::topology::{ObserveOutcome, PhysicalDirId, Topology, TOPOLOGY_SEEN_CAP};

fn dir(ino: u64) -> PhysicalDirId {
    PhysicalDirId {
        dev: 1,
        ino,
        namespace: String::from("dev:1"),
    }
}

/// Growth past the cap evicts oldest-first: length stays flat, the newest
/// identity still dedupes, and an evicted identity re-reports `New`
/// (bounded re-walk, never unbounded memory).
#[test]
fn topology_seen_bounded_fifo_with_documented_rewalk() {
    let mut topo = Topology::new();
    assert!(topo.is_empty());
    assert_eq!(topo.observe(dir(7)), ObserveOutcome::New);
    assert_eq!(topo.observe(dir(7)), ObserveOutcome::Duplicate);
    assert_eq!(topo.len(), 1);

    let total = (TOPOLOGY_SEEN_CAP as u64) * 2 + 10;
    for ino in 0..total {
        topo.observe(dir(ino));
    }
    assert!(
        topo.len() <= TOPOLOGY_SEEN_CAP,
        "retained {} exceeds cap {TOPOLOGY_SEEN_CAP}",
        topo.len()
    );
    assert_eq!(topo.len(), TOPOLOGY_SEEN_CAP);

    // Newest identity retained: still dedupes.
    let newest = total - 1;
    assert!(topo.contains(&dir(newest)));
    assert_eq!(topo.observe(dir(newest)), ObserveOutcome::Duplicate);

    // Oldest identity evicted: re-reports New (bounded re-walk cost).
    assert!(!topo.contains(&dir(0)));
    assert_eq!(topo.observe(dir(0)), ObserveOutcome::New);
    assert!(topo.len() <= TOPOLOGY_SEEN_CAP);
}
