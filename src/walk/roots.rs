//! Machine-scope root planning (spec §7).
//!
//! `machine` scope inventories every mounted, addressable root and attempts
//! each fairly. Likely locations are seeded for early useful results but
//! never substitute for complete scope: `/tmp`, `/private/tmp`, the
//! effective user home, `/private/var/folders`, and configured Cargo
//! locations are priorities. Scheduling order: seeds first, then mounts in
//! plan order; the scheduler enqueues one enumeration task per root in
//! that order and claims FIFO within each task class with R06
//! class-interleaved claims, so a large tree under one root cannot starve
//! the others indefinitely — every root's tasks eventually claim (a stuck
//! scope becomes a gap, never a silent skip). Nothing is excluded by
//! directory name (`target`, `.cargo`, `.cache`, `node_modules`, `.git`
//! are all in scope).

use crate::platform::{MountPoint, VolumeId};
use std::path::PathBuf;

/// Scheduling priority of one planned root. Priority orders first contact;
/// every root is still attempted fairly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootPriority {
    /// Seed: likely location, visited first for early results.
    Early,
    /// Ordinary scope member.
    Normal,
}

/// One root of the machine plan.
#[derive(Debug, Clone)]
pub struct PlannedRoot {
    /// Absolute path where enumeration starts.
    pub path: PathBuf,
    /// Scheduling priority.
    pub priority: RootPriority,
    /// Dedup namespace for physical-dir identity (volume UUID or mount).
    pub namespace: String,
    /// Owning volume, when known from the mount table.
    pub volume: Option<VolumeId>,
}

/// Seed likely locations for early useful results (spec §7). These are
/// priorities, not scope: the full mount table is always added by
/// [`plan_machine_roots`].
pub fn seed_roots() -> Vec<PlannedRoot> {
    let mut seeds = Vec::new();
    let mut push = |path: PathBuf| {
        seeds.push(PlannedRoot {
            path,
            priority: RootPriority::Early,
            namespace: String::from("seed"),
            volume: None,
        });
    };

    push(PathBuf::from("/tmp"));
    #[cfg(target_os = "macos")]
    push(PathBuf::from("/private/tmp"));

    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            push(PathBuf::from(&home));
        }
    }

    #[cfg(target_os = "macos")]
    push(PathBuf::from("/private/var/folders"));

    if let Ok(cargo) = std::env::var("CARGO_HOME") {
        if !cargo.is_empty() {
            push(PathBuf::from(cargo));
        }
    } else if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            push(PathBuf::from(home).join(".cargo"));
        }
    }

    seeds
}

/// Build the machine-scope plan: seeds first, then every mount-table root,
/// deduplicated by path. Unavailable or permission-denied roots stay in the
/// plan as coverage gaps; they are never silently dropped here.
pub fn plan_machine_roots(mounts: &[MountPoint]) -> Vec<PlannedRoot> {
    let mut roots = seed_roots();
    for mount in mounts {
        if roots.iter().any(|r| r.path == mount.mount_path) {
            continue;
        }
        roots.push(PlannedRoot {
            path: mount.mount_path.clone(),
            priority: RootPriority::Normal,
            namespace: mount.volume.0.clone(),
            volume: Some(mount.volume.clone()),
        });
    }
    roots
}

/// Full generation scope key (goal Step 9, contract D5): normalized
/// policy, canonical roots, and per-root volume identity,
/// order-independent. Two scans share filesystem coverage if and only if
/// their keys match; targets stay OUT (one pass serves all targets;
/// filtering is separate).
///
/// Entry per root: dedup namespace (volume UUID/mount, or `explicit`/`seed`),
/// canonical path bytes, and the device number pinning the volume. Device
/// numbers can change across reboots/remounts; a mismatch only forces a
/// fresh generation (safe direction), never wrong reuse. No user exclusion
/// flags exist yet; traversal-time filesystem-class filtering is
/// deterministic from the mount set, so it needs no extra key input.
pub fn generation_scope_key(policy: &str, roots: &[PlannedRoot]) -> String {
    let paths: Vec<PathBuf> = roots.iter().map(|root| root.path.clone()).collect();
    // Root canonicalization and volume identity both run through the
    // topology layer's bounded identity-I/O worker. If admission or the
    // timeout fails, use the normalized lexical spelling and an explicit
    // unknown-device marker; when the identity becomes available later,
    // the key changes and safely starts a fresh generation.
    let identities = crate::walk::topology::bounded_scope_identities(&paths);
    let mut entries: Vec<Vec<u8>> = roots
        .iter()
        .enumerate()
        .map(|(index, root)| {
            let (canonical, dev) = identities
                .as_ref()
                .and_then(|items| items.get(index))
                .map(|(path, dev)| (path.clone(), *dev))
                .unwrap_or_else(|| (crate::config::normalize_scope_path(&root.path), None));
            let mut entry = Vec::new();
            entry.extend_from_slice(root.namespace.as_bytes());
            entry.push(0);
            entry.extend_from_slice(&crate::config::path_as_bytes(&canonical));
            entry.push(0);
            entry.extend_from_slice(
                dev.map(|value| value.to_string())
                    .unwrap_or_else(|| String::from("unknown"))
                    .as_bytes(),
            );
            entry
        })
        .collect();
    entries.sort();
    entries.dedup();
    let mut joined = Vec::new();
    for entry in &entries {
        joined.extend_from_slice(entry);
        joined.push(0);
    }
    format!("v2:{policy}:{}", crate::config::encode_hex(&joined))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explicit(path: PathBuf) -> PlannedRoot {
        PlannedRoot {
            path,
            priority: RootPriority::Early,
            namespace: String::from("explicit"),
            volume: None,
        }
    }

    fn scratch(case: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("repo-scan-scopekey-{}-{case}", std::process::id()));
        // Pid-scoped: only this live process owns the name, so a leftover
        // from a dead pid-holder is safe to clear (pid-reuse flake).
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    #[test]
    fn scratch_survives_stale_pid_reuse() {
        // A previous test process with a recycled pid leaves its scratch
        // dir behind; scratch() must start clean so symlink creation below
        // cannot fail with EEXIST (the spelling_variants_share_key flake).
        let base = scratch("stale-reuse");
        let real = base.join("real");
        std::fs::create_dir_all(&real).expect("real");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("plant stale link");
        let base = scratch("stale-reuse");
        let link = base.join("link");
        std::os::unix::fs::symlink(base.join("real"), &link).expect("reuse after stale");
    }

    #[test]
    fn key_is_order_independent() {
        let base = scratch("order");
        let a = base.join("a");
        let b = base.join("b");
        std::fs::create_dir_all(&a).expect("a");
        std::fs::create_dir_all(&b).expect("b");
        let ab = generation_scope_key("roots", &[explicit(a.clone()), explicit(b.clone())]);
        let ba = generation_scope_key("roots", &[explicit(b), explicit(a)]);
        assert_eq!(ab, ba);
    }

    #[test]
    fn distinct_sets_and_policies_differ() {
        let base = scratch("distinct");
        let a = base.join("a");
        let b = base.join("b");
        std::fs::create_dir_all(&a).expect("a");
        std::fs::create_dir_all(&b).expect("b");
        let ka = generation_scope_key("roots", &[explicit(a.clone())]);
        let kb = generation_scope_key("roots", &[explicit(b.clone())]);
        let kab = generation_scope_key("roots", &[explicit(a.clone()), explicit(b)]);
        let k_machine = generation_scope_key("machine", &[explicit(a)]);
        assert_ne!(ka, kb, "different root sets");
        assert_ne!(ka, kab, "subset differs from set");
        assert_ne!(ka, k_machine, "policy differs");
        assert!(ka.starts_with("v2:roots:"));
    }

    #[test]
    fn duplicate_roots_collapse() {
        let base = scratch("dupe");
        let a = base.join("a");
        std::fs::create_dir_all(&a).expect("a");
        let once = generation_scope_key("roots", &[explicit(a.clone())]);
        let twice = generation_scope_key("roots", &[explicit(a.clone()), explicit(a)]);
        assert_eq!(once, twice);
    }

    #[cfg(unix)]
    #[test]
    fn spelling_variants_share_key() {
        let base = scratch("spelling");
        let real = base.join("real");
        std::fs::create_dir_all(&real).expect("real");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let via_real = generation_scope_key("roots", &[explicit(real)]);
        let via_link = generation_scope_key("roots", &[explicit(link)]);
        assert_eq!(via_real, via_link);
    }

    #[test]
    fn missing_root_has_stable_lexical_scope_key() {
        let base = scratch("missing-lexical");
        let with_dotdot = base.join("unused").join("..").join("missing");
        let normalized = base.join("missing");
        let first = generation_scope_key("roots", &[explicit(with_dotdot)]);
        let second = generation_scope_key("roots", &[explicit(normalized.clone())]);
        let third = generation_scope_key("roots", &[explicit(normalized)]);
        assert_eq!(
            first, second,
            "lexically equivalent paths share the fallback key"
        );
        assert_eq!(second, third, "the fallback key is deterministic");
    }
}
