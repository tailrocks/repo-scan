//! Shared deterministic fixture builders (spec §§17–18, acceptance FS/GIT/STATUS).
//!
//! Every builder shells out to the installed `git` binary with a hermetic
//! config environment (no user/system config, fixed identity) plus
//! `tempfile` scratch roots. Builders panic with the failing command and its
//! stderr on setup failure: a broken fixture is a loud test error, never a
//! silent skip.
//!
//! `tests/fixtures_impl.rs` asserts every builder produces the layout it
//! claims. Benches cannot import this module (integration-test scope), so
//! `benches/support.rs` carries its own minimal copy of the git runner.

pub mod fixture;
