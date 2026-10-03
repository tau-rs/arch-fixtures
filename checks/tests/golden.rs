//! Runs the harness over every `golden/<repo>/` directory.
//!
//! A repo with no golden data reports "awaiting data" and passes. A repo with a `facts.json` is loaded
//! through `load_golden` and must satisfy every invariant that facts alone can decide; the ones that
//! read views hold trivially until `views/` exists.

use std::path::PathBuf;

use arch_fixtures_checks::{check_all, load_golden, LoadError};

fn golden_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../golden")
}

#[test]
fn every_golden_repo_satisfies_the_invariants() {
    let mut dirs: Vec<_> = std::fs::read_dir(golden_root())
        .expect("golden/ exists")
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .map(|e| e.path())
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "golden/ has no repo directories");
    let mut failures = Vec::new();
    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        match load_golden(&dir) {
            Ok(input) => {
                let report = check_all(&input);
                if !report.is_clean() {
                    failures.push(format!("{name}:\n{report}"));
                }
            }
            Err(LoadError::AwaitingData) => eprintln!("{name}: awaiting data"),
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
