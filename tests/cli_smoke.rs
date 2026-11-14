use assert_cmd::cargo::cargo_bin;
use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

#[test]
fn discover_and_scan_claude_fixture() {
    let path = fixture("claude");

    Command::new(cargo_bin!("agentscrub"))
        .args(["discover", "--path"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("claude_code"));

    Command::new(cargo_bin!("agentscrub"))
        .args(["scan", "--path"])
        .arg(fixture("claude/session_secrets.jsonl"))
        .args(["--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("aws_access_key_id"))
        .stdout(predicate::str::contains("fingerprint"))
        .stdout(predicate::str::contains("masked_value"));
}

#[test]
fn retention_apply_refuses_when_flag_off() {
    let bin = cargo_bin!("agentscrub");
    Command::new(bin)
        .args(["retention", "apply", "--confirm"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("retention.enabled"));
}

#[test]
fn scrub_dry_run_on_temp_copy() {
    let bin = cargo_bin!("agentscrub");
    let dir = tempfile::tempdir().unwrap();
    let claude = dir.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    let dest = claude.join("session.jsonl");
    std::fs::copy(fixture("claude/session_secrets.jsonl"), &dest).unwrap();

    Command::new(bin)
        .args(["scrub", "--path"])
        .arg(&dest)
        .args(["--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dry_run"));
}
