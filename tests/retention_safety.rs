//! Retention safety: plan is read-only; apply refuses when disabled.
use agentscrub::config::AppConfig;
use agentscrub::errors::AgentscrubError;
use agentscrub::models::SourceFile;
use agentscrub::policy::{ensure_retention_enabled, plan_retention, RetentionAction};
use assert_cmd::cargo::cargo_bin;
use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn source(path: &str, modified_at: Option<i64>) -> SourceFile {
    SourceFile {
        path: PathBuf::from(path),
        adapter_id: "generic_jsonl".into(),
        size_bytes: 1,
        modified_at,
    }
}

#[test]
fn plan_never_deletes_when_flag_off_even_for_old_files() {
    let cfg = AppConfig::default();
    assert!(!cfg.retention.enabled);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ancient = now - (365 * 86_400);
    let plan = plan_retention(
        &cfg,
        &[
            source("a.jsonl", Some(ancient)),
            source("b.jsonl", Some(ancient)),
            source("c.jsonl", None),
        ],
    );
    assert!(!plan.enabled);
    assert_eq!(plan.would_delete, 0);
    assert!(plan
        .decisions
        .iter()
        .all(|d| d.action == RetentionAction::Keep));
}

#[test]
fn mixed_age_uncertain_mtime_stays_keep_when_enabled() {
    let mut cfg = AppConfig::default();
    cfg.retention.enabled = true;
    cfg.retention.max_age_days = 14;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let plan = plan_retention(
        &cfg,
        &[
            source("known-old.jsonl", Some(now - 90 * 86_400)),
            source("no-mtime.jsonl", None),
            source("future.jsonl", Some(now + 86_400)),
        ],
    );
    assert_eq!(plan.would_delete, 1);
    assert_eq!(plan.refused_mixed_age, 2);
    assert_eq!(plan.decisions[0].action, RetentionAction::Delete);
    assert_eq!(plan.decisions[1].action, RetentionAction::Keep);
    assert_eq!(plan.decisions[2].action, RetentionAction::Keep);
}

#[test]
fn ensure_apply_refuses_when_disabled() {
    let err = ensure_retention_enabled(&AppConfig::default()).unwrap_err();
    match err {
        AgentscrubError::Policy(msg) => assert!(msg.contains("retention.enabled")),
        other => panic!("expected Policy, got {other}"),
    }
}

#[test]
fn cli_retention_plan_is_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("session.jsonl");
    std::fs::write(&file, "{\"text\":\"hi\"}\n").unwrap();
    let before = std::fs::metadata(&file).unwrap().modified().unwrap();

    Command::new(cargo_bin!("agentscrub"))
        .args(["retention", "plan", "--path"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("retention plan"));

    let after = std::fs::metadata(&file).unwrap().modified().unwrap();
    assert_eq!(before, after);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "{\"text\":\"hi\"}\n"
    );
}

#[test]
fn cli_retention_apply_refuses_without_flag() {
    Command::new(cargo_bin!("agentscrub"))
        .args(["retention", "apply", "--confirm"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("retention.enabled"));
}
