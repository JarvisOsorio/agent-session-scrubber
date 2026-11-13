use crate::config::AppConfig;
use crate::errors::{AgentscrubError, Result};
use crate::models::SourceFile;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RetentionAction {
    Keep,
    Redact,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionDecision {
    pub path: String,
    pub action: RetentionAction,
    pub reason: String,
    pub age_days: Option<u64>,
    pub timestamp_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPlan {
    pub enabled: bool,
    pub max_age_days: u64,
    pub decisions: Vec<RetentionDecision>,
    pub would_delete: usize,
    pub refused_mixed_age: usize,
}

pub fn ensure_retention_enabled(config: &AppConfig) -> Result<()> {
    if !config.retention.enabled {
        return Err(AgentscrubError::Policy(
            "retention.enabled = false; deletion/apply is refused until the feature flag is enabled and safety tests pass"
                .into(),
        ));
    }
    Ok(())
}

pub fn retention_status(config: &AppConfig) -> String {
    format!(
        "retention.enabled={} max_age_days={}",
        config.retention.enabled, config.retention.max_age_days
    )
}

/// Read-only retention plan. Never deletes. When the feature flag is off, every
/// file is KEEP. Mixed-age / uncertain timestamps are treated conservatively
/// (KEEP with explanation) rather than DELETE.
pub fn plan_retention(config: &AppConfig, files: &[SourceFile]) -> RetentionPlan {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut decisions = Vec::new();
    let mut would_delete = 0usize;
    let mut refused_mixed_age = 0usize;

    for file in files {
        let (age_days, ts_source, uncertain) = age_for_file(file, now);
        let decision = if !config.retention.enabled {
            RetentionDecision {
                path: file.path.display().to_string(),
                action: RetentionAction::Keep,
                reason: "retention.enabled=false; plan is informational only".into(),
                age_days,
                timestamp_source: ts_source,
            }
        } else if uncertain {
            refused_mixed_age += 1;
            RetentionDecision {
                path: file.path.display().to_string(),
                action: RetentionAction::Keep,
                reason: "uncertain/mixed-age timestamp; refusing destructive action".into(),
                age_days,
                timestamp_source: ts_source,
            }
        } else if age_days.is_some_and(|d| d > config.retention.max_age_days) {
            would_delete += 1;
            RetentionDecision {
                path: file.path.display().to_string(),
                action: RetentionAction::Delete,
                reason: format!(
                    "age_days={} exceeds max_age_days={}",
                    age_days.unwrap_or(0),
                    config.retention.max_age_days
                ),
                age_days,
                timestamp_source: ts_source,
            }
        } else {
            RetentionDecision {
                path: file.path.display().to_string(),
                action: RetentionAction::Keep,
                reason: "within retention window".into(),
                age_days,
                timestamp_source: ts_source,
            }
        };
        decisions.push(decision);
    }

    RetentionPlan {
        enabled: config.retention.enabled,
        max_age_days: config.retention.max_age_days,
        decisions,
        would_delete,
        refused_mixed_age,
    }
}

fn age_for_file(file: &SourceFile, now: i64) -> (Option<u64>, String, bool) {
    match file.modified_at {
        Some(ts) if ts > 0 && ts <= now => {
            let age = ((now - ts) as u64) / 86_400;
            (Some(age), "mtime".into(), false)
        }
        Some(ts) if ts > now => (None, "mtime_future".into(), true),
        Some(_) => (None, "mtime_invalid".into(), true),
        None => (None, "missing".into(), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn file(path: &str, modified_at: Option<i64>) -> SourceFile {
        SourceFile {
            path: PathBuf::from(path),
            adapter_id: "generic_jsonl".into(),
            size_bytes: 10,
            modified_at,
        }
    }

    #[test]
    fn plan_is_keep_when_flag_off() {
        let cfg = AppConfig::default();
        assert!(!cfg.retention.enabled);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let old = now - (200 * 86_400);
        let plan = plan_retention(&cfg, &[file("old.jsonl", Some(old))]);
        assert_eq!(plan.would_delete, 0);
        assert!(plan
            .decisions
            .iter()
            .all(|d| d.action == RetentionAction::Keep));
    }

    #[test]
    fn apply_gate_refuses_when_disabled() {
        let cfg = AppConfig::default();
        let err = ensure_retention_enabled(&cfg).unwrap_err();
        assert!(matches!(err, AgentscrubError::Policy(_)));
    }

    #[test]
    fn uncertain_timestamps_keep_when_enabled() {
        let mut cfg = AppConfig::default();
        cfg.retention.enabled = true;
        cfg.retention.max_age_days = 30;
        let plan = plan_retention(
            &cfg,
            &[
                file("no-ts.jsonl", None),
                file("future.jsonl", Some(i64::MAX / 2)),
            ],
        );
        assert_eq!(plan.refused_mixed_age, 2);
        assert_eq!(plan.would_delete, 0);
        assert!(plan
            .decisions
            .iter()
            .all(|d| d.action == RetentionAction::Keep));
    }

    #[test]
    fn old_files_marked_delete_only_when_enabled() {
        let mut cfg = AppConfig::default();
        cfg.retention.enabled = true;
        cfg.retention.max_age_days = 30;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let old = now - (90 * 86_400);
        let young = now - (5 * 86_400);
        let plan = plan_retention(
            &cfg,
            &[
                file("old.jsonl", Some(old)),
                file("young.jsonl", Some(young)),
            ],
        );
        assert_eq!(plan.would_delete, 1);
        assert_eq!(plan.decisions[0].action, RetentionAction::Delete);
        assert_eq!(plan.decisions[1].action, RetentionAction::Keep);
    }
}
