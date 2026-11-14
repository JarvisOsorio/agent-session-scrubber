//! Redaction safety: structure preservation, failed validation, hash recheck.
use agentscrub::adapters::{AdapterRegistry, SourceAdapter};
use agentscrub::config::AppConfig;
use agentscrub::detectors::detect_in_session;
use agentscrub::models::{Finding, RewriteResult, Severity, SourceDocument};
use agentscrub::remediation::redact::{apply_redaction, RedactionMode};
use agentscrub::remediation::verify::verify_file;
use agentscrub::utils::sha256_hex;
use std::path::PathBuf;
use std::sync::Arc;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

fn temp_claude_copy() -> (tempfile::TempDir, PathBuf, Arc<dyn SourceAdapter>) {
    let dir = tempfile::tempdir().unwrap();
    let claude = dir.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    let path = claude.join("session.jsonl");
    std::fs::copy(fixture("claude/session_secrets.jsonl"), &path).unwrap();
    let registry = AdapterRegistry::with_defaults();
    let adapter = registry.get("claude_code").unwrap();
    (dir, path, adapter)
}

fn doc_for(path: &PathBuf, adapter: &Arc<dyn SourceAdapter>) -> (SourceDocument, Vec<Finding>) {
    let bytes = std::fs::read(path).unwrap();
    let parsed = adapter.parse(path).unwrap();
    let findings = detect_in_session(&parsed, &AppConfig::default());
    (
        SourceDocument {
            path: path.clone(),
            original_hash: sha256_hex(&bytes),
            original_bytes: bytes,
            parsed,
        },
        findings,
    )
}

#[test]
fn confirm_redaction_preserves_valid_jsonl_structure() {
    let (_dir, path, adapter) = temp_claude_copy();
    let (doc, findings) = doc_for(&path, &adapter);
    assert!(!findings.is_empty());

    let (_plan, receipt, rewrite) =
        apply_redaction(&doc, &adapter, &findings, RedactionMode::Confirm, true).unwrap();
    let rewrite = rewrite.unwrap();
    assert!(rewrite.structure_valid);
    assert!(receipt.unwrap().redactions_applied > 0);

    let text = std::fs::read_to_string(&path).unwrap();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("invalid JSONL after redaction: {e} :: {line}"));
    }
    assert!(
        text.contains("[REDACTED:"),
        "expected redaction tokens in output"
    );
}

#[test]
fn invalid_rewrite_does_not_replace_original() {
    struct BrokenAdapter;
    impl SourceAdapter for BrokenAdapter {
        fn id(&self) -> &'static str {
            "broken"
        }
        fn discover(
            &self,
            _: &AppConfig,
        ) -> agentscrub::errors::Result<Vec<agentscrub::models::SourceFile>> {
            Ok(vec![])
        }
        fn identify(&self, _: &std::path::Path) -> agentscrub::errors::Result<bool> {
            Ok(false)
        }
        fn parse(
            &self,
            _: &std::path::Path,
        ) -> agentscrub::errors::Result<agentscrub::models::ParsedSession> {
            unreachable!()
        }
        fn rewrite(
            &self,
            _: &SourceDocument,
            _: &[Finding],
        ) -> agentscrub::errors::Result<RewriteResult> {
            Ok(RewriteResult {
                new_bytes: b"{not valid jsonl\n".to_vec(),
                redactions_applied: 1,
                structure_valid: false,
            })
        }
        fn capabilities(&self) -> agentscrub::models::AdapterCapabilities {
            agentscrub::models::AdapterCapabilities {
                read: true,
                redaction: true,
                deletion: false,
                retention: false,
                structural_verification: true,
            }
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keep.jsonl");
    let original = "{\"role\":\"user\",\"content\":\"hello\"}\n";
    std::fs::write(&path, original).unwrap();
    let bytes = original.as_bytes().to_vec();
    let doc = SourceDocument {
        path: path.clone(),
        original_hash: sha256_hex(&bytes),
        original_bytes: bytes,
        parsed: agentscrub::models::ParsedSession {
            source: "broken".into(),
            session_id: None,
            file_path: path.clone(),
            format_version: None,
            events: vec![],
            original_hash: sha256_hex(original.as_bytes()),
            modified_at: None,
        },
    };
    let finding = Finding {
        id: "fnd_test".into(),
        detector_id: "test".into(),
        category: "test".into(),
        severity: Severity::High,
        confidence: agentscrub::models::Confidence::High,
        source: "broken".into(),
        file_path: path.display().to_string(),
        event_id: None,
        field_path: "content".into(),
        start_offset: 0,
        end_offset: 1,
        fingerprint: "abc".into(),
        masked_value: "a***".into(),
    };
    let adapter: Arc<dyn SourceAdapter> = Arc::new(BrokenAdapter);
    let err =
        apply_redaction(&doc, &adapter, &[finding], RedactionMode::Confirm, false).unwrap_err();
    assert!(err.to_string().contains("structural validation"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
}

#[test]
fn concurrent_hash_change_refuses_write() {
    let (_dir, path, adapter) = temp_claude_copy();
    let (mut doc, findings) = doc_for(&path, &adapter);
    assert!(!findings.is_empty());

    // Simulate TOCTOU: file changes after scan hash was captured.
    doc.original_hash = "0".repeat(64);
    let err = apply_redaction(&doc, &adapter, &findings, RedactionMode::Confirm, true).unwrap_err();
    assert!(
        err.to_string().contains("hash mismatch") || err.to_string().contains("changed since scan"),
        "unexpected error: {err}"
    );
    // Original fixture content still present (copy was not replaced with redacted body).
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(body.contains("AKIAIOSFODNN7TESTKEY"));
}

#[test]
fn dry_run_does_not_modify_file() {
    let (_dir, path, adapter) = temp_claude_copy();
    let before = std::fs::read(&path).unwrap();
    let (doc, findings) = doc_for(&path, &adapter);
    let (_plan, receipt, _) =
        apply_redaction(&doc, &adapter, &findings, RedactionMode::DryRun, true).unwrap();
    assert!(receipt.unwrap().dry_run);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

/// Regression: multi-finding / nested tool_use redaction must leave zero supported secrets.
#[test]
fn confirm_scrub_claude_fixture_verify_clean() {
    let registry = AdapterRegistry::with_defaults();
    let (_dir, path, adapter) = temp_claude_copy();
    let (doc, findings) = doc_for(&path, &adapter);
    assert!(
        findings.len() >= 4,
        "fixture should yield multiple findings, got {}",
        findings.len()
    );

    apply_redaction(&doc, &adapter, &findings, RedactionMode::Confirm, true).unwrap();

    let verify = verify_file(&path, &AppConfig::default(), &registry, &[]).unwrap();
    assert_eq!(
        verify.remaining_findings, 0,
        "expected remaining_findings=0, got {} ({:?})",
        verify.remaining_findings, verify.remaining_fingerprints
    );
    assert!(verify.clean);
    assert!(verify.structure_valid);

    let body = std::fs::read_to_string(&path).unwrap();
    assert!(!body.contains("sk-ant-"));
    assert!(!body.contains("sk-proj-"));
    assert!(!body.contains("AKIA"));
    assert!(!body.contains("ghp_"));
}
