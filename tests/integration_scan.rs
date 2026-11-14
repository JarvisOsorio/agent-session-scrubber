use agentscrub::adapters::AdapterRegistry;
use agentscrub::config::AppConfig;
use agentscrub::detectors::detect_in_session;
use agentscrub::models::SourceDocument;
use agentscrub::remediation::redact::{apply_redaction, RedactionMode};
use agentscrub::remediation::verify::verify_file;
use agentscrub::utils::sha256_hex;
use std::path::PathBuf;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

#[test]
fn scan_claude_fixture_finds_known_secrets() {
    let registry = AdapterRegistry::with_defaults();
    let path = fixture("claude/session_secrets.jsonl");
    let adapter = registry.identify(&path).unwrap().expect("claude adapter");
    assert_eq!(adapter.id(), "claude_code");
    let parsed = adapter.parse(&path).unwrap();
    let cfg = AppConfig::default();
    let findings = detect_in_session(&parsed, &cfg);
    assert!(
        findings
            .iter()
            .any(|f| f.detector_id == "aws_access_key_id"),
        "expected AWS finding, got {:?}",
        findings.iter().map(|f| &f.detector_id).collect::<Vec<_>>()
    );
    assert!(findings.iter().any(|f| f.detector_id == "github_pat"));
    assert!(findings
        .iter()
        .any(|f| f.detector_id == "anthropic_api_key"));
    assert!(findings
        .iter()
        .any(|f| f.detector_id == "stripe_secret_key"));
    assert!(findings.iter().any(|f| f.category == "email"));
    for f in &findings {
        assert!(!f.masked_value.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert_eq!(f.fingerprint.len(), 64);
    }
}

#[test]
fn scan_codex_and_generic_jsonl() {
    let registry = AdapterRegistry::with_defaults();
    let cfg = AppConfig::default();

    let codex = fixture("codex/session_secrets.jsonl");
    let a = registry.identify(&codex).unwrap().unwrap();
    assert_eq!(a.id(), "codex");
    let findings = detect_in_session(&a.parse(&codex).unwrap(), &cfg);
    assert!(findings.iter().any(|f| f.detector_id == "npm_token"));

    let generic = fixture("generic_jsonl/mixed.jsonl");
    let g = registry.identify(&generic).unwrap().unwrap();
    assert!(matches!(g.id(), "generic_jsonl" | "claude_code" | "codex"));
    let findings = detect_in_session(&g.parse(&generic).unwrap(), &cfg);
    assert!(findings
        .iter()
        .any(|f| f.detector_id.contains("github") || f.category == "ssh"));
}

#[test]
fn cursor_jsonl_is_read_only() {
    let registry = AdapterRegistry::with_defaults();
    let path = fixture("cursor/composer_export.jsonl");
    let adapter = registry.identify(&path).unwrap().unwrap();
    assert_eq!(adapter.id(), "cursor");
    assert!(!adapter.capabilities().redaction);
    let parsed = adapter.parse(&path).unwrap();
    let cfg = AppConfig::default();
    let findings = detect_in_session(&parsed, &cfg);
    assert!(!findings.is_empty());
    let bytes = std::fs::read(&path).unwrap();
    let doc = SourceDocument {
        path: path.clone(),
        original_hash: sha256_hex(&bytes),
        original_bytes: bytes,
        parsed,
    };
    let err = apply_redaction(&doc, &adapter, &findings, RedactionMode::DryRun, true).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("read-only") || msg.contains("Unsupported") || msg.contains("rewrite"));
}

#[test]
fn scrub_dry_run_and_confirm_on_temp_claude_fixture() {
    let registry = AdapterRegistry::with_defaults();
    let src = fixture("claude/session_secrets.jsonl");
    let dir = tempfile::tempdir().unwrap();
    // Ensure path hints Claude identification
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let path = claude_dir.join("session_secrets.jsonl");
    std::fs::copy(&src, &path).unwrap();

    let adapter = registry.get("claude_code").unwrap();
    assert!(adapter.identify(&path).unwrap());
    let bytes = std::fs::read(&path).unwrap();
    let parsed = adapter.parse(&path).unwrap();
    let cfg = AppConfig::default();
    let findings = detect_in_session(&parsed, &cfg);
    assert!(!findings.is_empty());
    let doc = SourceDocument {
        path: path.clone(),
        original_hash: sha256_hex(&bytes),
        original_bytes: bytes,
        parsed,
    };

    let (_plan, receipt, rewrite) =
        apply_redaction(&doc, &adapter, &findings, RedactionMode::DryRun, true).unwrap();
    assert!(receipt.unwrap().dry_run);
    assert!(rewrite.unwrap().structure_valid);
    // Original unchanged
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        std::fs::read_to_string(&src).unwrap()
    );

    let (_plan, receipt, _) =
        apply_redaction(&doc, &adapter, &findings, RedactionMode::Confirm, true).unwrap();
    let receipt = receipt.unwrap();
    assert!(!receipt.dry_run);
    assert!(receipt.redactions_applied > 0);

    let verify = verify_file(&path, &cfg, &registry, &[]).unwrap();
    assert!(verify.structure_valid);
    assert!(
        verify.clean && verify.remaining_findings == 0,
        "expected clean verify after confirm scrub, got remaining={} fps={:?}",
        verify.remaining_findings,
        verify.remaining_fingerprints
    );

    let body = std::fs::read_to_string(&path).unwrap();
    for residual in [
        "AKIAIOSFODNN7TESTKEY",
        "IOSFODNN7TESTKEY",
        "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX",
        "sk-proj-abcdefghijklmnopqrstuvwxyz012345",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "sk_test_51HaBcDeFgHiJkLmNoPqRsTu",
        "xoxb-12345678901-123456789012-abcdefghijklmnopqrstuvwx",
    ] {
        assert!(
            !body.contains(residual),
            "residual secret substring still present after scrub: {residual}\n{body}"
        );
    }
    assert!(body.contains("[REDACTED:"));
}

#[test]
fn malformed_jsonl_skips_bad_lines_but_parses_good() {
    let registry = AdapterRegistry::with_defaults();
    let path = fixture("claude/malformed.jsonl");
    let adapter = registry.get("claude_code").unwrap();
    let parsed = adapter.parse(&path).unwrap();
    assert!(parsed.events.len() >= 2);
}

#[test]
fn generic_json_scan() {
    let registry = AdapterRegistry::with_defaults();
    let path = fixture("generic_json/session.json");
    let adapter = registry.identify(&path).unwrap().unwrap();
    assert_eq!(adapter.id(), "generic_json");
    let findings = detect_in_session(&adapter.parse(&path).unwrap(), &AppConfig::default());
    assert!(findings
        .iter()
        .any(|f| f.category == "stripe" || f.category == "email"));
}
