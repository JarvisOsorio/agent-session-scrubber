use crate::adapters::AdapterRegistry;
use crate::config::AppConfig;
use crate::detectors::detect_in_session;
use crate::errors::{AgentscrubError, Result};
use crate::models::Finding;
use crate::utils::sha256_hex;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub file_path: String,
    pub adapter_id: Option<String>,
    pub hash: String,
    pub remaining_findings: usize,
    pub remaining_fingerprints: Vec<String>,
    pub structure_valid: bool,
    pub clean: bool,
}

pub fn verify_file(
    path: &Path,
    config: &AppConfig,
    registry: &AdapterRegistry,
    expected_absent: &[String],
) -> Result<VerificationResult> {
    let adapter = registry.identify(path)?.ok_or_else(|| {
        AgentscrubError::Unsupported(format!(
            "cannot verify unrecognized file {}",
            path.display()
        ))
    })?;

    let bytes = std::fs::read(path).map_err(|source| AgentscrubError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let hash = sha256_hex(&bytes);
    let parsed = adapter.parse(path)?;
    let findings = detect_in_session(&parsed, config);

    let remaining: Vec<&Finding> = if expected_absent.is_empty() {
        findings.iter().collect()
    } else {
        findings
            .iter()
            .filter(|f| expected_absent.iter().any(|fp| fp == &f.fingerprint))
            .collect()
    };

    let structure_valid = if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
        String::from_utf8_lossy(&bytes)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .all(|l| serde_json::from_str::<serde_json::Value>(l).is_ok())
    } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
        serde_json::from_slice::<serde_json::Value>(&bytes).is_ok()
    } else {
        true
    };

    Ok(VerificationResult {
        file_path: path.display().to_string(),
        adapter_id: Some(adapter.id().into()),
        hash,
        remaining_findings: remaining.len(),
        remaining_fingerprints: remaining.iter().map(|f| f.fingerprint.clone()).collect(),
        structure_valid,
        clean: remaining.is_empty() && structure_valid,
    })
}
