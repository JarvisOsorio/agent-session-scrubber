use super::jsonl_common::{
    collect_string_fields, modified_at, read_limited, redaction_token, text_segment,
};
use super::traits::SourceAdapter;
use crate::config::AppConfig;
use crate::errors::{AgentscrubError, Result};
use crate::models::{
    AdapterCapabilities, Finding, ParsedSession, RewriteResult, SegmentType, SessionEvent,
    SourceDocument, SourceFile,
};
use crate::utils::sha256_hex;
use serde_json::Value;
use std::path::Path;
use walkdir::WalkDir;

pub struct GenericJsonAdapter;

impl SourceAdapter for GenericJsonAdapter {
    fn id(&self) -> &'static str {
        "generic_json"
    }

    fn discover(&self, config: &AppConfig) -> Result<Vec<SourceFile>> {
        let mut out = Vec::new();
        for root in &config.discovery.roots {
            if !root.exists() {
                continue;
            }
            for entry in WalkDir::new(root)
                .follow_links(config.discovery.follow_symlinks)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.is_file() && self.identify(path)? {
                    let meta = entry.metadata().ok();
                    out.push(SourceFile {
                        path: path.to_path_buf(),
                        adapter_id: self.id().into(),
                        size_bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                        modified_at: modified_at(path),
                    });
                }
            }
        }
        Ok(out)
    }

    fn identify(&self, path: &Path) -> Result<bool> {
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            return Ok(false);
        }
        let Ok(bytes) = std::fs::read(path) else {
            return Ok(false);
        };
        Ok(serde_json::from_slice::<Value>(&bytes).is_ok())
    }

    fn parse(&self, path: &Path) -> Result<ParsedSession> {
        let bytes = read_limited(path, 64 * 1024 * 1024)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
            AgentscrubError::Validation(format!("invalid JSON {}: {e}", path.display()))
        })?;
        let fields = vec![
            "content".into(),
            "text".into(),
            "message".into(),
            "input".into(),
            "output".into(),
            "prompt".into(),
            "response".into(),
        ];
        let mut pairs = Vec::new();
        collect_string_fields(&value, "", &fields, &mut pairs);
        let content = pairs
            .into_iter()
            .map(|(fp, text)| text_segment(&fp, &text, SegmentType::Unknown))
            .collect();

        Ok(ParsedSession {
            source: self.id().into(),
            session_id: path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string),
            file_path: path.to_path_buf(),
            format_version: Some("generic-json-v1".into()),
            events: vec![SessionEvent {
                event_id: Some("evt-0".into()),
                timestamp: None,
                role: None,
                event_type: "document".into(),
                content,
                metadata: value,
            }],
            original_hash: sha256_hex(&bytes),
            modified_at: modified_at(path),
        })
    }

    fn rewrite(&self, original: &SourceDocument, findings: &[Finding]) -> Result<RewriteResult> {
        let mut value: Value = serde_json::from_slice(&original.original_bytes).map_err(|e| {
            AgentscrubError::Remediation(format!("cannot parse JSON for rewrite: {e}"))
        })?;
        let mut applied = 0usize;
        for finding in findings {
            if apply_offset_redaction(&mut value, finding, &redaction_token(finding)) {
                applied += 1;
            }
        }
        let new_bytes = serde_json::to_vec_pretty(&value).map_err(|e| {
            AgentscrubError::Remediation(format!("cannot serialize redacted JSON: {e}"))
        })?;
        let structure_valid = serde_json::from_slice::<Value>(&new_bytes).is_ok();
        Ok(RewriteResult {
            new_bytes,
            redactions_applied: applied,
            structure_valid,
        })
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            read: true,
            redaction: true,
            deletion: false,
            retention: false,
            structural_verification: true,
        }
    }
}

fn apply_offset_redaction(value: &mut Value, finding: &Finding, token: &str) -> bool {
    fn walk(value: &mut Value, finding: &Finding, token: &str, path: &str) -> bool {
        match value {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    let child = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    if walk(v, finding, token, &child) {
                        return true;
                    }
                }
                false
            }
            Value::Array(arr) => {
                for (i, v) in arr.iter_mut().enumerate() {
                    if walk(v, finding, token, &format!("{path}[{i}]")) {
                        return true;
                    }
                }
                false
            }
            Value::String(s) => {
                if (path == finding.field_path
                    || finding.field_path.ends_with(path)
                    || path.ends_with(&finding.field_path))
                    && finding.end_offset <= s.len()
                    && finding.start_offset < finding.end_offset
                {
                    s.replace_range(finding.start_offset..finding.end_offset, token);
                    return true;
                }
                false
            }
            _ => false,
        }
    }
    walk(value, finding, token, "")
}
