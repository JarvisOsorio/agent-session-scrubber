use super::jsonl_common::{
    collect_string_fields, modified_at, parse_jsonl_lines, redaction_token, rewrite_jsonl_bytes,
    text_segment,
};
use super::traits::SourceAdapter;
use crate::config::AppConfig;
use crate::errors::Result;
use crate::models::{
    AdapterCapabilities, Finding, ParsedSession, RewriteResult, SegmentType, SessionEvent,
    SourceDocument, SourceFile,
};
use serde_json::Value;
use std::path::Path;
use std::sync::OnceLock;
use walkdir::WalkDir;

pub struct GenericJsonlAdapter;

static FORCE_GENERIC: OnceLock<bool> = OnceLock::new();

/// When scanning with `--format jsonl`, prefer this adapter for .jsonl files.
pub fn set_force_generic_jsonl(force: bool) {
    let _ = FORCE_GENERIC.set(force);
}

fn force_generic() -> bool {
    *FORCE_GENERIC.get().unwrap_or(&false)
}

impl SourceAdapter for GenericJsonlAdapter {
    fn id(&self) -> &'static str {
        "generic_jsonl"
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
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            return Ok(false);
        }
        // Specific adapters claim first via registry order; this is a catch-all
        // for JSONL that isn't Claude/Codex, or when forced.
        if force_generic() {
            return Ok(true);
        }
        let Ok(bytes) = std::fs::read(path) else {
            return Ok(false);
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut objects = 0usize;
        for line in text.lines().take(30) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(trimmed) {
                Ok(v) if v.is_object() || v.is_array() => objects += 1,
                Ok(_) => {}
                Err(_) => {}
            }
        }
        Ok(objects > 0)
    }

    fn parse(&self, path: &Path) -> Result<ParsedSession> {
        let fields = default_text_fields();
        parse_jsonl_lines(
            path,
            self.id(),
            Some("generic-jsonl-v1".into()),
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string),
            |value, idx| {
                let mut pairs = Vec::new();
                collect_string_fields(value, "", &fields, &mut pairs);
                if pairs.is_empty() {
                    // Fallback: top-level stringification of content-like keys already empty
                    return None;
                }
                let content = pairs
                    .into_iter()
                    .map(|(fp, text)| {
                        text_segment(&format!("line[{idx}].{fp}"), &text, SegmentType::Unknown)
                    })
                    .collect();
                Some(SessionEvent {
                    event_id: Some(format!("evt-{idx}")),
                    timestamp: value.get("timestamp").and_then(|t| t.as_i64()),
                    role: value
                        .get("role")
                        .and_then(|r| r.as_str())
                        .map(str::to_string),
                    event_type: "record".into(),
                    content,
                    metadata: value.clone(),
                })
            },
        )
    }

    fn rewrite(&self, original: &SourceDocument, findings: &[Finding]) -> Result<RewriteResult> {
        rewrite_jsonl_bytes(original, findings, |_m, f| redaction_token(f))
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

fn default_text_fields() -> Vec<String> {
    vec![
        "content".into(),
        "text".into(),
        "message".into(),
        "input".into(),
        "output".into(),
        "prompt".into(),
        "response".into(),
    ]
}
