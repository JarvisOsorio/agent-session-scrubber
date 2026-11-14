use super::jsonl_common::{
    modified_at, parse_jsonl_lines, redaction_token, rewrite_jsonl_bytes, text_segment,
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
use walkdir::WalkDir;

pub struct CodexAdapter;

impl SourceAdapter for CodexAdapter {
    fn id(&self) -> &'static str {
        "codex"
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
        let path_s = path.to_string_lossy().to_lowercase();
        let path_hint = path_s.contains("codex") || path_s.contains(".codex");

        let Ok(bytes) = std::fs::read(path) else {
            return Ok(false);
        };
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines().take(20) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            if looks_like_codex(&v) {
                return Ok(true);
            }
            if path_hint
                && v.is_object()
                && (v.get("role").is_some()
                    || v.get("content").is_some()
                    || v.get("type").is_some())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn parse(&self, path: &Path) -> Result<ParsedSession> {
        let session_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string);

        parse_jsonl_lines(
            path,
            self.id(),
            Some("codex-jsonl-v1".into()),
            session_id,
            |value, idx| {
                let role = value
                    .get("role")
                    .and_then(|r| r.as_str())
                    .map(str::to_string);
                let event_type = value
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("message")
                    .to_string();

                let mut content = Vec::new();
                if let Some(s) = value.get("content").and_then(|c| c.as_str()) {
                    content.push(text_segment(
                        &format!("line[{idx}].content"),
                        s,
                        segment_for_role(role.as_deref()),
                    ));
                }
                if let Some(arr) = value.get("content").and_then(|c| c.as_array()) {
                    for (i, item) in arr.iter().enumerate() {
                        if let Some(t) = item.get("text").and_then(|t| t.as_str()) {
                            content.push(text_segment(
                                &format!("line[{idx}].content[{i}].text"),
                                t,
                                SegmentType::Unknown,
                            ));
                        }
                    }
                }
                if let Some(s) = value.get("text").and_then(|t| t.as_str()) {
                    content.push(text_segment(
                        &format!("line[{idx}].text"),
                        s,
                        SegmentType::Unknown,
                    ));
                }
                if let Some(input) = value.get("tool_input").or_else(|| value.get("arguments")) {
                    let s = match input {
                        Value::String(t) => t.clone(),
                        other => serde_json::to_string(other).unwrap_or_default(),
                    };
                    content.push(text_segment(
                        &format!("line[{idx}].tool_input"),
                        &s,
                        SegmentType::ToolInput,
                    ));
                }
                if let Some(output) = value.get("tool_output").or_else(|| value.get("output")) {
                    let s = match output {
                        Value::String(t) => t.clone(),
                        other => serde_json::to_string(other).unwrap_or_default(),
                    };
                    content.push(text_segment(
                        &format!("line[{idx}].tool_output"),
                        &s,
                        SegmentType::ToolOutput,
                    ));
                }

                if content.is_empty() {
                    return None;
                }

                Some(SessionEvent {
                    event_id: Some(format!("evt-{idx}")),
                    timestamp: value.get("timestamp").and_then(|t| t.as_i64()),
                    role,
                    event_type,
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

fn looks_like_codex(v: &Value) -> bool {
    // Codex-specific event types, or path-hinted flat role/content records.
    v.get("type")
        .and_then(|t| t.as_str())
        .is_some_and(|t| t.starts_with("response.") || t == "tool_call" || t == "session_meta")
        || (v.get("tool_input").is_some() && v.get("tool_output").is_some())
}

fn segment_for_role(role: Option<&str>) -> SegmentType {
    match role {
        Some("user") => SegmentType::UserMessage,
        Some("assistant") => SegmentType::AssistantMessage,
        Some("system") => SegmentType::SystemPrompt,
        Some("tool") => SegmentType::ToolOutput,
        _ => SegmentType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_fixture() {
        let path = Path::new("tests/fixtures/codex/session_secrets.jsonl");
        if !path.exists() {
            return;
        }
        assert!(CodexAdapter.identify(path).unwrap());
    }
}
