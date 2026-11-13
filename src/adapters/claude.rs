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
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct ClaudeCodeAdapter;

impl SourceAdapter for ClaudeCodeAdapter {
    fn id(&self) -> &'static str {
        "claude_code"
    }

    fn discover(&self, config: &AppConfig) -> Result<Vec<SourceFile>> {
        let mut out = Vec::new();
        for root in &config.discovery.roots {
            if !root.exists() {
                continue;
            }
            // Claude Code typically stores under ~/.claude/projects/**/*.jsonl
            let walker = WalkDir::new(root).follow_links(config.discovery.follow_symlinks);
            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if self.identify(path)? {
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
        // Heuristic: path contains claude markers OR first valid line has Claude-ish shape.
        let path_s = path.to_string_lossy().to_lowercase();
        let path_hint = path_s.contains("claude") || path_s.contains(".claude");

        let Ok(bytes) = std::fs::read(path) else {
            return Ok(false);
        };
        if bytes.len() > 64 * 1024 * 1024 {
            return Ok(false);
        }
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines().take(20) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            if looks_like_claude(&v) {
                return Ok(true);
            }
            // Under Claude dirs, JSONL objects with role/content are accepted.
            if path_hint
                && v.is_object()
                && (v.get("message").is_some()
                    || v.get("role").is_some()
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
            Some("claude-jsonl-v1".into()),
            session_id,
            |value, idx| {
                let role = value
                    .get("role")
                    .and_then(|r| r.as_str())
                    .or_else(|| value.get("type").and_then(|t| t.as_str()))
                    .map(str::to_string);

                let event_type = value
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("message")
                    .to_string();

                let mut content = Vec::new();

                if let Some(msg) = value.get("message") {
                    extract_claude_content(msg, &format!("line[{idx}].message"), &mut content);
                }
                if let Some(c) = value.get("content") {
                    extract_claude_content(c, &format!("line[{idx}].content"), &mut content);
                }
                if let Some(tool_use) = value.get("tool_use") {
                    if let Some(input) = tool_use.get("input") {
                        let s = serde_json::to_string(input).unwrap_or_default();
                        content.push(text_segment(
                            &format!("line[{idx}].tool_use.input"),
                            &s,
                            SegmentType::ToolInput,
                        ));
                    }
                }
                if let Some(tool_result) = value.get("tool_result") {
                    let s = match tool_result {
                        Value::String(t) => t.clone(),
                        other => serde_json::to_string(other).unwrap_or_default(),
                    };
                    content.push(text_segment(
                        &format!("line[{idx}].tool_result"),
                        &s,
                        SegmentType::ToolOutput,
                    ));
                }

                // Flat content string
                if content.is_empty() {
                    if let Some(s) = value.get("text").and_then(|t| t.as_str()) {
                        content.push(text_segment(
                            &format!("line[{idx}].text"),
                            s,
                            SegmentType::Unknown,
                        ));
                    }
                }

                if content.is_empty() {
                    return None;
                }

                Some(SessionEvent {
                    event_id: Some(format!("evt-{idx}")),
                    timestamp: value.get("timestamp").and_then(|t| {
                        t.as_i64()
                            .or_else(|| t.as_str().and_then(|s| s.parse().ok()))
                    }),
                    role,
                    event_type,
                    content,
                    metadata: value.clone(),
                })
            },
        )
    }

    fn rewrite(&self, original: &SourceDocument, findings: &[Finding]) -> Result<RewriteResult> {
        if !self.capabilities().redaction {
            return Err(crate::errors::AgentscrubError::Unsupported(
                "claude_code rewrite unavailable".into(),
            ));
        }
        rewrite_jsonl_bytes(original, findings, |_matched, finding| {
            redaction_token(finding)
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

fn looks_like_claude(v: &Value) -> bool {
    // Prefer Claude-specific envelope: top-level type + message object with content blocks.
    let has_message_obj = v
        .get("message")
        .and_then(|m| m.as_object())
        .is_some_and(|m| m.contains_key("content") || m.contains_key("role"));
    let has_type = v.get("type").and_then(|t| t.as_str()).is_some_and(|t| {
        matches!(
            t,
            "user" | "assistant" | "system" | "tool_use" | "tool_result"
        )
    });
    has_message_obj && has_type
}

fn extract_claude_content(
    value: &Value,
    prefix: &str,
    out: &mut Vec<crate::models::ContentSegment>,
) {
    match value {
        Value::String(s) => {
            out.push(text_segment(prefix, s, SegmentType::Unknown));
        }
        Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                let path = format!("{prefix}[{i}]");
                if let Some(t) = item.get("type").and_then(|t| t.as_str()) {
                    match t {
                        "text" => {
                            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                                out.push(text_segment(
                                    &format!("{path}.text"),
                                    text,
                                    SegmentType::AssistantMessage,
                                ));
                            }
                        }
                        "tool_use" => {
                            if let Some(input) = item.get("input") {
                                let s = serde_json::to_string(input).unwrap_or_default();
                                out.push(text_segment(
                                    &format!("{path}.input"),
                                    &s,
                                    SegmentType::ToolInput,
                                ));
                            }
                        }
                        "tool_result" => {
                            let s = item
                                .get("content")
                                .map(|c| match c {
                                    Value::String(t) => t.clone(),
                                    other => serde_json::to_string(other).unwrap_or_default(),
                                })
                                .unwrap_or_default();
                            out.push(text_segment(
                                &format!("{path}.content"),
                                &s,
                                SegmentType::ToolOutput,
                            ));
                        }
                        _ => {
                            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                                out.push(text_segment(
                                    &format!("{path}.text"),
                                    text,
                                    SegmentType::Unknown,
                                ));
                            }
                        }
                    }
                } else if let Value::String(s) = item {
                    out.push(text_segment(&path, s, SegmentType::Unknown));
                }
            }
        }
        Value::Object(map) => {
            if let Some(Value::String(s)) = map.get("content") {
                out.push(text_segment(
                    &format!("{prefix}.content"),
                    s,
                    SegmentType::UserMessage,
                ));
            }
            if let Some(Value::String(s)) = map.get("text") {
                out.push(text_segment(
                    &format!("{prefix}.text"),
                    s,
                    SegmentType::Unknown,
                ));
            }
            if let Some(arr) = map.get("content").and_then(|c| c.as_array()) {
                extract_claude_content(
                    &Value::Array(arr.clone()),
                    &format!("{prefix}.content"),
                    out,
                );
            }
        }
        _ => {}
    }
}

pub fn default_claude_roots(home: &Path) -> Vec<PathBuf> {
    vec![home.join(".claude"), home.join(".config/claude")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_and_parses_fixture() {
        let path = Path::new("tests/fixtures/claude/session_secrets.jsonl");
        if !path.exists() {
            return;
        }
        let adapter = ClaudeCodeAdapter;
        assert!(adapter.identify(path).unwrap());
        let parsed = adapter.parse(path).unwrap();
        assert!(!parsed.events.is_empty());
        assert_eq!(parsed.source, "claude_code");
    }
}
