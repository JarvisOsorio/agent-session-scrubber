use crate::errors::{AgentscrubError, Result};
use crate::models::{
    ContentSegment, Finding, ParsedSession, RewriteResult, SegmentType, SessionEvent,
    SourceDocument,
};
use crate::utils::sha256_hex;
use serde_json::Value;
use std::path::Path;

pub fn read_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).map_err(|source| AgentscrubError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.len() > max_bytes {
        return Err(AgentscrubError::Validation(format!(
            "file exceeds max size ({} > {}): {}",
            meta.len(),
            max_bytes,
            path.display()
        )));
    }
    std::fs::read(path).map_err(|source| AgentscrubError::Io {
        path: path.to_path_buf(),
        source,
    })
}

pub fn modified_at(path: &Path) -> Option<i64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

pub fn parse_jsonl_lines(
    path: &Path,
    source: &str,
    format_version: Option<String>,
    session_id: Option<String>,
    extract: impl Fn(&Value, usize) -> Option<SessionEvent>,
) -> Result<ParsedSession> {
    let bytes = read_limited(path, 64 * 1024 * 1024)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut events = Vec::new();
    let mut malformed = 0usize;

    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(value) => {
                if let Some(event) = extract(&value, idx) {
                    events.push(event);
                }
            }
            Err(_) => {
                malformed += 1;
                tracing::warn!(
                    path = %path.display(),
                    line = idx + 1,
                    "skipping malformed JSONL line"
                );
            }
        }
    }

    if events.is_empty() && malformed > 0 {
        return Err(AgentscrubError::Validation(format!(
            "no valid JSONL events in {} (malformed lines: {malformed})",
            path.display()
        )));
    }

    Ok(ParsedSession {
        source: source.to_string(),
        session_id,
        file_path: path.to_path_buf(),
        format_version,
        events,
        original_hash: sha256_hex(&bytes),
        modified_at: modified_at(path),
    })
}

pub fn text_segment(field_path: &str, text: &str, segment_type: SegmentType) -> ContentSegment {
    ContentSegment {
        field_path: field_path.to_string(),
        text: text.to_string(),
        segment_type,
    }
}

pub fn collect_string_fields(
    value: &Value,
    prefix: &str,
    wanted: &[String],
    out: &mut Vec<(String, String)>,
) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                if let Value::String(s) = v {
                    let leaf = k.as_str();
                    if wanted.iter().any(|w| w == leaf || w == &path) {
                        out.push((path, s.clone()));
                    }
                } else {
                    collect_string_fields(v, &path, wanted, out);
                }
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                collect_string_fields(v, &format!("{prefix}[{i}]"), wanted, out);
            }
        }
        _ => {}
    }
}

/// Apply redactions to JSONL by re-detecting on every string leaf and replacing
/// matches right-to-left. Stored finding offsets are not trusted across edits —
/// overlapping replacements previously left residual secrets.
pub fn rewrite_jsonl_bytes(
    original: &SourceDocument,
    findings: &[Finding],
    _redact: impl Fn(&str, &Finding) -> String,
) -> Result<RewriteResult> {
    let _ = findings; // caller gates empty findings; rewrite remediates all detections in-file
    let text = String::from_utf8_lossy(&original.original_bytes);
    let mut lines_out = Vec::new();
    let mut applied = 0usize;

    for line in text.lines() {
        if line.trim().is_empty() {
            lines_out.push(line.to_string());
            continue;
        }
        let mut value: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                lines_out.push(line.to_string());
                continue;
            }
        };

        applied += redact_all_string_leaves(&mut value);

        lines_out.push(serde_json::to_string(&value).map_err(|e| {
            AgentscrubError::Remediation(format!("failed to serialize redacted JSONL: {e}"))
        })?);
    }

    let new_text = if text.ends_with('\n') {
        format!("{}\n", lines_out.join("\n"))
    } else {
        lines_out.join("\n")
    };

    let mut structure_valid = true;
    for line in new_text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if serde_json::from_str::<Value>(line).is_err() {
            structure_valid = false;
            break;
        }
    }

    Ok(RewriteResult {
        new_bytes: new_text.into_bytes(),
        redactions_applied: applied,
        structure_valid,
    })
}

fn redact_all_string_leaves(value: &mut Value) -> usize {
    match value {
        Value::Object(map) => map.values_mut().map(redact_all_string_leaves).sum(),
        Value::Array(arr) => arr.iter_mut().map(redact_all_string_leaves).sum(),
        Value::String(s) => {
            let (next, n) = redact_text_in_place(s);
            *s = next;
            n
        }
        _ => 0,
    }
}

/// Re-detect secrets + PII on `text`, drop overlapping matches, replace right-to-left.
fn redact_text_in_place(text: &str) -> (String, usize) {
    use crate::detectors::pii::find_pii;
    use crate::detectors::secrets::find_secrets;
    use crate::models::Confidence;

    let mut matches = find_secrets(text);
    matches.extend(find_pii(text));
    matches.retain(|m| m.confidence >= Confidence::Medium);
    if matches.is_empty() {
        return (text.to_string(), 0);
    }

    // Prefer longer, higher-severity spans when overlaps collide.
    matches.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| a.start.cmp(&b.start))
    });

    let mut selected: Vec<(usize, usize, String)> = Vec::new();
    for m in &matches {
        let overlaps = selected.iter().any(|(s, e, _)| m.start < *e && m.end > *s);
        if !overlaps {
            selected.push((m.start, m.end, m.category.clone()));
        }
    }

    // Apply from the end so earlier byte offsets stay valid.
    selected.sort_by_key(|a| std::cmp::Reverse(a.0));
    let mut out = text.to_string();
    let mut applied = 0usize;
    for (start, end, category) in selected {
        if end > out.len() || start >= end {
            continue;
        }
        if out.is_char_boundary(start) && out.is_char_boundary(end) {
            let token = format!("[REDACTED:{}]", category.to_uppercase());
            out.replace_range(start..end, &token);
            applied += 1;
        }
    }
    (out, applied)
}

pub fn redaction_token(finding: &Finding) -> String {
    format!("[REDACTED:{}]", finding.category.to_uppercase())
}

/// Redact string leaves inside a generic JSON document (same engine as JSONL).
pub fn redact_json_value(value: &mut Value) -> usize {
    redact_all_string_leaves(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_multiple_secrets_right_to_left_without_residue() {
        let text = "AWS AKIAIOSFODNN7TESTKEY and Anthropic sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX and openai sk-proj-abcdefghijklmnopqrstuvwxyz012345";
        let (out, n) = redact_text_in_place(text);
        assert!(n >= 3, "expected >=3 redactions, got {n}: {out}");
        assert!(!out.contains("AKIAIOSFODNN7TESTKEY"));
        assert!(!out.contains("sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX"));
        assert!(!out.contains("sk-proj-abcdefghijklmnopqrstuvwxyz012345"));
        assert!(out.contains("[REDACTED:"));
    }
}
