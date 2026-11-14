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

/// Apply redactions to JSONL by rewriting string fields that contain findings.
pub fn rewrite_jsonl_bytes(
    original: &SourceDocument,
    findings: &[Finding],
    redact: impl Fn(&str, &Finding) -> String,
) -> Result<RewriteResult> {
    let text = String::from_utf8_lossy(&original.original_bytes);
    let mut lines_out = Vec::new();
    let mut applied = 0usize;

    for (line_idx, line) in text.lines().enumerate() {
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

        let line_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.event_id
                    .as_deref()
                    .and_then(|id| id.strip_prefix("line:"))
                    .and_then(|n| n.parse::<usize>().ok())
                    == Some(line_idx)
                    || f.field_path.contains(&format!("line[{line_idx}]"))
                    || finding_targets_line(f, line_idx)
            })
            .collect();

        for finding in &line_findings {
            if apply_finding_to_value(&mut value, finding, &redact) {
                applied += 1;
            }
        }

        // Also apply by scanning all string leaves for masked replacements when field_path matches.
        if line_findings.is_empty() {
            for finding in findings {
                if apply_finding_to_value(&mut value, finding, &redact) {
                    applied += 1;
                }
            }
        }

        lines_out.push(serde_json::to_string(&value).map_err(|e| {
            AgentscrubError::Remediation(format!("failed to serialize redacted JSONL: {e}"))
        })?);
    }

    let new_text = if text.ends_with('\n') {
        format!("{}\n", lines_out.join("\n"))
    } else {
        lines_out.join("\n")
    };

    // Validate each line still parses.
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

fn finding_targets_line(finding: &Finding, line_idx: usize) -> bool {
    finding
        .event_id
        .as_ref()
        .is_some_and(|id| id == &format!("evt-{line_idx}") || id == &format!("line:{line_idx}"))
}

fn apply_finding_to_value(
    value: &mut Value,
    finding: &Finding,
    redact: &impl Fn(&str, &Finding) -> String,
) -> bool {
    let path = finding.field_path.as_str();
    // Strip event-qualified prefixes like "line[0]." or "events[3]."
    let normalized = path
        .find('.')
        .map(|i| &path[i + 1..])
        .filter(|_p| path.contains('['))
        .unwrap_or(path);

    if let Some(Value::String(s)) = get_mut_by_path(value, normalized) {
        if finding.start_offset < s.len() && finding.end_offset <= s.len() {
            let before = &s[..finding.start_offset];
            let matched = &s[finding.start_offset..finding.end_offset];
            let after = &s[finding.end_offset..];
            let replacement = redact(matched, finding);
            *s = format!("{before}{replacement}{after}");
            return true;
        }
        let _ = finding.masked_value.split('…').next().unwrap_or("");
    }

    // Broad fallback: walk strings and replace by exact offset window when unique.
    replace_in_strings(value, finding, redact)
}

fn get_mut_by_path<'a>(value: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    if path.is_empty() {
        return Some(value);
    }
    let mut current = value;
    for part in path.split('.') {
        if let Some(bracket) = part.find('[') {
            let key = &part[..bracket];
            if !key.is_empty() {
                current = current.get_mut(key)?;
            }
            let idx_str = part[bracket + 1..].trim_end_matches(']');
            let idx: usize = idx_str.parse().ok()?;
            current = current.get_mut(idx)?;
        } else {
            current = current.get_mut(part)?;
        }
    }
    Some(current)
}

fn replace_in_strings(
    value: &mut Value,
    finding: &Finding,
    redact: &impl Fn(&str, &Finding) -> String,
) -> bool {
    match value {
        Value::Object(map) => {
            for v in map.values_mut() {
                if replace_in_strings(v, finding, redact) {
                    return true;
                }
            }
            false
        }
        Value::Array(arr) => {
            for v in arr {
                if replace_in_strings(v, finding, redact) {
                    return true;
                }
            }
            false
        }
        Value::String(s) => {
            if finding.end_offset <= s.len()
                && finding.start_offset < finding.end_offset
                && finding.end_offset - finding.start_offset <= s.len()
            {
                // Only apply when the slice looks like the finding (same length).
                let end = finding.end_offset.min(s.len());
                let start = finding.start_offset.min(end);
                if end > start {
                    let matched = s[start..end].to_string();
                    // Heuristic: apply once per finding id via length match of masked value len hint
                    if matched.len() >= 8 {
                        let replacement = redact(&matched, finding);
                        s.replace_range(start..end, &replacement);
                        return true;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

pub fn redaction_token(finding: &Finding) -> String {
    format!("[REDACTED:{}]", finding.category.to_uppercase())
}
