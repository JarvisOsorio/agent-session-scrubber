use super::jsonl_common::{modified_at, parse_jsonl_lines, text_segment};
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

/// Cursor adapter: identifies JSONL composer exports and SQLite `state.vscdb`-style stores.
/// SQLite rewrite stays disabled (read-only) until proven safe.
pub struct CursorAdapter;

impl SourceAdapter for CursorAdapter {
    fn id(&self) -> &'static str {
        "cursor"
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
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        let path_s = path.to_string_lossy().to_lowercase();

        if (name.ends_with(".vscdb")
            || name == "state.vscdb"
            || name.ends_with(".sqlite")
            || name.ends_with(".db"))
            && (path_s.contains("cursor") || looks_like_sqlite(path))
        {
            return Ok(is_sqlite_file(path));
        }

        if path.extension().and_then(|e| e.to_str()) == Some("jsonl")
            && (path_s.contains("cursor") || name.contains("composer"))
        {
            return Ok(true);
        }

        // Versioned fixture marker
        if path_s.contains("fixtures/cursor") {
            if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                return Ok(true);
            }
            if is_sqlite_file(path) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn parse(&self, path: &Path) -> Result<ParsedSession> {
        if is_sqlite_file(path) {
            return parse_cursor_sqlite(path, self.id());
        }
        parse_jsonl_lines(
            path,
            self.id(),
            Some("cursor-jsonl-v1".into()),
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string),
            |value, idx| {
                let mut content = Vec::new();
                if let Some(s) = value.get("text").and_then(|t| t.as_str()) {
                    content.push(text_segment(
                        &format!("line[{idx}].text"),
                        s,
                        SegmentType::Unknown,
                    ));
                }
                if let Some(s) = value.get("content").and_then(|c| c.as_str()) {
                    content.push(text_segment(
                        &format!("line[{idx}].content"),
                        s,
                        SegmentType::Unknown,
                    ));
                }
                if let Some(bubble) = value.get("bubble") {
                    if let Some(s) = bubble.get("text").and_then(|t| t.as_str()) {
                        content.push(text_segment(
                            &format!("line[{idx}].bubble.text"),
                            s,
                            SegmentType::AssistantMessage,
                        ));
                    }
                }
                if content.is_empty() {
                    return None;
                }
                Some(SessionEvent {
                    event_id: Some(format!("evt-{idx}")),
                    timestamp: None,
                    role: value
                        .get("type")
                        .and_then(|t| t.as_str())
                        .map(str::to_string),
                    event_type: "cursor_message".into(),
                    content,
                    metadata: value.clone(),
                })
            },
        )
    }

    fn rewrite(&self, _original: &SourceDocument, _findings: &[Finding]) -> Result<RewriteResult> {
        Err(AgentscrubError::Unsupported(
            "cursor rewrite is read-only in v0.1.0 (SQLite/transcript rewrite not yet proven safe)"
                .into(),
        ))
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            read: true,
            redaction: false, // capability-gated until rewrite proven
            deletion: false,
            retention: false,
            structural_verification: false,
        }
    }
}

fn is_sqlite_file(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let mut header = [0u8; 16];
    if f.read_exact(&mut header).is_err() {
        return false;
    }
    &header == b"SQLite format 3\0"
}

fn looks_like_sqlite(path: &Path) -> bool {
    is_sqlite_file(path)
}

fn parse_cursor_sqlite(path: &Path, source: &str) -> Result<ParsedSession> {
    let bytes = std::fs::read(path).map_err(|source_err| AgentscrubError::Io {
        path: path.to_path_buf(),
        source: source_err,
    })?;
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| {
        AgentscrubError::Validation(format!("cannot open SQLite {}: {e}", path.display()))
    })?;

    let mut events = Vec::new();
    // Cursor/VSCode state DBs often store ItemTable(key TEXT, value BLOB)
    let table_exists: bool = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='ItemTable'")
        .and_then(|mut s| s.exists([]))
        .unwrap_or(false);

    if table_exists {
        let mut stmt = conn
            .prepare("SELECT key, value FROM ItemTable")
            .map_err(|e| AgentscrubError::Validation(format!("ItemTable prepare failed: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                let key: String = row.get(0)?;
                let value: Vec<u8> = row.get(1)?;
                Ok((key, value))
            })
            .map_err(|e| AgentscrubError::Validation(format!("ItemTable query failed: {e}")))?;

        for (idx, row) in rows.enumerate() {
            let (key, value) =
                row.map_err(|e| AgentscrubError::Validation(format!("ItemTable row error: {e}")))?;
            let text = String::from_utf8_lossy(&value).to_string();
            if text.is_empty() {
                continue;
            }
            events.push(SessionEvent {
                event_id: Some(format!("row-{idx}")),
                timestamp: None,
                role: None,
                event_type: "cursor_kv".into(),
                content: vec![text_segment(
                    &format!("ItemTable[{key}].value"),
                    &text,
                    SegmentType::Metadata,
                )],
                metadata: serde_json::json!({ "key": key }),
            });
        }
    } else {
        // Fallback: scan all text-ish columns from user tables (read-only).
        let mut tables_stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .map_err(|e| AgentscrubError::Validation(format!("schema query failed: {e}")))?;
        let tables: Vec<String> = tables_stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| AgentscrubError::Validation(format!("schema map failed: {e}")))?
            .filter_map(|r| r.ok())
            .collect();

        for table in tables {
            let sql = format!("SELECT * FROM \"{table}\" LIMIT 1000");
            let Ok(mut stmt) = conn.prepare(&sql) else {
                continue;
            };
            let column_names: Vec<String> = stmt.column_names().map(|s| s.to_string()).collect();
            let mut rows = match stmt.query([]) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let mut row_idx = 0usize;
            while let Ok(Some(row)) = rows.next() {
                for (col_i, col_name) in column_names.iter().enumerate() {
                    if let Ok(text) = row.get::<_, String>(col_i) {
                        if text.len() >= 8 {
                            events.push(SessionEvent {
                                event_id: Some(format!("{table}-{row_idx}")),
                                timestamp: None,
                                role: None,
                                event_type: "cursor_row".into(),
                                content: vec![text_segment(
                                    &format!("{table}.{col_name}"),
                                    &text,
                                    SegmentType::Unknown,
                                )],
                                metadata: Value::Null,
                            });
                        }
                    } else if let Ok(blob) = row.get::<_, Vec<u8>>(col_i) {
                        if let Ok(text) = std::str::from_utf8(&blob) {
                            if text.len() >= 8 {
                                events.push(SessionEvent {
                                    event_id: Some(format!("{table}-{row_idx}")),
                                    timestamp: None,
                                    role: None,
                                    event_type: "cursor_blob".into(),
                                    content: vec![text_segment(
                                        &format!("{table}.{col_name}"),
                                        text,
                                        SegmentType::Unknown,
                                    )],
                                    metadata: Value::Null,
                                });
                            }
                        }
                    }
                }
                row_idx += 1;
            }
        }
    }

    if events.is_empty() {
        return Err(AgentscrubError::Validation(format!(
            "no readable text rows in Cursor SQLite {}",
            path.display()
        )));
    }

    Ok(ParsedSession {
        source: source.into(),
        session_id: path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string),
        file_path: path.to_path_buf(),
        format_version: Some("cursor-sqlite-v1".into()),
        events,
        original_hash: sha256_hex(&bytes),
        modified_at: modified_at(path),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_jsonl_fixture() {
        let path = Path::new("tests/fixtures/cursor/composer_export.jsonl");
        if !path.exists() {
            return;
        }
        assert!(CursorAdapter.identify(path).unwrap());
    }
}
