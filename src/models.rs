use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSession {
    pub source: String,
    pub session_id: Option<String>,
    pub file_path: PathBuf,
    pub format_version: Option<String>,
    pub events: Vec<SessionEvent>,
    pub original_hash: String,
    pub modified_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    pub event_id: Option<String>,
    pub timestamp: Option<i64>,
    pub role: Option<String>,
    pub event_type: String,
    pub content: Vec<ContentSegment>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSegment {
    pub field_path: String,
    pub text: String,
    pub segment_type: SegmentType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentType {
    UserMessage,
    AssistantMessage,
    SystemPrompt,
    ToolInput,
    ToolOutput,
    FileContent,
    Metadata,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub detector_id: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub source: String,
    pub file_path: String,
    pub event_id: Option<String>,
    pub field_path: String,
    pub start_offset: usize,
    pub end_offset: usize,
    pub fingerprint: String,
    pub masked_value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    // Ordered low → high for comparisons; display order is handled separately.
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Informational => "informational",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    // Ordered low → high so PartialOrd matches “at least this confident”.
    Low,
    Medium,
    High,
    Certain,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Certain => "certain",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: PathBuf,
    pub adapter_id: String,
    pub size_bytes: u64,
    pub modified_at: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct AdapterCapabilities {
    pub read: bool,
    pub redaction: bool,
    pub deletion: bool,
    pub retention: bool,
    pub structural_verification: bool,
}

#[derive(Debug, Clone)]
pub struct SourceDocument {
    pub path: PathBuf,
    pub original_bytes: Vec<u8>,
    pub original_hash: String,
    pub parsed: ParsedSession,
}

#[derive(Debug, Clone)]
pub struct RewriteResult {
    pub new_bytes: Vec<u8>,
    pub redactions_applied: usize,
    pub structure_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkipRecord {
    pub path: String,
    pub reason: String,
    pub adapter_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files_discovered: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub findings: usize,
    pub by_severity: SeverityCounts,
    pub incomplete: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}

impl SeverityCounts {
    pub fn increment(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Informational => self.informational += 1,
        }
    }
}
