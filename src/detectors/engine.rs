use super::pii::find_pii;
use super::secrets::find_secrets;
use crate::config::AppConfig;
use crate::models::{Confidence, Finding, ParsedSession};
use crate::utils::{finding_id, fingerprint_value, mask_secret};
use std::collections::HashSet;

pub struct DetectionEngine<'a> {
    pub config: &'a AppConfig,
}

impl<'a> DetectionEngine<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        Self { config }
    }

    pub fn scan_session(&self, session: &ParsedSession) -> Vec<Finding> {
        detect_in_session(session, self.config)
    }
}

pub fn detect_in_session(session: &ParsedSession, config: &AppConfig) -> Vec<Finding> {
    let min_conf = parse_min_confidence(&config.detection.min_confidence);
    let allow: HashSet<String> = config.detection.allowlist.iter().cloned().collect();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for event in &session.events {
        for segment in &event.content {
            let mut raw = find_secrets(&segment.text);
            if config.detection.enable_pii {
                raw.extend(find_pii(&segment.text));
            }

            for m in raw {
                if m.confidence < min_conf {
                    continue;
                }
                if allow.contains(&m.value) || allow.contains(&m.detector_id) {
                    continue;
                }

                let fingerprint = fingerprint_value(&config.hmac_key, &m.value);
                let dedup_key = format!(
                    "{}|{}|{}|{}|{}",
                    session.file_path.display(),
                    segment.field_path,
                    m.detector_id,
                    m.start,
                    fingerprint
                );
                if !seen.insert(dedup_key) {
                    continue;
                }

                let id = finding_id(
                    &fingerprint,
                    &session.file_path.display().to_string(),
                    &segment.field_path,
                    m.start,
                );

                findings.push(Finding {
                    id,
                    detector_id: m.detector_id,
                    category: m.category,
                    severity: m.severity,
                    confidence: m.confidence,
                    source: session.source.clone(),
                    file_path: session.file_path.display().to_string(),
                    event_id: event.event_id.clone(),
                    field_path: segment.field_path.clone(),
                    start_offset: m.start,
                    end_offset: m.end,
                    fingerprint,
                    masked_value: mask_secret(&m.value),
                });
            }
        }
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity) // critical first
            .then(a.file_path.cmp(&b.file_path))
            .then(a.start_offset.cmp(&b.start_offset))
    });
    findings
}

fn parse_min_confidence(s: &str) -> Confidence {
    match s.to_lowercase().as_str() {
        "certain" => Confidence::Certain,
        "high" => Confidence::High,
        "low" => Confidence::Low,
        _ => Confidence::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ContentSegment, SegmentType, SessionEvent};
    use std::path::PathBuf;

    #[test]
    fn masks_and_fingerprints_without_raw() {
        let cfg = AppConfig::default();
        let session = ParsedSession {
            source: "test".into(),
            session_id: None,
            file_path: PathBuf::from("t.jsonl"),
            format_version: None,
            events: vec![SessionEvent {
                event_id: Some("evt-0".into()),
                timestamp: None,
                role: Some("user".into()),
                event_type: "message".into(),
                content: vec![ContentSegment {
                    field_path: "content".into(),
                    text: "my key is sk-ant-api03-abcdefghijklmnopqrstuv".into(),
                    segment_type: SegmentType::UserMessage,
                }],
                metadata: serde_json::Value::Null,
            }],
            original_hash: "abc".into(),
            modified_at: None,
        };
        let findings = detect_in_session(&session, &cfg);
        assert!(!findings.is_empty());
        for f in findings {
            assert!(!f.masked_value.contains("abcdefghijklmnopqrstuv"));
            assert_eq!(f.fingerprint.len(), 64);
        }
    }
}
