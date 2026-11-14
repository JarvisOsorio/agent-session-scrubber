use crate::models::{Confidence, Severity};
use regex::Regex;
use std::sync::OnceLock;

use super::secrets::RawMatch;

struct PiiRule {
    id: &'static str,
    category: &'static str,
    severity: Severity,
    confidence: Confidence,
    pattern: &'static str,
}

fn pii_rules() -> &'static [PiiRule] {
    &[
        PiiRule {
            id: "email_address",
            category: "email",
            severity: Severity::Medium,
            confidence: Confidence::High,
            pattern: r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        },
        PiiRule {
            id: "phone_number",
            category: "phone",
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            pattern: r"(?i)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        },
        PiiRule {
            id: "ipv4_address",
            category: "ip",
            severity: Severity::Low,
            confidence: Confidence::High,
            pattern: r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        },
        PiiRule {
            id: "ipv6_address",
            category: "ip",
            severity: Severity::Low,
            confidence: Confidence::Medium,
            pattern: r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",
        },
        PiiRule {
            id: "credit_card",
            category: "credit_card",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: r"\b(?:\d[ -]*?){13,19}\b",
        },
    ]
}

struct CompiledPii {
    rule: &'static PiiRule,
    regex: Regex,
}

fn compiled() -> &'static [CompiledPii] {
    static RULES: OnceLock<Vec<CompiledPii>> = OnceLock::new();
    RULES.get_or_init(|| {
        pii_rules()
            .iter()
            .map(|rule| CompiledPii {
                rule,
                regex: Regex::new(rule.pattern).expect("valid pii regex"),
            })
            .collect()
    })
}

pub fn find_pii(text: &str) -> Vec<RawMatch> {
    let mut out = Vec::new();
    for c in compiled() {
        for m in c.regex.find_iter(text) {
            let value = m.as_str().to_string();
            if c.rule.id == "credit_card" {
                let digits: String = value.chars().filter(|ch| ch.is_ascii_digit()).collect();
                if digits.len() < 13 || digits.len() > 19 || !luhn_ok(&digits) {
                    continue;
                }
                // Avoid matching plain timestamps / order ids without separators when low entropy
                if digits.chars().all(|d| d == '0') {
                    continue;
                }
            }
            if c.rule.id == "phone_number" {
                let digits: String = value.chars().filter(|ch| ch.is_ascii_digit()).collect();
                if digits.len() < 10 {
                    continue;
                }
            }
            if c.rule.id == "ipv4_address" {
                // Skip 0.0.0.0 and version-like noise optionally kept
                if value.starts_with("0.") {
                    continue;
                }
            }
            out.push(RawMatch {
                detector_id: c.rule.id.to_string(),
                category: c.rule.category.to_string(),
                severity: c.rule.severity,
                confidence: c.rule.confidence,
                start: m.start(),
                end: m.end(),
                value,
            });
        }
    }
    out
}

fn luhn_ok(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for ch in digits.chars().rev() {
        let mut n = ch.to_digit(10).unwrap_or(0);
        if alt {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_email_and_luhn_card() {
        let text = "contact user@example.com card 4111111111111111";
        let hits = find_pii(text);
        assert!(hits.iter().any(|h| h.detector_id == "email_address"));
        assert!(hits.iter().any(|h| h.detector_id == "credit_card"));
    }

    #[test]
    fn rejects_bad_luhn() {
        let text = "card 4111111111111112";
        let hits = find_pii(text);
        assert!(!hits.iter().any(|h| h.detector_id == "credit_card"));
    }
}
