use crate::models::{Confidence, Severity};
use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct SecretRule {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub pattern: &'static str,
}

pub fn secret_rules() -> &'static [SecretRule] {
    &[
        SecretRule {
            id: "aws_access_key_id",
            category: "aws",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            // Non-capturing alternation: find_secrets prefers group 1 when present.
            pattern: r"(?i)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        },
        SecretRule {
            id: "aws_secret_access_key",
            category: "aws",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: r#"(?i)(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
        },
        SecretRule {
            id: "github_pat",
            category: "github",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bghp_[A-Za-z0-9_]{36,}\b",
        },
        SecretRule {
            id: "github_fine_grained_pat",
            category: "github",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        },
        SecretRule {
            id: "github_oauth",
            category: "github",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: r"\bgho_[A-Za-z0-9_]{36,}\b",
        },
        SecretRule {
            id: "anthropic_api_key",
            category: "anthropic",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
        },
        SecretRule {
            id: "openai_api_key",
            category: "openai",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bsk-[A-Za-z0-9]{20,}\b",
        },
        SecretRule {
            id: "openai_project_key",
            category: "openai",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bsk-proj-[A-Za-z0-9_-]{20,}\b",
        },
        SecretRule {
            id: "stripe_secret_key",
            category: "stripe",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b",
        },
        SecretRule {
            id: "stripe_publishable_key",
            category: "stripe",
            severity: Severity::Medium,
            confidence: Confidence::High,
            pattern: r"\bpk_(?:live|test)_[A-Za-z0-9]{16,}\b",
        },
        SecretRule {
            id: "slack_bot_token",
            category: "slack",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bxoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}\b",
        },
        SecretRule {
            id: "slack_user_token",
            category: "slack",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bxoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}\b",
        },
        SecretRule {
            id: "slack_webhook",
            category: "slack",
            severity: Severity::High,
            confidence: Confidence::Certain,
            pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        },
        SecretRule {
            id: "gcp_api_key",
            category: "gcp",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: r"\bAIza[0-9A-Za-z_-]{30,40}\b",
        },
        SecretRule {
            id: "azure_storage_key",
            category: "azure",
            severity: Severity::Critical,
            confidence: Confidence::Medium,
            pattern: r"(?i)AccountKey=([A-Za-z0-9+/=]{40,})",
        },
        SecretRule {
            id: "postgres_url",
            category: "database",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: r#"(?i)\bpostgres(?:ql)?://[^\s"']+"#,
        },
        SecretRule {
            id: "mysql_url",
            category: "database",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: r#"(?i)\bmysql://[^\s"']+"#,
        },
        SecretRule {
            id: "mongodb_url",
            category: "database",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: r#"(?i)\bmongodb(?:\+srv)?://[^\s"']+"#,
        },
        SecretRule {
            id: "redis_url",
            category: "database",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: r#"(?i)\bredis://[^\s"']+"#,
        },
        SecretRule {
            id: "ssh_private_key",
            category: "ssh",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----",
        },
        SecretRule {
            id: "tls_private_key",
            category: "tls",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        },
        SecretRule {
            id: "generic_bearer_token",
            category: "bearer",
            severity: Severity::High,
            confidence: Confidence::Medium,
            pattern: r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]+=*)",
        },
        SecretRule {
            id: "generic_password_assignment",
            category: "password",
            severity: Severity::High,
            confidence: Confidence::Medium,
            pattern: r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]"#,
        },
        SecretRule {
            id: "jwt_token",
            category: "jwt",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        },
        SecretRule {
            id: "npm_token",
            category: "npm",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bnpm_[A-Za-z0-9]{36,}\b",
        },
        SecretRule {
            id: "huggingface_token",
            category: "huggingface",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bhf_[A-Za-z0-9]{30,}\b",
        },
        SecretRule {
            id: "sendgrid_api_key",
            category: "sendgrid",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            pattern: r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
        },
        SecretRule {
            id: "twilio_account_sid",
            category: "twilio",
            severity: Severity::Medium,
            confidence: Confidence::High,
            pattern: r"\bAC[0-9a-fA-F]{32}\b",
        },
    ]
}

struct CompiledRule {
    rule: SecretRule,
    regex: Regex,
}

fn compiled_rules() -> &'static [CompiledRule] {
    static RULES: OnceLock<Vec<CompiledRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        secret_rules()
            .iter()
            .map(|rule| CompiledRule {
                rule: rule.clone(),
                regex: Regex::new(rule.pattern)
                    .unwrap_or_else(|e| panic!("invalid secret regex for {}: {e}", rule.id)),
            })
            .collect()
    })
}

#[derive(Debug, Clone)]
pub struct RawMatch {
    pub detector_id: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub start: usize,
    pub end: usize,
    pub value: String,
}

pub fn find_secrets(text: &str) -> Vec<RawMatch> {
    let mut out = Vec::new();
    for compiled in compiled_rules() {
        for caps in compiled.regex.captures_iter(text) {
            // Prefer an intentional secret-body capture (group 1) when it spans most of
            // the match (e.g. password=VALUE). Never use tiny alternation groups like
            // (AKIA|ASIA) or (live|test) as the redaction span.
            let full = caps.get(0).expect("regex match");
            let m = caps
                .get(1)
                .filter(|g1| g1.as_str().len() * 2 >= full.as_str().len())
                .unwrap_or(full);
            let value = m.as_str().to_string();
            if is_placeholder(&value) {
                continue;
            }
            out.push(RawMatch {
                detector_id: compiled.rule.id.to_string(),
                category: compiled.rule.category.to_string(),
                severity: compiled.rule.severity,
                confidence: compiled.rule.confidence,
                start: m.start(),
                end: m.end(),
                value,
            });
        }
    }
    out
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    if lower == "password" || lower == "secret" {
        return true;
    }
    if lower.contains("placeholder")
        || lower.contains("your_api_key")
        || lower.contains("redacted")
        || lower.contains("example")
    {
        return true;
    }
    // Only treat as placeholder when the value is mostly literal x's.
    let alnum: String = lower
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if alnum.len() >= 8 {
        let x_count = alnum.chars().filter(|c| *c == 'x').count();
        if x_count * 100 / alnum.len() >= 70 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_and_github() {
        let text = "key=AKIAIOSFODNN7EXAMPLA token=ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let hits = find_secrets(text);
        assert!(hits.iter().any(|h| h.detector_id == "aws_access_key_id"));
        assert!(hits.iter().any(|h| h.detector_id == "github_pat"));
    }

    #[test]
    fn aws_and_stripe_spans_cover_full_secret_not_alternation() {
        let text = "AKIAIOSFODNN7TESTKEY and sk_test_51HaBcDeFgHiJkLmNoPqRsTu";
        let hits = find_secrets(text);
        let aws = hits
            .iter()
            .find(|h| h.detector_id == "aws_access_key_id")
            .expect("aws");
        assert_eq!(aws.value, "AKIAIOSFODNN7TESTKEY");
        let stripe = hits
            .iter()
            .find(|h| h.detector_id == "stripe_secret_key")
            .expect("stripe");
        assert_eq!(stripe.value, "sk_test_51HaBcDeFgHiJkLmNoPqRsTu");
    }

    #[test]
    fn rule_count_at_least_20() {
        assert!(secret_rules().len() >= 20);
    }
}
