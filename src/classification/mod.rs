use crate::models::{Confidence, Finding, Severity};

/// Risk classification helpers — severity/confidence already assigned by detectors;
/// this module normalizes and can bump/downgrade based on context later.
pub fn normalize_finding(mut finding: Finding) -> Finding {
    if finding.category == "credit_card" && finding.confidence == Confidence::High {
        finding.severity = Severity::Critical;
    }
    if finding.category == "email" && finding.severity > Severity::Medium {
        // Cap email at medium unless policy says otherwise.
        finding.severity = Severity::Medium;
    }
    finding
}

pub fn classify_all(findings: Vec<Finding>) -> Vec<Finding> {
    findings.into_iter().map(normalize_finding).collect()
}
