use crate::models::{Finding, ScanSummary, Severity, SeverityCounts, SkipRecord};
use crate::remediation::redact::{RedactionPlan, RedactionReceipt};
use comfy_table::{presets::UTF8_FULL, Table};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use std::io::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
    pub skipped: Vec<SkipRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubReport {
    pub plans: Vec<RedactionPlan>,
    pub receipts: Vec<RedactionReceipt>,
}

pub fn summarize(
    findings: &[Finding],
    discovered: usize,
    scanned: usize,
    skipped: usize,
    incomplete: bool,
) -> ScanSummary {
    let mut by_severity = SeverityCounts::default();
    for f in findings {
        by_severity.increment(f.severity);
    }
    ScanSummary {
        files_discovered: discovered,
        files_scanned: scanned,
        files_skipped: skipped,
        findings: findings.len(),
        by_severity,
        incomplete,
    }
}

pub fn print_terminal_scan(report: &ScanReport, include_masked: bool) {
    println!("{}", "agentscrub scan".bold());
    println!(
        "discovered={} scanned={} skipped={} findings={} incomplete={}",
        report.summary.files_discovered,
        report.summary.files_scanned,
        report.summary.files_skipped,
        report.summary.findings,
        report.summary.incomplete
    );
    println!(
        "severity: critical={} high={} medium={} low={} info={}",
        report.summary.by_severity.critical,
        report.summary.by_severity.high,
        report.summary.by_severity.medium,
        report.summary.by_severity.low,
        report.summary.by_severity.informational
    );

    if !report.findings.is_empty() {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        if include_masked {
            table.set_header(vec![
                "sev",
                "conf",
                "detector",
                "source",
                "file",
                "masked",
                "fingerprint",
            ]);
        } else {
            table.set_header(vec![
                "sev",
                "conf",
                "detector",
                "source",
                "file",
                "fingerprint",
            ]);
        }
        for f in &report.findings {
            let sev = colorize_severity(f.severity);
            if include_masked {
                table.add_row(vec![
                    sev,
                    f.confidence.as_str().to_string(),
                    f.detector_id.clone(),
                    f.source.clone(),
                    short_path(&f.file_path),
                    f.masked_value.clone(),
                    f.fingerprint[..12].to_string(),
                ]);
            } else {
                table.add_row(vec![
                    sev,
                    f.confidence.as_str().to_string(),
                    f.detector_id.clone(),
                    f.source.clone(),
                    short_path(&f.file_path),
                    f.fingerprint[..12].to_string(),
                ]);
            }
        }
        println!("{table}");
    }

    if !report.skipped.is_empty() {
        println!("{}", "skipped:".yellow());
        for s in &report.skipped {
            println!("  {} — {}", s.path, s.reason);
        }
    }
}

pub fn print_json(value: &impl Serialize) -> crate::errors::Result<()> {
    let out = serde_json::to_string_pretty(value)
        .map_err(|e| crate::errors::AgentscrubError::Validation(format!("json encode: {e}")))?;
    println!("{out}");
    Ok(())
}

pub fn write_json_file(
    path: &std::path::Path,
    value: &impl Serialize,
) -> crate::errors::Result<()> {
    let out = serde_json::to_vec_pretty(value)
        .map_err(|e| crate::errors::AgentscrubError::Validation(format!("json encode: {e}")))?;
    let mut f =
        std::fs::File::create(path).map_err(|source| crate::errors::AgentscrubError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    f.write_all(&out)
        .map_err(|source| crate::errors::AgentscrubError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

pub fn to_markdown(report: &ScanReport) -> String {
    let mut md = String::new();
    md.push_str("# agentscrub scan report\n\n");
    md.push_str(&format!(
        "- discovered: {}\n- scanned: {}\n- skipped: {}\n- findings: {}\n- incomplete: {}\n\n",
        report.summary.files_discovered,
        report.summary.files_scanned,
        report.summary.files_skipped,
        report.summary.findings,
        report.summary.incomplete
    ));
    md.push_str("| Severity | Confidence | Detector | Source | File | Fingerprint |\n");
    md.push_str("|---|---|---|---|---|---|\n");
    for f in &report.findings {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            f.severity.as_str(),
            f.confidence.as_str(),
            f.detector_id,
            f.source,
            f.file_path,
            &f.fingerprint[..16]
        ));
    }
    md
}

fn short_path(path: &str) -> String {
    if path.len() <= 48 {
        path.to_string()
    } else {
        format!("…{}", &path[path.len() - 47..])
    }
}

fn colorize_severity(sev: Severity) -> String {
    match sev {
        Severity::Critical => "critical".red().to_string(),
        Severity::High => "high".bright_red().to_string(),
        Severity::Medium => "medium".yellow().to_string(),
        Severity::Low => "low".blue().to_string(),
        Severity::Informational => "info".white().to_string(),
    }
}
