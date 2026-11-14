use super::{Cli, Commands, ConfigCommands, OutputFormat, RetentionCommands};
use crate::adapters::generic_jsonl::set_force_generic_jsonl;
use crate::adapters::AdapterRegistry;
use crate::classification::classify_all;
use crate::config::AppConfig;
use crate::detectors::detect_in_session;
use crate::discovery::{discover, discover_paths};
use crate::errors::{AgentscrubError, ExitCode, Result};
use crate::models::{Finding, SkipRecord, SourceDocument};
use crate::normalization::normalize_session;
use crate::policy::{ensure_retention_enabled, plan_retention, retention_status};
use crate::remediation::redact::{apply_redaction, RedactionMode};
use crate::remediation::verify::verify_file;
use crate::reporting::{
    print_json, print_terminal_scan, summarize, to_markdown, write_json_file, ScanReport,
    ScrubReport,
};
use crate::utils::sha256_hex;
use std::path::PathBuf;

pub fn run(cli: Cli) -> Result<ExitCode> {
    let mut config = AppConfig::load(cli.config.as_deref())?;
    if !cli.paths.is_empty() {
        // When paths provided, use them as roots / explicit targets.
        config = config.with_roots(cli.paths.clone());
    }
    let registry = AdapterRegistry::with_defaults();

    match &cli.command {
        Commands::Discover { adapter } => {
            cmd_discover(&cli, &config, &registry, adapter.as_deref())
        }
        Commands::Scan {
            adapter,
            force_format,
        } => {
            if force_format.as_deref() == Some("jsonl") {
                set_force_generic_jsonl(true);
            }
            cmd_scan(&cli, &config, &registry, adapter.as_deref())
        }
        Commands::Report { from } => cmd_report(&cli, &config, &registry, from.clone()),
        Commands::Scrub {
            adapter,
            confirm,
            no_backup,
        } => cmd_scrub(
            &cli,
            &config,
            &registry,
            adapter.as_deref(),
            *confirm,
            !*no_backup,
        ),
        Commands::Verify {
            files,
            fingerprints,
        } => cmd_verify(&cli, &config, &registry, files, fingerprints),
        Commands::Retention { action } => cmd_retention(&cli, &config, action.clone()),
        Commands::Config { action } => cmd_config(&cli, &config, action.clone()),
    }
}

fn cmd_discover(
    cli: &Cli,
    config: &AppConfig,
    registry: &AdapterRegistry,
    adapter_filter: Option<&str>,
) -> Result<ExitCode> {
    let result = if !cli.paths.is_empty() {
        discover_paths(&cli.paths, config, registry)?
    } else {
        discover(config, registry)?
    };
    let files: Vec<_> = result
        .files
        .into_iter()
        .filter(|f| adapter_filter.is_none_or(|id| f.adapter_id == id))
        .collect();

    match cli.format {
        OutputFormat::Json => {
            print_json(&serde_json::json!({
                "files": files,
                "skipped": result.skipped,
            }))?;
        }
        OutputFormat::Markdown => {
            println!("# discover\n");
            for f in &files {
                println!("- `{}` ({})", f.path.display(), f.adapter_id);
            }
        }
        OutputFormat::Terminal => {
            println!("discovered {} file(s)", files.len());
            for f in &files {
                println!(
                    "  [{}] {} ({} bytes)",
                    f.adapter_id,
                    f.path.display(),
                    f.size_bytes
                );
            }
            for s in &result.skipped {
                println!("  skip: {} — {}", s.path, s.reason);
            }
        }
    }
    Ok(ExitCode::Ok)
}

type ScanBatch = (
    Vec<(SourceDocument, Vec<Finding>)>,
    Vec<SkipRecord>,
    usize,
    bool,
);

fn scan_targets(
    cli: &Cli,
    config: &AppConfig,
    registry: &AdapterRegistry,
    adapter_filter: Option<&str>,
) -> Result<ScanBatch> {
    let discovered = if !cli.paths.is_empty() {
        discover_paths(&cli.paths, config, registry)?
    } else {
        discover(config, registry)?
    };

    let mut scanned = Vec::new();
    let mut skipped = discovered.skipped;
    let mut incomplete = false;
    let mut file_count = 0usize;

    for source in discovered.files {
        if let Some(id) = adapter_filter {
            if source.adapter_id != id {
                continue;
            }
        }
        file_count += 1;
        let adapter = match registry.get(&source.adapter_id) {
            Some(a) => a,
            None => {
                skipped.push(SkipRecord {
                    path: source.path.display().to_string(),
                    reason: format!("unknown adapter {}", source.adapter_id),
                    adapter_id: Some(source.adapter_id),
                });
                incomplete = true;
                continue;
            }
        };
        let bytes = match std::fs::read(&source.path) {
            Ok(b) => b,
            Err(e) => {
                skipped.push(SkipRecord {
                    path: source.path.display().to_string(),
                    reason: format!("read error: {e}"),
                    adapter_id: Some(adapter.id().into()),
                });
                incomplete = true;
                continue;
            }
        };
        if bytes.len() as u64 > config.discovery.max_file_bytes {
            skipped.push(SkipRecord {
                path: source.path.display().to_string(),
                reason: "exceeds max_file_bytes".into(),
                adapter_id: Some(adapter.id().into()),
            });
            incomplete = true;
            continue;
        }
        match adapter.parse(&source.path) {
            Ok(parsed) => {
                let parsed = normalize_session(parsed);
                let findings = classify_all(detect_in_session(&parsed, config));
                let doc = SourceDocument {
                    path: source.path.clone(),
                    original_bytes: bytes,
                    original_hash: sha256_hex(
                        // re-hash from file bytes already read
                        &std::fs::read(&source.path).unwrap_or_default(),
                    ),
                    parsed,
                };
                // Fix hash from the bytes we already have
                let doc = SourceDocument {
                    original_hash: sha256_hex(&doc.original_bytes),
                    ..doc
                };
                scanned.push((doc, findings));
            }
            Err(e) => {
                skipped.push(SkipRecord {
                    path: source.path.display().to_string(),
                    reason: format!("parse skipped: {e}"),
                    adapter_id: Some(adapter.id().into()),
                });
                incomplete = true;
            }
        }
    }

    Ok((scanned, skipped, file_count, incomplete))
}

fn cmd_scan(
    cli: &Cli,
    config: &AppConfig,
    registry: &AdapterRegistry,
    adapter_filter: Option<&str>,
) -> Result<ExitCode> {
    let (scanned, skipped, discovered_count, incomplete) =
        scan_targets(cli, config, registry, adapter_filter)?;
    let mut all_findings = Vec::new();
    for (_doc, findings) in &scanned {
        all_findings.extend(findings.clone());
    }
    let report = ScanReport {
        summary: summarize(
            &all_findings,
            discovered_count,
            scanned.len(),
            skipped.len(),
            incomplete,
        ),
        findings: all_findings,
        skipped,
    };

    emit_scan(cli, config, &report)?;

    if incomplete {
        Ok(ExitCode::IncompleteScan)
    } else {
        Ok(ExitCode::Ok)
    }
}

fn emit_scan(cli: &Cli, config: &AppConfig, report: &ScanReport) -> Result<()> {
    match cli.format {
        OutputFormat::Terminal => {
            print_terminal_scan(report, config.reporting.include_masked_values)
        }
        OutputFormat::Json => print_json(report)?,
        OutputFormat::Markdown => println!("{}", to_markdown(report)),
    }
    if let Some(path) = &cli.output {
        write_json_file(path, report)?;
    }
    Ok(())
}

fn cmd_report(
    cli: &Cli,
    config: &AppConfig,
    registry: &AdapterRegistry,
    from: Option<PathBuf>,
) -> Result<ExitCode> {
    if let Some(path) = from {
        let raw = std::fs::read_to_string(&path).map_err(|source| AgentscrubError::Io {
            path: path.clone(),
            source,
        })?;
        let report: ScanReport = serde_json::from_str(&raw)
            .map_err(|e| AgentscrubError::Validation(format!("invalid report JSON: {e}")))?;
        emit_scan(cli, config, &report)?;
        return Ok(ExitCode::Ok);
    }
    cmd_scan(cli, config, registry, None)
}

fn cmd_scrub(
    cli: &Cli,
    config: &AppConfig,
    registry: &AdapterRegistry,
    adapter_filter: Option<&str>,
    confirm: bool,
    backup: bool,
) -> Result<ExitCode> {
    let mode = if confirm {
        RedactionMode::Confirm
    } else {
        RedactionMode::DryRun
    };
    let (scanned, _skipped, _, incomplete) = scan_targets(cli, config, registry, adapter_filter)?;
    let mut plans = Vec::new();
    let mut receipts = Vec::new();
    let mut remediation_error = false;

    for (doc, findings) in scanned {
        if findings.is_empty() {
            continue;
        }
        let adapter = registry
            .get(&doc.parsed.source)
            .ok_or_else(|| AgentscrubError::Unsupported(doc.parsed.source.clone()))?;
        if !adapter.capabilities().redaction {
            plans.push(crate::remediation::redact::plan_redaction(
                &doc, &adapter, &findings, mode,
            ));
            eprintln!(
                "skip rewrite (read-only adapter): {} [{}]",
                doc.path.display(),
                adapter.id()
            );
            continue;
        }
        match apply_redaction(&doc, &adapter, &findings, mode, backup) {
            Ok((plan, receipt, _)) => {
                plans.push(plan);
                if let Some(r) = receipt {
                    receipts.push(r);
                }
            }
            Err(e) => {
                eprintln!("remediation error for {}: {e}", doc.path.display());
                remediation_error = true;
            }
        }
    }

    let report = ScrubReport { plans, receipts };
    match cli.format {
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Markdown | OutputFormat::Terminal => {
            let label = if confirm {
                "scrub --confirm"
            } else {
                "scrub --dry-run"
            };
            println!(
                "{label}: {} plan(s), {} receipt(s)",
                report.plans.len(),
                report.receipts.len()
            );
            for p in &report.plans {
                println!(
                    "  {} findings={} supports_redaction={} would_modify={}",
                    p.file_path, p.findings_count, p.supports_redaction, p.would_modify
                );
            }
            for r in &report.receipts {
                println!(
                    "  receipt: {} applied={} dry_run={} new_hash={}",
                    r.file_path,
                    r.redactions_applied,
                    r.dry_run,
                    &r.new_hash[..12]
                );
            }
        }
    }
    if let Some(path) = &cli.output {
        write_json_file(path, &report)?;
    }

    if remediation_error {
        Ok(ExitCode::Remediation)
    } else if incomplete {
        Ok(ExitCode::IncompleteScan)
    } else {
        Ok(ExitCode::Ok)
    }
}

fn cmd_verify(
    cli: &Cli,
    config: &AppConfig,
    registry: &AdapterRegistry,
    files: &[PathBuf],
    fingerprints: &[String],
) -> Result<ExitCode> {
    let mut all_clean = true;
    let mut results = Vec::new();
    for f in files {
        let result = verify_file(f, config, registry, fingerprints)?;
        if !result.clean {
            all_clean = false;
        }
        results.push(result);
    }
    match cli.format {
        OutputFormat::Json => print_json(&results)?,
        _ => {
            for r in &results {
                println!(
                    "verify {} clean={} remaining={} structure_valid={}",
                    r.file_path, r.clean, r.remaining_findings, r.structure_valid
                );
            }
        }
    }
    if all_clean {
        Ok(ExitCode::Ok)
    } else {
        Ok(ExitCode::Validation)
    }
}

fn cmd_retention(cli: &Cli, config: &AppConfig, action: RetentionCommands) -> Result<ExitCode> {
    match action {
        RetentionCommands::Status => {
            let status = retention_status(config);
            match cli.format {
                OutputFormat::Json => print_json(&serde_json::json!({
                    "enabled": config.retention.enabled,
                    "max_age_days": config.retention.max_age_days,
                    "status": status,
                }))?,
                _ => println!("{status}"),
            }
            Ok(ExitCode::Ok)
        }
        RetentionCommands::Plan => {
            let discovered = if !cli.paths.is_empty() {
                discover_paths(&cli.paths, config, &AdapterRegistry::with_defaults())?
            } else {
                discover(config, &AdapterRegistry::with_defaults())?
            };
            let plan = plan_retention(config, &discovered.files);
            match cli.format {
                OutputFormat::Json => print_json(&plan)?,
                _ => {
                    println!(
                        "retention plan (read-only): enabled={} max_age_days={} files={} would_delete={} refused_uncertain={}",
                        plan.enabled,
                        plan.max_age_days,
                        plan.decisions.len(),
                        plan.would_delete,
                        plan.refused_mixed_age
                    );
                    for d in &plan.decisions {
                        println!(
                            "  {:?} {} — {} ({})",
                            d.action, d.path, d.reason, d.timestamp_source
                        );
                    }
                }
            }
            Ok(ExitCode::Ok)
        }
        RetentionCommands::Apply { confirm } => {
            ensure_retention_enabled(config)?;
            if !confirm {
                return Err(AgentscrubError::Policy(
                    "retention apply requires --confirm (and retention.enabled=true)".into(),
                ));
            }
            Err(AgentscrubError::Unsupported(
                "retention deletion apply is not enabled in v0.1.0 pending safety tests".into(),
            ))
        }
        RetentionCommands::Verify => {
            println!("retention verify: no deletion operations recorded (feature flagged off)");
            Ok(ExitCode::Ok)
        }
    }
}

fn cmd_config(cli: &Cli, config: &AppConfig, action: ConfigCommands) -> Result<ExitCode> {
    match action {
        ConfigCommands::Show => {
            match cli.format {
                OutputFormat::Json => print_json(config)?,
                _ => {
                    println!("retention.enabled = {}", config.retention.enabled);
                    println!("detection.enable_pii = {}", config.detection.enable_pii);
                    println!("redaction.mode = {}", config.redaction.mode);
                    println!("discovery.roots = {:?}", config.discovery.roots);
                }
            }
            Ok(ExitCode::Ok)
        }
        ConfigCommands::Path => {
            println!("config/default.toml");
            Ok(ExitCode::Ok)
        }
    }
}
