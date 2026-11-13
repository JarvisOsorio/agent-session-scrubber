use crate::adapters::SourceAdapter;
use crate::errors::{AgentscrubError, Result};
use crate::models::{Finding, RewriteResult, SourceDocument};
use crate::utils::sha256_hex;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionMode {
    DryRun,
    Confirm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionPlan {
    pub file_path: String,
    pub adapter_id: String,
    pub findings_count: usize,
    pub mode: String,
    pub would_modify: bool,
    pub supports_redaction: bool,
    pub original_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionReceipt {
    pub file_path: String,
    pub adapter_id: String,
    pub original_hash: String,
    pub new_hash: String,
    pub redactions_applied: usize,
    pub structure_valid: bool,
    pub backup_path: Option<String>,
    pub dry_run: bool,
    pub finding_fingerprints: Vec<String>,
}

pub fn plan_redaction(
    doc: &SourceDocument,
    adapter: &Arc<dyn SourceAdapter>,
    findings: &[Finding],
    mode: RedactionMode,
) -> RedactionPlan {
    let caps = adapter.capabilities();
    RedactionPlan {
        file_path: doc.path.display().to_string(),
        adapter_id: adapter.id().into(),
        findings_count: findings.len(),
        mode: match mode {
            RedactionMode::DryRun => "dry-run".into(),
            RedactionMode::Confirm => "confirm".into(),
        },
        would_modify: caps.redaction && !findings.is_empty() && mode == RedactionMode::Confirm,
        supports_redaction: caps.redaction,
        original_hash: doc.original_hash.clone(),
    }
}

pub fn apply_redaction(
    doc: &SourceDocument,
    adapter: &Arc<dyn SourceAdapter>,
    findings: &[Finding],
    mode: RedactionMode,
    backup: bool,
) -> Result<(
    RedactionPlan,
    Option<RedactionReceipt>,
    Option<RewriteResult>,
)> {
    let plan = plan_redaction(doc, adapter, findings, mode);
    if !adapter.capabilities().redaction {
        return Err(AgentscrubError::Unsupported(format!(
            "adapter {} does not support redaction; staying read-only",
            adapter.id()
        )));
    }
    if findings.is_empty() {
        return Ok((plan, None, None));
    }

    let rewrite = adapter.rewrite(doc, findings)?;
    if !rewrite.structure_valid {
        return Err(AgentscrubError::Remediation(
            "redacted output failed structural validation; refusing to write".into(),
        ));
    }

    if mode == RedactionMode::DryRun {
        let receipt = RedactionReceipt {
            file_path: doc.path.display().to_string(),
            adapter_id: adapter.id().into(),
            original_hash: doc.original_hash.clone(),
            new_hash: sha256_hex(&rewrite.new_bytes),
            redactions_applied: rewrite.redactions_applied,
            structure_valid: rewrite.structure_valid,
            backup_path: None,
            dry_run: true,
            finding_fingerprints: findings.iter().map(|f| f.fingerprint.clone()).collect(),
        };
        return Ok((plan, Some(receipt), Some(rewrite)));
    }

    // Confirm path: lock, recheck hash, atomic replace.
    let receipt = atomic_replace(doc, &rewrite, findings, adapter.id(), backup)?;
    Ok((plan, Some(receipt), Some(rewrite)))
}

fn atomic_replace(
    doc: &SourceDocument,
    rewrite: &RewriteResult,
    findings: &[Finding],
    adapter_id: &str,
    backup: bool,
) -> Result<RedactionReceipt> {
    let path = &doc.path;
    if path
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(AgentscrubError::Remediation(
            "refusing to modify symlink targets".into(),
        ));
    }

    // Lock + hash recheck, then drop the handle before rename.
    // Windows cannot replace a file while this process still holds it open.
    let current = {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|source| AgentscrubError::Io {
                path: path.clone(),
                source,
            })?;
        FileExt::lock_exclusive(&file).map_err(|e| {
            AgentscrubError::Remediation(format!("could not lock {}: {e}", path.display()))
        })?;
        let bytes = std::fs::read(path).map_err(|source| AgentscrubError::Io {
            path: path.clone(),
            source,
        })?;
        let current_hash = sha256_hex(&bytes);
        let _ = FileExt::unlock(&file);
        drop(file);
        if current_hash != doc.original_hash {
            return Err(AgentscrubError::Remediation(format!(
                "file changed since scan (hash mismatch); refusing write: {}",
                path.display()
            )));
        }
        bytes
    };

    // Final recheck immediately before staging the replacement.
    let recheck = std::fs::read(path).map_err(|source| AgentscrubError::Io {
        path: path.clone(),
        source,
    })?;
    if sha256_hex(&recheck) != doc.original_hash {
        return Err(AgentscrubError::Remediation(format!(
            "file changed since scan (hash mismatch); refusing write: {}",
            path.display()
        )));
    }

    let backup_path = if backup {
        let bak = backup_path_for(path);
        std::fs::write(&bak, &current).map_err(|source| AgentscrubError::Io {
            path: bak.clone(),
            source,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o600));
        }
        Some(bak)
    } else {
        None
    };

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| AgentscrubError::Remediation(format!("tempfile create failed: {e}")))?;
    tmp.write_all(&rewrite.new_bytes)
        .map_err(|e| AgentscrubError::Remediation(format!("temp write failed: {e}")))?;
    tmp.flush()
        .map_err(|e| AgentscrubError::Remediation(format!("temp flush failed: {e}")))?;

    let tmp_path = tmp.path().to_path_buf();
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp_path, meta.permissions());
    }

    // Prefer same-directory persist. On Windows, overwrite via remove+rename if needed.
    if let Err(err) = tmp.persist(path) {
        let staged = err.file.path().to_path_buf();
        // Keep staged bytes available even if persist failed.
        let staged_bytes = std::fs::read(&staged).unwrap_or_else(|_| rewrite.new_bytes.clone());
        drop(err.file);
        let swap = parent.join(format!(
            ".agentscrub-swap-{}",
            &sha256_hex(&rewrite.new_bytes)[..12]
        ));
        std::fs::write(&swap, &staged_bytes).map_err(|source| AgentscrubError::Io {
            path: swap.clone(),
            source,
        })?;
        let retired = parent.join(format!(".agentscrub-old-{}", &sha256_hex(&current)[..12]));
        std::fs::rename(path, &retired).map_err(|source| AgentscrubError::Io {
            path: path.clone(),
            source,
        })?;
        if let Err(e) = std::fs::rename(&swap, path) {
            let _ = std::fs::rename(&retired, path);
            let _ = std::fs::remove_file(&swap);
            return Err(AgentscrubError::Remediation(format!(
                "atomic replace failed: {e}"
            )));
        }
        let _ = std::fs::remove_file(&retired);
        let _ = staged;
    }

    Ok(RedactionReceipt {
        file_path: path.display().to_string(),
        adapter_id: adapter_id.into(),
        original_hash: doc.original_hash.clone(),
        new_hash: sha256_hex(&rewrite.new_bytes),
        redactions_applied: rewrite.redactions_applied,
        structure_valid: rewrite.structure_valid,
        backup_path: backup_path.map(|p| p.display().to_string()),
        dry_run: false,
        finding_fingerprints: findings.iter().map(|f| f.fingerprint.clone()).collect(),
    })
}

fn backup_path_for(path: &Path) -> PathBuf {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    path.with_extension(format!(
        "{}.bak.{ts}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("file")
    ))
}
