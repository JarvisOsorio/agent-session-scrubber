use crate::adapters::AdapterRegistry;
use crate::config::AppConfig;
use crate::errors::Result;
use crate::models::{SkipRecord, SourceFile};
use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub files: Vec<SourceFile>,
    pub skipped: Vec<SkipRecord>,
}

pub fn discover(config: &AppConfig, registry: &AdapterRegistry) -> Result<DiscoveryResult> {
    let mut result = DiscoveryResult::default();
    for root in &config.discovery.roots {
        if !root.exists() {
            result.skipped.push(SkipRecord {
                path: root.display().to_string(),
                reason: "root does not exist".into(),
                adapter_id: None,
            });
        }
    }
    result.files = registry.discover_all(config)?;
    result.files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

pub fn discover_paths(
    paths: &[PathBuf],
    config: &AppConfig,
    registry: &AdapterRegistry,
) -> Result<DiscoveryResult> {
    let mut result = DiscoveryResult::default();
    for path in paths {
        if path.is_dir() {
            let mut cfg = config.clone();
            cfg.discovery.roots = vec![path.clone()];
            let sub = discover(&cfg, registry)?;
            result.files.extend(sub.files);
            result.skipped.extend(sub.skipped);
            continue;
        }
        if !path.is_file() {
            result.skipped.push(SkipRecord {
                path: path.display().to_string(),
                reason: "not a file".into(),
                adapter_id: None,
            });
            continue;
        }
        match registry.identify(path)? {
            Some(adapter) => {
                let meta = std::fs::metadata(path).ok();
                result.files.push(SourceFile {
                    path: path.clone(),
                    adapter_id: adapter.id().into(),
                    size_bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                    modified_at: meta.and_then(|m| {
                        m.modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs() as i64)
                    }),
                });
            }
            None => result.skipped.push(SkipRecord {
                path: path.display().to_string(),
                reason: "unrecognized format".into(),
                adapter_id: None,
            }),
        }
    }
    result.files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}
