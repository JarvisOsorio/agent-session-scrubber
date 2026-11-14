use crate::errors::{AgentscrubError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub discovery: DiscoveryConfig,
    pub detection: DetectionConfig,
    pub redaction: RedactionConfig,
    pub retention: RetentionConfig,
    pub reporting: ReportingConfig,
    pub generic_jsonl: GenericJsonlConfig,
    pub hmac_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub roots: Vec<PathBuf>,
    pub follow_symlinks: bool,
    pub max_file_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub min_confidence: String,
    pub enable_pii: bool,
    pub enable_entropy: bool,
    pub allowlist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionConfig {
    pub mode: String,
    pub backup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Retention deletion stays disabled until safety tests pass.
    pub enabled: bool,
    pub max_age_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    pub include_masked_values: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericJsonlConfig {
    pub text_fields: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            discovery: DiscoveryConfig {
                roots: default_roots(),
                follow_symlinks: false,
                max_file_bytes: 64 * 1024 * 1024,
            },
            detection: DetectionConfig {
                min_confidence: "medium".into(),
                enable_pii: true,
                enable_entropy: false,
                allowlist: Vec::new(),
            },
            redaction: RedactionConfig {
                mode: "mask".into(),
                backup: true,
            },
            retention: RetentionConfig {
                enabled: false,
                max_age_days: 90,
            },
            reporting: ReportingConfig {
                include_masked_values: true,
            },
            generic_jsonl: GenericJsonlConfig {
                text_fields: vec![
                    "content".into(),
                    "text".into(),
                    "message".into(),
                    "input".into(),
                    "output".into(),
                ],
            },
            // Local-only fingerprinting key; not a secret for network auth.
            hmac_key: "agentscrub-local-fingerprint-v1".into(),
        }
    }
}

fn default_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = dirs_home() {
        roots.push(home.join(".claude"));
        roots.push(home.join(".codex"));
        roots.push(home.join(".cursor"));
        roots.push(home.join("Library/Application Support/Cursor"));
        roots.push(home.join(".config/Cursor"));
    }
    roots
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

impl AppConfig {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut cfg = Self::default();
        if let Some(path) = path {
            let raw = std::fs::read_to_string(path).map_err(|source| AgentscrubError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            let overlay: AppConfigOverlay = toml::from_str(&raw)
                .map_err(|e| AgentscrubError::Config(format!("parse {}: {e}", path.display())))?;
            overlay.apply(&mut cfg);
        } else if let Ok(default_path) = locate_default_config() {
            if default_path.exists() {
                let raw = std::fs::read_to_string(&default_path).map_err(|source| {
                    AgentscrubError::Io {
                        path: default_path.clone(),
                        source,
                    }
                })?;
                let overlay: AppConfigOverlay = toml::from_str(&raw).map_err(|e| {
                    AgentscrubError::Config(format!("parse {}: {e}", default_path.display()))
                })?;
                overlay.apply(&mut cfg);
            }
        }
        Ok(cfg)
    }

    pub fn with_roots(mut self, roots: Vec<PathBuf>) -> Self {
        if !roots.is_empty() {
            self.discovery.roots = roots;
        }
        self
    }
}

#[derive(Debug, Default, Deserialize)]
struct AppConfigOverlay {
    discovery: Option<DiscoveryOverlay>,
    detection: Option<DetectionOverlay>,
    redaction: Option<RedactionOverlay>,
    retention: Option<RetentionOverlay>,
    reporting: Option<ReportingOverlay>,
    generic_jsonl: Option<GenericJsonlOverlay>,
    hmac_key: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DiscoveryOverlay {
    roots: Option<Vec<PathBuf>>,
    follow_symlinks: Option<bool>,
    max_file_bytes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct DetectionOverlay {
    min_confidence: Option<String>,
    enable_pii: Option<bool>,
    enable_entropy: Option<bool>,
    allowlist: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
struct RedactionOverlay {
    mode: Option<String>,
    backup: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct RetentionOverlay {
    enabled: Option<bool>,
    max_age_days: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct ReportingOverlay {
    include_masked_values: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct GenericJsonlOverlay {
    text_fields: Option<Vec<String>>,
}

impl AppConfigOverlay {
    fn apply(self, cfg: &mut AppConfig) {
        if let Some(d) = self.discovery {
            if let Some(v) = d.roots {
                cfg.discovery.roots = v;
            }
            if let Some(v) = d.follow_symlinks {
                cfg.discovery.follow_symlinks = v;
            }
            if let Some(v) = d.max_file_bytes {
                cfg.discovery.max_file_bytes = v;
            }
        }
        if let Some(d) = self.detection {
            if let Some(v) = d.min_confidence {
                cfg.detection.min_confidence = v;
            }
            if let Some(v) = d.enable_pii {
                cfg.detection.enable_pii = v;
            }
            if let Some(v) = d.enable_entropy {
                cfg.detection.enable_entropy = v;
            }
            if let Some(v) = d.allowlist {
                cfg.detection.allowlist = v;
            }
        }
        if let Some(d) = self.redaction {
            if let Some(v) = d.mode {
                cfg.redaction.mode = v;
            }
            if let Some(v) = d.backup {
                cfg.redaction.backup = v;
            }
        }
        if let Some(d) = self.retention {
            if let Some(v) = d.enabled {
                cfg.retention.enabled = v;
            }
            if let Some(v) = d.max_age_days {
                cfg.retention.max_age_days = v;
            }
        }
        if let Some(d) = self.reporting {
            if let Some(v) = d.include_masked_values {
                cfg.reporting.include_masked_values = v;
            }
        }
        if let Some(d) = self.generic_jsonl {
            if let Some(v) = d.text_fields {
                cfg.generic_jsonl.text_fields = v;
            }
        }
        if let Some(v) = self.hmac_key {
            cfg.hmac_key = v;
        }
    }
}

fn locate_default_config() -> Result<PathBuf> {
    let candidates = [
        PathBuf::from("config/default.toml"),
        PathBuf::from("/etc/agentscrub/default.toml"),
    ];
    for c in candidates {
        if c.exists() {
            return Ok(c);
        }
    }
    Ok(PathBuf::from("config/default.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_toml_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
[retention]
enabled = false
max_age_days = 30

[detection]
enable_pii = true
"#
        )
        .unwrap();
        let cfg = AppConfig::load(Some(&path)).unwrap();
        assert!(!cfg.retention.enabled);
        assert_eq!(cfg.retention.max_age_days, 30);
        assert!(cfg.detection.enable_pii);
    }
}
