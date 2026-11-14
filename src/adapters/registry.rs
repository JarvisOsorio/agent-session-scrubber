use super::claude::ClaudeCodeAdapter;
use super::codex::CodexAdapter;
use super::cursor::CursorAdapter;
use super::generic_json::GenericJsonAdapter;
use super::generic_jsonl::GenericJsonlAdapter;
use super::traits::SourceAdapter;
use crate::config::AppConfig;
use crate::errors::{AgentscrubError, Result};
use crate::models::SourceFile;
use std::path::Path;
use std::sync::Arc;

pub struct AdapterRegistry {
    adapters: Vec<Arc<dyn SourceAdapter>>,
}

impl AdapterRegistry {
    pub fn with_defaults() -> Self {
        Self {
            adapters: vec![
                Arc::new(ClaudeCodeAdapter),
                Arc::new(CodexAdapter),
                Arc::new(CursorAdapter),
                Arc::new(GenericJsonlAdapter),
                Arc::new(GenericJsonAdapter),
            ],
        }
    }

    pub fn all(&self) -> &[Arc<dyn SourceAdapter>] {
        &self.adapters
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn SourceAdapter>> {
        self.adapters.iter().find(|a| a.id() == id).cloned()
    }

    pub fn identify(&self, path: &Path) -> Result<Option<Arc<dyn SourceAdapter>>> {
        // Prefer specific adapters before generic catch-alls.
        for adapter in &self.adapters {
            if adapter.identify(path)? {
                return Ok(Some(Arc::clone(adapter)));
            }
        }
        Ok(None)
    }

    pub fn discover_all(&self, config: &AppConfig) -> Result<Vec<SourceFile>> {
        let mut files = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for adapter in &self.adapters {
            for file in adapter.discover(config)? {
                let key = file.path.display().to_string();
                if seen.insert(key) {
                    files.push(file);
                }
            }
        }
        Ok(files)
    }

    pub fn require(&self, id: &str) -> Result<Arc<dyn SourceAdapter>> {
        self.get(id)
            .ok_or_else(|| AgentscrubError::Unsupported(format!("unknown adapter: {id}")))
    }
}
