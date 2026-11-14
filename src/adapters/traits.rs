use crate::config::AppConfig;
use crate::errors::Result;
use crate::models::{
    AdapterCapabilities, Finding, ParsedSession, RewriteResult, SourceDocument, SourceFile,
};
use std::path::Path;

pub trait SourceAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn discover(&self, config: &AppConfig) -> Result<Vec<SourceFile>>;
    fn identify(&self, path: &Path) -> Result<bool>;
    fn parse(&self, path: &Path) -> Result<ParsedSession>;
    fn rewrite(&self, original: &SourceDocument, findings: &[Finding]) -> Result<RewriteResult>;
    fn capabilities(&self) -> AdapterCapabilities;
}
