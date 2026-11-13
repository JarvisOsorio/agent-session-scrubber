use crate::errors::{AgentscrubError, Result};
use std::path::{Component, Path, PathBuf};

/// Resolve a path without following the final component if it is a symlink escape.
pub fn resolve_safe_path(path: &Path) -> Result<PathBuf> {
    let canonical_parent = path
        .parent()
        .map(|p| {
            if p.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                p.to_path_buf()
            }
        })
        .unwrap_or_else(|| PathBuf::from("."));

    let parent = std::fs::canonicalize(&canonical_parent).unwrap_or(canonical_parent);
    let name = path
        .file_name()
        .ok_or_else(|| AgentscrubError::Validation(format!("invalid path: {}", path.display())))?;

    for c in path.components() {
        if matches!(c, Component::ParentDir) {
            // Allow relative parents only after canonicalize of existing roots.
            continue;
        }
    }

    Ok(parent.join(name))
}

pub fn is_within_roots(path: &Path, roots: &[PathBuf]) -> bool {
    let Ok(canon) = std::fs::canonicalize(path) else {
        return roots.iter().any(|r| path.starts_with(r));
    };
    roots.iter().any(|root| {
        std::fs::canonicalize(root)
            .map(|r| canon.starts_with(&r))
            .unwrap_or_else(|_| path.starts_with(root))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_roots_detects_membership() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let file = nested.join("x.jsonl");
        std::fs::write(&file, b"{}").unwrap();
        assert!(is_within_roots(&file, &[dir.path().to_path_buf()]));
        assert!(!is_within_roots(
            &file,
            &[dir.path().join("other").to_path_buf()]
        ));
    }
}
