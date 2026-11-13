use crate::config::AppConfig;
use crate::errors::{AgentscrubError, Result};

pub fn ensure_retention_enabled(config: &AppConfig) -> Result<()> {
    if !config.retention.enabled {
        return Err(AgentscrubError::Policy(
            "retention.enabled = false; deletion/apply is refused until the feature flag is enabled and safety tests pass"
                .into(),
        ));
    }
    Ok(())
}

pub fn retention_status(config: &AppConfig) -> String {
    format!(
        "retention.enabled={} max_age_days={}",
        config.retention.enabled, config.retention.max_age_days
    )
}
