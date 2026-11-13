/// Mask a secret for reports/logs: keep category hint via length, never full value.
pub fn mask_secret(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len == 0 {
        return String::new();
    }
    if len <= 8 {
        return format!("{}***", chars.first().copied().unwrap_or('*'));
    }
    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars.iter().skip(len.saturating_sub(4)).collect();
    format!("{prefix}…{suffix} (len={len})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_long_secret() {
        let m = mask_secret("AKIAIOSFODNN7EXAMPLE");
        assert!(m.starts_with("AKIA"));
        assert!(m.contains("len="));
        assert!(!m.contains("IOSFODNN7EXAMP"));
    }
}
