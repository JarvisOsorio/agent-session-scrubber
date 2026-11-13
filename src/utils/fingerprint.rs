use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 fingerprint of a detected value. Never log the raw value.
pub fn fingerprint_value(hmac_key: &str, value: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(hmac_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn finding_id(fingerprint: &str, file_path: &str, field_path: &str, start: usize) -> String {
    let material = format!("{fingerprint}|{file_path}|{field_path}|{start}");
    let digest = crate::utils::hash::sha256_hex(material.as_bytes());
    format!("fnd_{}", &digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_stable_and_non_reversible_looking() {
        let a = fingerprint_value("key", "AKIAIOSFODNN7EXAMPLE");
        let b = fingerprint_value("key", "AKIAIOSFODNN7EXAMPLE");
        let c = fingerprint_value("key", "other");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(!a.contains("AKIA"));
        assert_eq!(a.len(), 64);
    }
}
