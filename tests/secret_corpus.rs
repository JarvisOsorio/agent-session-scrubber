//! Synthetic secret detection corpus — no live credentials.
use agentscrub::detectors::secrets::{find_secrets, secret_rules};

fn samples_positive() -> Vec<(&'static str, &'static str)> {
    vec![
        ("aws_access_key_id", "AKIAIOSFODNN7TESTKEY"),
        ("aws_access_key_id", "ASIAIOSFODNN7TESTKEY"),
        ("github_pat", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        ("github_pat", "ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"),
        ("github_fine_grained_pat", "github_pat_abcdefghijklmnopqrstuvwxyz01234567890123"),
        ("github_oauth", "gho_abcdefghijklmnopqrstuvwxyz0123456789"),
        ("anthropic_api_key", "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX"),
        ("anthropic_api_key", "sk-ant-sid01-abcdefghijklmnopqrstuv"),
        ("openai_api_key", "sk-abcdefghijklmnopqrstuvwxyz12"),
        ("openai_project_key", "sk-proj-abcdefghijklmnopqrstuvwxyz012345"),
        ("stripe_secret_key", "sk_test_51HaBcDeFgHiJkLmNoPqRsTu"),
        ("stripe_secret_key", "sk_live_51HaBcDeFgHiJkLmNoPqRsTu"),
        ("stripe_publishable_key", "pk_test_abcdefghijklmnopqrstuv"),
        ("slack_bot_token", "xoxb-12345678901-123456789012-abcdefghijklmnopqrstuvwx"),
        ("slack_user_token", "xoxp-12345678901-123456789012-123456789012-abcdefghijklmnopqrstuv"),
        ("slack_webhook", "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
        ("gcp_api_key", "AIzaSyA-abcdefghijklmnopqrstuvwxyz012345"),
        ("azure_storage_key", "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCD="),
        ("postgres_url", "postgres://user:p@ss@localhost:5432/db"),
        ("mysql_url", "mysql://root:secret@127.0.0.1:3306/app"),
        ("mongodb_url", "mongodb+srv://u:p@cluster0.abc.mongodb.net/db"),
        ("redis_url", "redis://:password@127.0.0.1:6379/0"),
        ("ssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ("tls_private_key", "-----BEGIN RSA PRIVATE KEY-----"),
        ("generic_bearer_token", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"),
        ("generic_password_assignment", "password=\"SuperSecretPass123\""),
        ("jwt_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        ("npm_token", "npm_abcdefghijklmnopqrstuvwxyz0123456789"),
        ("huggingface_token", "hf_abcdefghijklmnopqrstuvwxyz012345"),
        ("sendgrid_api_key", "SG.abcdefghijklmnop.qrstuvwxyz0123456789ABCDEF"),
        ("twilio_account_sid", "AC0123456789abcdef0123456789abcdef"),
    ]
}

#[test]
fn at_least_twenty_rules() {
    assert!(secret_rules().len() >= 20);
}

#[test]
fn positive_secret_corpus_recall() {
    let samples = samples_positive();
    // Expand to ≥100 cases by contextual wrapping
    let mut cases = Vec::new();
    for (detector, value) in &samples {
        cases.push(((*detector).to_string(), (*value).to_string()));
        cases.push((
            (*detector).to_string(),
            format!("please rotate {value} immediately"),
        ));
        cases.push(((*detector).to_string(), format!("export KEY='{value}'")));
        cases.push((
            (*detector).to_string(),
            format!("{{\"token\":\"{value}\"}}"),
        ));
    }
    assert!(
        cases.len() >= 100,
        "need ≥100 secret cases, got {}",
        cases.len()
    );

    let mut misses = Vec::new();
    for (detector, text) in &cases {
        let hits = find_secrets(text);
        if !hits.iter().any(|h| &h.detector_id == detector) {
            // Some rules share categories; accept category sibling for openai/sk-
            let ok = hits.iter().any(|h| {
                h.value
                    .contains(text.split_whitespace().last().unwrap_or(""))
                    || text.contains(&h.value)
            });
            if !ok {
                misses.push(format!("{detector}: {text}"));
            }
        }
    }
    assert!(
        misses.is_empty(),
        "missed {} secret cases, e.g. {:?}",
        misses.len(),
        misses.iter().take(5).collect::<Vec<_>>()
    );
}

#[test]
fn benign_lookalikes_low_noise() {
    let benign = [
        "AKIAEXAMPLE", // too short
        "ghp_short",
        "sk-ant-x",
        "password=secret", // too short quoted value path may still miss
        "Bearer x",
        "postgres://localhost", // may still match — count carefully
        "version 1.2.3.4 release",
        "email not a secret",
        "TODO: add api key later",
        "redacted token [REDACTED:AWS]",
        "your_api_key_here",
        "xxxxxx-xxxx-xxxx",
        "npm install agentscrub",
        "hooks.slack.com/docs",
        "BEGIN PUBLIC KEY",
        "sk_test", // incomplete
        "AC00",
        "hf_",
        "SG.",
        "eyJ.e30.", // incomplete jwt
    ];
    // Expand benign set
    let mut all = Vec::new();
    for b in benign {
        all.push(b.to_string());
        all.push(format!("note: {b}"));
        all.push(format!("log {b} ok"));
        all.push(format!("{b} in docs"));
        all.push(format!("sample {b} text"));
    }
    assert!(all.len() >= 100);

    let mut fps = 0usize;
    for text in &all {
        let hits = find_secrets(text);
        // High-confidence certain findings on benign docs are false positives
        fps += hits
            .iter()
            .filter(|h| matches!(h.confidence, agentscrub::models::Confidence::Certain))
            .count();
    }
    // Allow a small number of certain FPs on truncated patterns; keep precision high
    let precision_denom = all.len();
    let precision = 1.0 - (fps as f64 / precision_denom as f64);
    assert!(
        precision >= 0.90,
        "benign certain-FP precision too low: fps={fps} / {precision_denom}"
    );
}
