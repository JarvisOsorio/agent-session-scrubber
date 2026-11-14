//! Synthetic secret detection corpus — no live credentials.
//! Targets: ≥100 positive secret cases, ≥100 benign lookalikes,
//! measurable recall (known secrets) and precision (high-confidence).
use agentscrub::detectors::secrets::{find_secrets, secret_rules};
use agentscrub::models::Confidence;

fn samples_positive() -> Vec<(&'static str, &'static str)> {
    vec![
        ("aws_access_key_id", "AKIAIOSFODNN7TESTKEY"),
        ("aws_access_key_id", "ASIAIOSFODNN7TESTKEY"),
        ("aws_access_key_id", "AKIAJG74R7OYWBTEST12"),
        ("github_pat", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        ("github_pat", "ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"),
        (
            "github_fine_grained_pat",
            "github_pat_abcdefghijklmnopqrstuvwxyz01234567890123",
        ),
        ("github_oauth", "gho_abcdefghijklmnopqrstuvwxyz0123456789"),
        ("anthropic_api_key", "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX"),
        ("anthropic_api_key", "sk-ant-sid01-abcdefghijklmnopqrstuv"),
        ("openai_api_key", "sk-abcdefghijklmnopqrstuvwxyz12"),
        ("openai_project_key", "sk-proj-abcdefghijklmnopqrstuvwxyz012345"),
        ("stripe_secret_key", "sk_test_51HaBcDeFgHiJkLmNoPqRsTu"),
        ("stripe_secret_key", "sk_live_51HaBcDeFgHiJkLmNoPqRsTu"),
        ("stripe_publishable_key", "pk_test_abcdefghijklmnopqrstuv"),
        (
            "slack_bot_token",
            "xoxb-12345678901-123456789012-abcdefghijklmnopqrstuvwx",
        ),
        (
            "slack_user_token",
            "xoxp-12345678901-123456789012-123456789012-abcdefghijklmnopqrstuv",
        ),
        (
            "slack_webhook",
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
        ),
        ("gcp_api_key", "AIzaSyA-abcdefghijklmnopqrstuvwxyz012345"),
        (
            "azure_storage_key",
            "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCD=",
        ),
        ("postgres_url", "postgres://user:p@ss@localhost:5432/db"),
        ("mysql_url", "mysql://root:secret@127.0.0.1:3306/app"),
        (
            "mongodb_url",
            "mongodb+srv://u:p@cluster0.abc.mongodb.net/db",
        ),
        ("redis_url", "redis://:password@127.0.0.1:6379/0"),
        ("ssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ("tls_private_key", "-----BEGIN RSA PRIVATE KEY-----"),
        (
            "generic_bearer_token",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
        ),
        (
            "generic_password_assignment",
            "password=\"SuperSecretPass123\"",
        ),
        (
            "jwt_token",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        ),
        ("npm_token", "npm_abcdefghijklmnopqrstuvwxyz0123456789"),
        ("huggingface_token", "hf_abcdefghijklmnopqrstuvwxyz012345"),
        (
            "sendgrid_api_key",
            "SG.abcdefghijklmnop.qrstuvwxyz0123456789ABCDEF",
        ),
        ("twilio_account_sid", "AC0123456789abcdef0123456789abcdef"),
    ]
}

fn expand_positive(samples: &[(&str, &str)]) -> Vec<(String, String)> {
    let wrappers = [
        "{value}",
        "please rotate {value} immediately",
        "export KEY='{value}'",
        "{{\"token\":\"{value}\"}}",
        "tool_output: {value}",
        "found credential {value} in log",
    ];
    let mut cases = Vec::new();
    for (detector, value) in samples {
        for w in wrappers {
            cases.push(((*detector).to_string(), w.replace("{value}", value)));
        }
    }
    cases
}

fn benign_lookalikes() -> Vec<String> {
    let seeds = [
        "AKIAEXAMPLE",
        "ghp_short",
        "sk-ant-x",
        "password=secret",
        "Bearer x",
        "version 1.2.3.4 release",
        "email not a secret",
        "TODO: add api key later",
        "redacted token [REDACTED:AWS]",
        "your_api_key_here",
        "xxxxxx-xxxx-xxxx",
        "npm install agentscrub",
        "hooks.slack.com/docs",
        "BEGIN PUBLIC KEY",
        "sk_test",
        "AC00",
        "hf_",
        "SG.",
        "eyJ.e30.",
        "ASIATOO_SHORT",
        "pk_live",
        "xoxb-1-2-short",
        "mongodb docs localhost only",
        "redis cache discussion",
        "AccountKey=short",
        "npm_short",
        "Authorization: Bearer x",
        "-----BEGIN PUBLIC KEY-----",
        "sk-proj-x",
        "github_pat_short",
        "see postgres docs for URI format",
        "hooks.slack.com/services/docs",
        "AIza too short key",
        "AC12 incomplete twilio",
    ];
    let mut all = Vec::new();
    for (i, b) in seeds.iter().enumerate() {
        all.push((*b).to_string());
        all.push(format!("note: {b}"));
        all.push(format!("log {b} ok"));
        all.push(format!("{b} in docs"));
        all.push(format!("sample {b} text #{i}"));
    }
    // Pad to ≥100 with clearly non-secret prose.
    while all.len() < 100 {
        let n = all.len();
        all.push(format!(
            "benign transcript line {n}: discussing architecture without credentials"
        ));
    }
    all
}

#[test]
fn at_least_twenty_rules() {
    assert!(secret_rules().len() >= 20);
}

#[test]
fn positive_secret_corpus_size_and_recall() {
    let cases = expand_positive(&samples_positive());
    assert!(
        cases.len() >= 100,
        "need ≥100 secret cases, got {}",
        cases.len()
    );

    let mut hits_ok = 0usize;
    let mut misses = Vec::new();
    for (detector, text) in &cases {
        let hits = find_secrets(text);
        if hits.iter().any(|h| &h.detector_id == detector)
            || hits.iter().any(|h| text.contains(&h.value))
        {
            hits_ok += 1;
        } else {
            misses.push(format!("{detector}: {text}"));
        }
    }
    let recall = hits_ok as f64 / cases.len() as f64;
    assert!(
        misses.is_empty(),
        "missed {}/{} secret cases (recall={recall:.3}), e.g. {:?}",
        misses.len(),
        cases.len(),
        misses.iter().take(5).collect::<Vec<_>>()
    );
    assert!(
        (recall - 1.0).abs() < f64::EPSILON,
        "known-secret recall must be 100%, got {recall:.3}"
    );
}

#[test]
fn high_confidence_precision_on_benign_lookalikes() {
    let all = benign_lookalikes();
    assert!(
        all.len() >= 100,
        "need ≥100 benign cases, got {}",
        all.len()
    );

    let mut certain_fps = 0usize;
    let mut high_or_better_fps = 0usize;
    for text in &all {
        for h in find_secrets(text) {
            if h.confidence >= Confidence::High {
                high_or_better_fps += 1;
            }
            if h.confidence == Confidence::Certain {
                certain_fps += 1;
            }
        }
    }

    // Spec target: ≥98% precision for high-confidence secrets.
    // Approximate via 1 - (FP / benign_docs) on a lookalike corpus with no true secrets.
    let precision_high = 1.0 - (high_or_better_fps as f64 / all.len() as f64);
    let precision_certain = 1.0 - (certain_fps as f64 / all.len() as f64);
    assert!(
        precision_high >= 0.98,
        "high-confidence precision too low: fps={high_or_better_fps}/{} => {precision_high:.3}",
        all.len()
    );
    assert!(
        precision_certain >= 0.98,
        "certain-confidence precision too low: fps={certain_fps}/{} => {precision_certain:.3}",
        all.len()
    );
}
