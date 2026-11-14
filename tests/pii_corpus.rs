//! Synthetic PII corpus — no real personal data.
//! Targets: ≥100 positive PII cases, ≥100 benign lookalikes, measurable recall/precision.
use agentscrub::detectors::pii::find_pii;

fn positive_cases() -> Vec<(String, String)> {
    let emails: Vec<String> = (0..30).map(|i| format!("user{i}@example.com")).collect();
    let phones = [
        "415-555-2671",
        "(212) 555-0199",
        "+1 310-555-0142",
        "646.555.0188",
        "202-555-0134",
        "312-555-0147",
    ];
    let ips = [
        "203.0.113.42",
        "198.51.100.7",
        "192.0.2.55",
        "8.8.8.8",
        "1.1.1.1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    ];
    // Luhn-valid synthetic PANs only
    let cards = [
        "4111111111111111",
        "4000000000000002",
        "5555555555554444",
        "378282246310005",
        "6011111111111117",
        "3530111333300000",
    ];

    let mut cases = Vec::new();
    for e in &emails {
        cases.push(("email_address".into(), e.clone()));
        cases.push(("email_address".into(), format!("contact {e} please")));
        cases.push(("email_address".into(), format!("From: {e}")));
    }
    for p in phones {
        for i in 0..3 {
            cases.push(("phone_number".into(), format!("{p} ext {i}")));
        }
    }
    for ip in ips {
        let det = if ip.contains(':') {
            "ipv6_address"
        } else {
            "ipv4_address"
        };
        for i in 0..3 {
            cases.push((det.into(), format!("peer {ip} hop {i}")));
        }
    }
    for c in cards {
        for i in 0..3 {
            cases.push(("credit_card".into(), format!("card {c} try {i}")));
        }
    }
    cases
}

fn benign_cases() -> Vec<String> {
    let mut benign: Vec<String> = (0..80)
        .map(|i| format!("order-{i:04} build-{i} version-1.2.{i}"))
        .collect();
    for i in 0..30 {
        benign.push(format!("commit sha deadbeef{i:02} reviewed"));
        benign.push(format!("ticket #{i} closed without customer data"));
    }
    while benign.len() < 100 {
        let n = benign.len();
        benign.push(format!("benign prose line {n} with no PII markers"));
    }
    benign
}

#[test]
fn pii_positive_corpus_recall() {
    let cases = positive_cases();
    assert!(
        cases.len() >= 100,
        "need ≥100 PII cases, got {}",
        cases.len()
    );

    let mut hits_ok = 0usize;
    let mut misses = Vec::new();
    for (det, text) in &cases {
        let found = find_pii(text).iter().any(|h| &h.detector_id == det);
        if found {
            hits_ok += 1;
        } else {
            misses.push(format!("{det}: {text}"));
        }
    }
    let recall = hits_ok as f64 / cases.len() as f64;
    assert!(
        misses.is_empty(),
        "PII recall misses {}/{} (recall={recall:.3}): {:?}",
        misses.len(),
        cases.len(),
        misses.iter().take(8).collect::<Vec<_>>()
    );
}

#[test]
fn pii_benign_precision() {
    let benign = benign_cases();
    assert!(benign.len() >= 100);

    let mut fps = 0usize;
    let mut card_fps = 0usize;
    for b in &benign {
        let hits = find_pii(b);
        fps += hits.len();
        card_fps += hits
            .iter()
            .filter(|h| h.detector_id == "credit_card")
            .count();
    }
    assert_eq!(card_fps, 0, "credit card FPs on order/build ids");
    // Spec ≥95% PII precision on benign lookalikes (no true PII in corpus).
    let precision = 1.0 - (fps as f64 / benign.len() as f64);
    assert!(
        precision >= 0.95,
        "PII precision too low on benign corpus: fps={fps}/{} => {precision:.3}",
        benign.len()
    );
}
