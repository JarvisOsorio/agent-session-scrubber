use agentscrub::detectors::pii::find_pii;

#[test]
fn pii_positive_corpus() {
    let emails = (0..25)
        .map(|i| format!("user{i}@example.com"))
        .collect::<Vec<_>>();
    let phones = [
        "415-555-2671",
        "(212) 555-0199",
        "+1 310-555-0142",
        "646.555.0188",
        "202-555-0134",
    ];
    let ips = [
        "203.0.113.42",
        "198.51.100.7",
        "192.0.2.55",
        "8.8.8.8",
        "1.1.1.1",
    ];
    // Luhn-valid test PANs (synthetic)
    let cards = [
        "4111111111111111",
        "4000000000000002",
        "5555555555554444",
        "378282246310005",
        "6011111111111117",
    ];

    let mut cases = Vec::new();
    for e in &emails {
        cases.push(("email_address", e.clone()));
        cases.push(("email_address", format!("contact {e} please")));
    }
    for p in phones {
        for i in 0..5 {
            cases.push(("phone_number", format!("{p} ext {i}")));
        }
    }
    for ip in ips {
        for i in 0..5 {
            cases.push(("ipv4_address", format!("peer {ip} hop {i}")));
        }
    }
    for c in cards {
        for i in 0..5 {
            cases.push(("credit_card", format!("card {c} try {i}")));
        }
    }
    assert!(cases.len() >= 100);

    let mut misses = 0usize;
    for (det, text) in &cases {
        let hits = find_pii(text);
        if !hits.iter().any(|h| &h.detector_id == det) {
            misses += 1;
        }
    }
    assert_eq!(misses, 0, "PII recall misses: {misses}");
}

#[test]
fn pii_benign_lookalikes() {
    let benign: Vec<String> = (0..100)
        .map(|i| format!("order-{i:04} build-{i} version-1.2.{i}"))
        .collect();
    let mut card_fps = 0usize;
    for b in &benign {
        card_fps += find_pii(b)
            .iter()
            .filter(|h| h.detector_id == "credit_card")
            .count();
    }
    assert_eq!(card_fps, 0, "credit card FPs on order ids");
}
