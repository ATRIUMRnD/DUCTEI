//! The generated Rust must be the same shape as the hand-written types the
//! stack already ships. If someone renames a field in ductei-limen without
//! touching the spec (or the other way round), this file stops compiling.

#![allow(dead_code)]

#[path = "../generated/atrium_spec.rs"]
mod generated;

/// Field-for-field conversion. Exhaustive destructuring on both sides means a
/// field added or renamed on either side is a compile error here.
fn to_handwritten(g: generated::CertSummary) -> ductei_limen::CertSummary {
    let generated::CertSummary {
        job_id,
        backend,
        tier,
        success_probability,
        target_met,
        lamport,
    } = g;
    ductei_limen::CertSummary {
        job_id,
        backend,
        tier,
        success_probability,
        target_met,
        lamport,
    }
}

#[test]
fn cert_summary_round_trips_through_limen_json() {
    let json = r#"{"job_id":"j1","backend":"sim","tier":1,"success_probability":0.97,"target_met":true,"lamport":7}"#;
    let hand = ductei_limen::CertSummary::from_json(json).unwrap();
    let gen: generated::CertSummary = serde_json::from_str(json).unwrap();
    assert_eq!(to_handwritten(gen), hand);
}

#[test]
fn scope_constant_agrees() {
    assert_eq!(generated::CERT_SCOPE, ductei_limen::CERT_SCOPE);
}
