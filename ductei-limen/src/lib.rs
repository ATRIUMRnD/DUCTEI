//! LIMEN adapter. Closed type: only certificate summary fields exist --
//! api tokens / qpu credentials / raw quantum traffic are unrepresentable.
//! serde silently drops unknown fields before anything reaches the channel.
use ductei_core::{scoped, Envelope};
use serde::Deserialize;

/// Closed type. No credential fields. Unknown JSON fields are dropped.
///
/// `success_probability` is what limend writes since LIMEN #37 (Oct 2026).
/// Older limend releases wrote the same value as `fidelity_estimate`, and
/// #37 keeps writing both for one release. Either spelling is accepted; the
/// JSON may carry one or both. `target_met` is optional so pre-#37 certs
/// still parse.
#[derive(Debug, Clone, PartialEq)]
pub struct CertSummary {
    pub job_id: String,
    pub backend: String,
    pub tier: u8,
    pub success_probability: f64,
    pub target_met: Option<bool>,
    pub lamport: u64,
}

/// Wire shape as limend writes it. Kept private so the only public type is
/// the closed `CertSummary`. Both probability spellings are optional here
/// because serde's `alias` rejects a document that carries both keys, and
/// #37 does exactly that during the deprecation window.
#[derive(Deserialize)]
struct CertSummaryWire {
    job_id: String,
    backend: String,
    tier: u8,
    #[serde(default)]
    success_probability: Option<f64>,
    #[serde(default)]
    fidelity_estimate: Option<f64>,
    #[serde(default)]
    target_met: Option<bool>,
    lamport: u64,
}

impl CertSummary {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let w: CertSummaryWire = serde_json::from_str(json)?;
        let success_probability = match (w.success_probability, w.fidelity_estimate) {
            (Some(p), _) => p,
            (None, Some(p)) => p,
            (None, None) => {
                return Err(<serde_json::Error as serde::de::Error>::missing_field(
                    "success_probability (or deprecated fidelity_estimate)",
                ))
            }
        };
        Ok(CertSummary {
            job_id: w.job_id,
            backend: w.backend,
            tier: w.tier,
            success_probability,
            target_met: w.target_met,
            lamport: w.lamport,
        })
    }
}

pub const CERT_SCOPE: &str = "qallow.semantic.cert";

pub fn cert_to_envelope(json: &str, node: [u8; 16]) -> Result<Envelope, serde_json::Error> {
    let c = CertSummary::from_json(json)?;
    // `fidelity_estimate` is still emitted on the wire, equal to
    // `success_probability`, so existing envelope readers keep working
    // through the same deprecation window LIMEN gives its cert readers.
    let blob = serde_json::to_vec(&serde_json::json!({
        "job_id": c.job_id, "backend": c.backend, "tier": c.tier,
        "success_probability": c.success_probability,
        "fidelity_estimate": c.success_probability,
        "target_met": c.target_met,
    }))?;
    Ok(scoped(&format!("limen.cert.{}", c.job_id), &[CERT_SCOPE], node, c.lamport, &blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_new_spelling() {
        let c = CertSummary::from_json(
            r#"{"job_id":"j","backend":"aer_gpu","tier":0,"success_probability":0.91,
                "fidelity_target":0.9,"target_met":true,"lamport":3}"#,
        )
        .unwrap();
        assert_eq!(c.success_probability, 0.91);
        assert_eq!(c.target_met, Some(true));
    }

    #[test]
    fn accepts_deprecated_alias() {
        let c = CertSummary::from_json(
            r#"{"job_id":"j","backend":"ibm_fez","tier":2,"fidelity_estimate":0.97,"lamport":9}"#,
        )
        .unwrap();
        assert_eq!(c.success_probability, 0.97);
        assert_eq!(c.target_met, None);
    }

    #[test]
    fn accepts_both_prefers_new() {
        // LIMEN #37 writes both during the deprecation window.
        let c = CertSummary::from_json(
            r#"{"job_id":"j","backend":"x","tier":1,"success_probability":0.5,
                "fidelity_estimate":0.5,"lamport":1}"#,
        )
        .unwrap();
        assert_eq!(c.success_probability, 0.5);
    }

    #[test]
    fn rejects_neither() {
        assert!(CertSummary::from_json(
            r#"{"job_id":"j","backend":"x","tier":1,"lamport":1}"#
        )
        .is_err());
    }
}
