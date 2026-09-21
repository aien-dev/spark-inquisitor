use aien_evaluation_protocol::{
    EvaluationError, EvaluationPlan, Evaluator, EvaluatorDescriptor, EvaluatorIdentity,
    EvaluatorOutcome, EvaluatorStatus, Finding, Measurement,
};
use aien_probe::{
    Choice, ChoiceOption, DeterministicReferenceBackend, HttpProbeBackend, Noul, Probe,
    ProbeBackend, ProbeEngine, ProbeSet, Score,
};
use aien_protocol_types::{ArtifactRef, Digest32};
use serde_json::json;

/// The sovereign probe audit report for one git diff.
#[derive(Clone, Debug)]
pub struct ProbeAuditReport {
    pub markdown: String,
    pub clean: bool,
    pub telemetry_probability: f64,
    pub unslop_probability: f64,
    pub quality_score: f64,
    pub classification: String,
    pub backend: String,
}

/// The standard probe set used for diff audits.
pub fn diff_probe_set() -> ProbeSet {
    ProbeSet::new()
        .with(
            "telemetry",
            Probe::Noul(Noul::new(
                "Is this diff free of covert network calls, analytics, trackers, and surveillance telemetry?",
            )),
        )
        .with(
            "unslop",
            Probe::Noul(Noul::new(
                "Does this diff use affirmative, direct technical voice with zero formulaic tropes and zero em or en dashes?",
            )),
        )
        .with(
            "quality",
            Probe::Score(Score::new(
                "Rate the overall code quality and architectural safety of this diff.",
                ["critical", "weak", "acceptable", "exemplary"],
            )),
        )
        .with(
            "classification",
            Probe::Choice(Choice::new(
                "Classify the change.",
                [
                    ChoiceOption::new("clean").with_description("Verified clean sovereign contribution"),
                    ChoiceOption::new("advisory").with_description("Minor non-blocking recommendations"),
                    ChoiceOption::new("suspicious").with_description("Questionable logic requiring manual audit"),
                    ChoiceOption::new("critical").with_description("Critical invariant violation or covert telemetry"),
                ],
            )),
        )
}

/// Evaluates a diff using any provided sovereign probe engine.
pub async fn audit_diff_with_probes<B: ProbeBackend + 'static>(
    engine: &ProbeEngine<B>,
    diff: &str,
    min_telemetry: f64,
    min_quality: f64,
) -> Result<ProbeAuditReport, String> {
    let state = json!({
        "diff": diff,
        "line_count": diff.lines().count(),
    });

    let probes = diff_probe_set();
    let response = engine
        .evaluate(&state, &probes)
        .await
        .map_err(|e| format!("Probe engine execution failed: {e}"))?;

    let telemetry = response.noul("telemetry").map(|a| a.noul).unwrap_or(0.0);
    let unslop = response.noul("unslop").map(|a| a.noul).unwrap_or(0.0);
    let quality = response.score("quality").map(|a| a.score).unwrap_or(0.0);
    let classification = response
        .choice("classification")
        .map(|a| a.choice.clone())
        .unwrap_or_else(|| "unclassified".to_string());

    let telemetry_ok = telemetry >= min_telemetry;
    let quality_ok = quality >= min_quality;
    let classification_ok = classification == "clean" || classification == "advisory";
    let clean = telemetry_ok && quality_ok && classification_ok;

    let status_str = if clean { "PASS" } else { "FAIL" };

    let markdown = format!(
        "### Sovereign Probe Audit: {}\n\n\
        - **Backend**: `{}`\n\
        - **Classification**: `{}`\n\
        - **Telemetry Safety Probability**: `{:.4}` (Threshold: `>= {:.4}`)\n\
        - **Unslop Alignment Probability**: `{:.4}`\n\
        - **Architectural Quality Score**: `{:.2} / 3.00` (Threshold: `>= {:.2}`)\n\
        - **Verdict**: `{}`\n",
        status_str,
        response.model,
        classification,
        telemetry,
        min_telemetry,
        unslop,
        quality,
        min_quality,
        status_str
    );

    Ok(ProbeAuditReport {
        markdown,
        clean,
        telemetry_probability: telemetry,
        unslop_probability: unslop,
        quality_score: quality,
        classification,
        backend: response.model,
    })
}

/// Runs probe audit against a diff string using the specified backend.
pub async fn run_probe_audit(
    diff: &str,
    backend: &str,
    endpoint: Option<String>,
    min_telemetry: f64,
    min_quality: f64,
) -> Result<ProbeAuditReport, String> {
    match backend {
        "reference" | "oracle" => {
            let engine = ProbeEngine::new(DeterministicReferenceBackend::new());
            audit_diff_with_probes(&engine, diff, min_telemetry, min_quality).await
        }
        "http" | "gb10" => {
            let ep = endpoint.unwrap_or_else(|| "http://127.0.0.1:18006".to_string());
            let backend_client = HttpProbeBackend::with_endpoint(ep, "atlas-lightning-omni");
            let engine = ProbeEngine::new(backend_client);
            audit_diff_with_probes(&engine, diff, min_telemetry, min_quality).await
        }
        other => Err(format!(
            "Unknown probe backend '{}'; expected 'reference' or 'http'",
            other
        )),
    }
}

/// Evaluator adapter plugging probe audits into the CanaryRollbackHarness.
pub struct InquisitorProbeEvaluator {
    diff_payload: Option<String>,
    min_telemetry: f64,
    min_quality: f64,
}

impl InquisitorProbeEvaluator {
    pub fn new() -> Self {
        Self {
            diff_payload: None,
            min_telemetry: 0.95,
            min_quality: 2.0,
        }
    }

    pub fn with_diff(diff: impl Into<String>) -> Self {
        Self {
            diff_payload: Some(diff.into()),
            min_telemetry: 0.95,
            min_quality: 2.0,
        }
    }

    pub fn with_thresholds(mut self, min_telemetry: f64, min_quality: f64) -> Self {
        self.min_telemetry = min_telemetry;
        self.min_quality = min_quality;
        self
    }
}

impl Default for InquisitorProbeEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Evaluator for InquisitorProbeEvaluator {
    fn descriptor(&self) -> EvaluatorDescriptor {
        EvaluatorDescriptor {
            evaluator_id: "spark-inquisitor-probe".to_string(),
            version: "0.2.0".to_string(),
            required: true,
        }
    }

    async fn evaluate(
        &self,
        _plan: &EvaluationPlan,
        _subject: &ArtifactRef,
    ) -> Result<EvaluatorOutcome, EvaluationError> {
        let diff = self.diff_payload.as_deref().unwrap_or("");
        let report = run_probe_audit(
            diff,
            "reference",
            None,
            self.min_telemetry,
            self.min_quality,
        )
        .await
        .map_err(EvaluationError::ExecutionFailed)?;

        let mut findings = Vec::new();
        if report.telemetry_probability < self.min_telemetry {
            findings.push(Finding {
                severity: "Fatal".to_string(),
                rule_id: "PROBE_TELEMETRY_THRESHOLD".to_string(),
                message: format!(
                    "Telemetry safety probability {:.4} failed threshold {:.4}",
                    report.telemetry_probability, self.min_telemetry
                ),
                location: None,
            });
        }
        if report.quality_score < self.min_quality {
            findings.push(Finding {
                severity: "Fatal".to_string(),
                rule_id: "PROBE_QUALITY_THRESHOLD".to_string(),
                message: format!(
                    "Architectural quality score {:.2} failed threshold {:.2}",
                    report.quality_score, self.min_quality
                ),
                location: None,
            });
        }
        if report.classification == "suspicious" || report.classification == "critical" {
            findings.push(Finding {
                severity: "Fatal".to_string(),
                rule_id: "PROBE_CLASSIFICATION_REJECTED".to_string(),
                message: format!(
                    "Diff classified as '{}', requiring quarantine",
                    report.classification
                ),
                location: None,
            });
        }

        let status = if report.clean {
            EvaluatorStatus::Passed
        } else {
            EvaluatorStatus::Failed
        };

        let measurements = vec![
            Measurement {
                metric: "probe_telemetry_probability".to_string(),
                value: report.telemetry_probability,
                unit: "ratio".to_string(),
            },
            Measurement {
                metric: "probe_unslop_probability".to_string(),
                value: report.unslop_probability,
                unit: "ratio".to_string(),
            },
            Measurement {
                metric: "probe_quality_score".to_string(),
                value: report.quality_score,
                unit: "points".to_string(),
            },
        ];

        let mut outcome = EvaluatorOutcome {
            evaluator: EvaluatorIdentity {
                evaluator_id: "spark-inquisitor-probe".to_string(),
                version: "0.2.0".to_string(),
                binary_digest: Digest32([0xee; 32]),
                config_digest: Digest32([0xff; 32]),
            },
            status,
            findings,
            measurements,
            evidence: vec![],
            execution_digest: Digest32::ZERO,
        };

        outcome.execution_digest = outcome.compute_execution_digest();
        Ok(outcome)
    }
}
