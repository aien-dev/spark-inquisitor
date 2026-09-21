use crate::audit::DiffAuditor;
use crate::eval::TestimonyEvaluator;
use aien_evaluation_protocol::{
    EvaluationError, EvaluationPlan, Evaluator, EvaluatorDescriptor, EvaluatorIdentity,
    EvaluatorOutcome, EvaluatorStatus, Finding, Measurement,
};
use aien_protocol_types::{ArtifactRef, Digest32};

pub struct InquisitorDiffEvaluator {
    diff_payload: Option<String>,
}

impl InquisitorDiffEvaluator {
    pub fn new() -> Self {
        Self { diff_payload: None }
    }

    pub fn with_diff(diff: String) -> Self {
        Self {
            diff_payload: Some(diff),
        }
    }
}

impl Default for InquisitorDiffEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Evaluator for InquisitorDiffEvaluator {
    fn descriptor(&self) -> EvaluatorDescriptor {
        EvaluatorDescriptor {
            evaluator_id: "spark-inquisitor-diff-auditor".to_string(),
            version: "0.2.0".to_string(),
            required: true,
        }
    }

    async fn evaluate(
        &self,
        _plan: &EvaluationPlan,
        _subject: &ArtifactRef,
    ) -> Result<EvaluatorOutcome, EvaluationError> {
        let diff_text = self.diff_payload.as_deref().unwrap_or("");
        let report = DiffAuditor::audit_diff(diff_text);

        let mut findings = Vec::new();
        for v in &report.violations {
            findings.push(Finding {
                severity: "Fatal".to_string(),
                rule_id: "CONSTITUTIONAL_TELEMETRY".to_string(),
                message: v.clone(),
                location: None,
            });
        }
        for s in &report.secret_violations {
            findings.push(Finding {
                severity: "Fatal".to_string(),
                rule_id: "ZERO_DISK_SECRETS".to_string(),
                message: s.clone(),
                location: None,
            });
        }
        for u in &report.unslop_violations {
            findings.push(Finding {
                severity: "InvariantViolation".to_string(),
                rule_id: "SOVEREIGN_UNSLOP".to_string(),
                message: u.clone(),
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
                metric: "telemetry_violations".to_string(),
                value: report.violations.len() as f64,
                unit: "count".to_string(),
            },
            Measurement {
                metric: "secret_violations".to_string(),
                value: report.secret_violations.len() as f64,
                unit: "count".to_string(),
            },
            Measurement {
                metric: "unslop_violations".to_string(),
                value: report.unslop_violations.len() as f64,
                unit: "count".to_string(),
            },
        ];

        let mut outcome = EvaluatorOutcome {
            evaluator: EvaluatorIdentity {
                evaluator_id: "spark-inquisitor-diff-auditor".to_string(),
                version: "0.2.0".to_string(),
                binary_digest: Digest32([0xaa; 32]),
                config_digest: Digest32([0xbb; 32]),
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

pub struct InquisitorConstitutionalEvaluator {
    testimony_payload: Option<String>,
}

impl InquisitorConstitutionalEvaluator {
    pub fn new() -> Self {
        Self {
            testimony_payload: None,
        }
    }

    pub fn with_testimony(testimony: String) -> Self {
        Self {
            testimony_payload: Some(testimony),
        }
    }
}

impl Default for InquisitorConstitutionalEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Evaluator for InquisitorConstitutionalEvaluator {
    fn descriptor(&self) -> EvaluatorDescriptor {
        EvaluatorDescriptor {
            evaluator_id: "spark-inquisitor-constitution".to_string(),
            version: "0.2.0".to_string(),
            required: true,
        }
    }

    async fn evaluate(
        &self,
        _plan: &EvaluationPlan,
        _subject: &ArtifactRef,
    ) -> Result<EvaluatorOutcome, EvaluationError> {
        let testimony_text = self.testimony_payload.as_deref().unwrap_or("");
        let verdict = TestimonyEvaluator::evaluate(testimony_text);

        let mut findings = Vec::new();
        if !verdict.approved {
            findings.push(Finding {
                severity: "Fatal".to_string(),
                rule_id: "CONSTITUTIONAL_OATH_INCOMPLETE".to_string(),
                message: verdict.reason,
                location: None,
            });
        }

        let status = if verdict.approved {
            EvaluatorStatus::Passed
        } else {
            EvaluatorStatus::Failed
        };

        let measurements = vec![Measurement {
            metric: "alignment_score".to_string(),
            value: verdict.score as f64,
            unit: "score".to_string(),
        }];

        let mut outcome = EvaluatorOutcome {
            evaluator: EvaluatorIdentity {
                evaluator_id: "spark-inquisitor-constitution".to_string(),
                version: "0.2.0".to_string(),
                binary_digest: Digest32([0xcc; 32]),
                config_digest: Digest32([0xdd; 32]),
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
