use aien_evaluation_protocol::{
    CanaryRollbackHarness, EvaluationPlan, Evaluator, EvaluatorStatus, SoftwareP256Signer, Verdict,
    VerifierIdentity, VerifierSigner,
};
use aien_protocol_types::{ArtifactRef, Digest32, EvaluationId, Timestamp};
use p256::ecdsa::SigningKey;
use spark_inquisitor::probe_audit::{run_probe_audit, InquisitorProbeEvaluator};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[tokio::test]
async fn test_run_probe_audit_reference_is_deterministic() {
    let diff =
        "diff --git a/src/lib.rs b/src/lib.rs\n+ pub fn hello() -> &'static str { \"hello\" }";
    let r1 = run_probe_audit(diff, "reference", None, 0.0, 0.0)
        .await
        .unwrap();
    let r2 = run_probe_audit(diff, "reference", None, 0.0, 0.0)
        .await
        .unwrap();

    assert_eq!(r1.telemetry_probability, r2.telemetry_probability);
    assert_eq!(r1.unslop_probability, r2.unslop_probability);
    assert_eq!(r1.quality_score, r2.quality_score);
    assert_eq!(r1.classification, r2.classification);
    assert_eq!(r1.backend, "deterministic-reference-oracle");
}

#[tokio::test]
async fn test_inquisitor_probe_evaluator_outcome() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n+ pub fn compute() -> i32 { 100 }";
    let evaluator = InquisitorProbeEvaluator::with_diff(diff).with_thresholds(0.0, 0.0);

    let subject = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([0x12; 32]),
        media_type: "text/x-diff".to_string(),
        byte_size: 256,
    };
    let mut plan = EvaluationPlan {
        evaluation_id: EvaluationId::new_v4(),
        subject: subject.clone(),
        profile: "probe-audit".to_string(),
        evaluators: vec![evaluator.descriptor()],
        baseline: None,
        sandbox_profile: "airgap".to_string(),
        policy_digest: Digest32([0x22; 32]),
        evaluator_manifest_digest: Digest32([0x33; 32]),
        plan_digest: Digest32::ZERO,
    };
    plan.plan_digest = plan.compute_plan_digest();

    let outcome = evaluator.evaluate(&plan, &subject).await.unwrap();
    assert_eq!(outcome.status, EvaluatorStatus::Passed);
    assert_eq!(outcome.measurements.len(), 3);
}

#[tokio::test]
async fn test_inquisitor_probe_evaluator_canary_rollback_integration() {
    let diff = "diff --git a/bad.rs b/bad.rs\n+ // test diff";
    // Threshold set impossibly high so it triggers failure and rollback
    let evaluator = InquisitorProbeEvaluator::with_diff(diff).with_thresholds(0.99999, 3.99999);
    let descriptor = evaluator.descriptor();

    let signing_key = SigningKey::from_slice(&[42u8; 32]).unwrap();
    let signer = Arc::new(SoftwareP256Signer::new(signing_key));
    let verifier = VerifierIdentity {
        principal_id: "inquisitor-daemon".to_string(),
        key_id: signer.key_fingerprint(),
        trust_epoch: 1,
        trusted_build_digest: Digest32([0x44; 32]),
        policy_bundle_digest: Digest32([0x55; 32]),
    };
    let harness = CanaryRollbackHarness::new(verifier, signer);

    let subject = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([0x66; 32]),
        media_type: "text/x-diff".to_string(),
        byte_size: 128,
    };
    let mut plan = EvaluationPlan {
        evaluation_id: EvaluationId::new_v4(),
        subject: subject.clone(),
        profile: "probe-canary".to_string(),
        evaluators: vec![descriptor],
        baseline: None,
        sandbox_profile: "airgap".to_string(),
        policy_digest: Digest32([0x77; 32]),
        evaluator_manifest_digest: Digest32([0x88; 32]),
        plan_digest: Digest32::ZERO,
    };
    plan.plan_digest = plan.compute_plan_digest();

    let rollback_executed = Arc::new(AtomicBool::new(false));
    let rollback_flag = rollback_executed.clone();
    let evaluators: Vec<Box<dyn Evaluator>> = vec![Box::new(evaluator)];

    let (receipt, outcomes) = harness
        .evaluate_and_enforce(
            &plan,
            &subject,
            &evaluators,
            Timestamp(1000),
            || async move {
                rollback_flag.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();

    assert_eq!(receipt.receipt.verdict, Verdict::Fail);
    assert_eq!(outcomes[0].status, EvaluatorStatus::Failed);
    assert!(rollback_executed.load(Ordering::SeqCst));
}
