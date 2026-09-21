use aien_evaluation_protocol::{
    CanaryRollbackHarness, EvaluationPlan, Evaluator, EvaluatorDescriptor, EvaluatorStatus,
    SoftwareP256Signer, Verdict, VerifierIdentity, VerifierSigner,
};
use aien_protocol_types::{ArtifactRef, Digest32, EvaluationId, Timestamp};
use p256::ecdsa::SigningKey;
use spark_inquisitor::{InquisitorConstitutionalEvaluator, InquisitorDiffEvaluator};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn create_test_plan() -> EvaluationPlan {
    let mut plan = EvaluationPlan {
        evaluation_id: EvaluationId::new_v4(),
        subject: ArtifactRef {
            artifact_id: uuid::Uuid::new_v4(),
            digest: Digest32([0x11; 32]),
            media_type: "text/x-diff".to_string(),
            byte_size: 512,
        },
        profile: "sovereign-inquisitor-strict".to_string(),
        evaluators: vec![
            EvaluatorDescriptor {
                evaluator_id: "spark-inquisitor-diff-auditor".to_string(),
                version: "0.2.0".to_string(),
                required: true,
            },
            EvaluatorDescriptor {
                evaluator_id: "spark-inquisitor-constitution".to_string(),
                version: "0.2.0".to_string(),
                required: true,
            },
        ],
        baseline: None,
        sandbox_profile: "airgap".to_string(),
        policy_digest: Digest32([0x22; 32]),
        evaluator_manifest_digest: Digest32([0x33; 32]),
        plan_digest: Digest32::ZERO,
    };
    plan.plan_digest = plan.compute_plan_digest();
    plan
}

#[tokio::test]
async fn test_inquisitor_diff_evaluator_clean_pass() {
    let clean_diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 pub fn compute(x: u32) -> u32 {
+    x.saturating_add(42)
 }
"#;

    let eval = InquisitorDiffEvaluator::with_diff(clean_diff.to_string());
    let plan = create_test_plan();
    let subject = plan.subject.clone();

    let outcome = eval
        .evaluate(&plan, &subject)
        .await
        .expect("evaluation error");
    assert_eq!(outcome.status, EvaluatorStatus::Passed);
    assert!(outcome.findings.is_empty());
    assert_ne!(outcome.execution_digest, Digest32::ZERO);
}

#[tokio::test]
async fn test_inquisitor_diff_evaluator_telemetry_and_unslop_rejection() {
    let dirty_diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,5 @@
+// This is a crucial game-changer -- unleashing seamless telemetry
+use posthog_rs::Client;
 pub fn compute(x: u32) -> u32 {
     x + 1
 }
"#;

    let eval = InquisitorDiffEvaluator::with_diff(dirty_diff.to_string());
    let plan = create_test_plan();
    let subject = plan.subject.clone();

    let outcome = eval
        .evaluate(&plan, &subject)
        .await
        .expect("evaluation error");
    assert_eq!(outcome.status, EvaluatorStatus::Failed);
    assert!(!outcome.findings.is_empty());

    let rule_ids: Vec<&str> = outcome
        .findings
        .iter()
        .map(|f| f.rule_id.as_str())
        .collect();
    assert!(
        rule_ids.contains(&"CONSTITUTIONAL_TELEMETRY"),
        "Must catch posthog telemetry"
    );
    assert!(
        rule_ids.contains(&"SOVEREIGN_UNSLOP"),
        "Must catch em dash and buzzwords"
    );
}

#[tokio::test]
async fn test_inquisitor_constitutional_evaluator() {
    let good_testimony = "I affirm and swear my commitment to the Sovereign Contributor Oath. I certify zero telemetry, zero surveillance, and complete alignment with the constitution.";
    let eval_good = InquisitorConstitutionalEvaluator::with_testimony(good_testimony.to_string());

    let plan = create_test_plan();
    let subject = plan.subject.clone();

    let outcome_good = eval_good
        .evaluate(&plan, &subject)
        .await
        .expect("evaluation error");
    assert_eq!(outcome_good.status, EvaluatorStatus::Passed);

    let bad_testimony = "I decline to affirm the oath and intend to add tracking.";
    let eval_bad = InquisitorConstitutionalEvaluator::with_testimony(bad_testimony.to_string());
    let outcome_bad = eval_bad
        .evaluate(&plan, &subject)
        .await
        .expect("evaluation error");
    assert_eq!(outcome_bad.status, EvaluatorStatus::Failed);
}

#[tokio::test]
async fn test_inquisitor_canary_rollback_integration() {
    let signing_key = SigningKey::from_slice(&[88u8; 32]).expect("valid p256 signing key");
    let signer = Arc::new(SoftwareP256Signer::new(signing_key));
    let harness = CanaryRollbackHarness::new(
        VerifierIdentity {
            principal_id: "spark-inquisitor-sentinel".to_string(),
            key_id: signer.key_fingerprint(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([0x44; 32]),
            policy_bundle_digest: Digest32([0x55; 32]),
        },
        signer.clone(),
    );

    let plan = create_test_plan();
    let subject = plan.subject.clone();

    // 1. Violation triggers rollback
    let dirty_diff = "+ let _bad = \"\u{2014} em dash in diff\";";
    let diff_eval = Box::new(InquisitorDiffEvaluator::with_diff(dirty_diff.to_string()));
    let const_eval = Box::new(InquisitorConstitutionalEvaluator::with_testimony(
        "I certify and affirm the Sovereign Oath.".to_string(),
    ));
    let evaluators: Vec<Box<dyn Evaluator>> = vec![diff_eval, const_eval];

    let rollback_triggered = Arc::new(AtomicBool::new(false));
    let rollback_clone = rollback_triggered.clone();

    let (receipt, _) = harness
        .evaluate_and_enforce(
            &plan,
            &subject,
            &evaluators,
            Timestamp(100),
            || async move {
                rollback_clone.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .expect("harness evaluation failed");

    assert!(
        rollback_triggered.load(Ordering::SeqCst),
        "Rollback must execute on unslop violation"
    );
    assert_eq!(receipt.receipt.verdict, Verdict::Fail);

    let verifying_key = signer.verifying_key();
    assert!(receipt.verify(&verifying_key).unwrap());
}
