package com.aisecurityguard;

import com.aisecurityguard.approval.ApprovedExecution;
import com.aisecurityguard.domain.ApprovalDecision;
import com.aisecurityguard.domain.ApprovalOutcome;
import com.aisecurityguard.domain.ApprovalRequest;
import com.aisecurityguard.domain.ApprovalToken;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.EvidenceReliability;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.tool.SimulationWorld;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The human approval gate and the remediation cycle.
 *
 * <p>The prototype stated that "approval is enforced by the runtime policy layer, not merely by an
 * AI prompt" but enforced it with a UI condition. These tests exist to prove the enforcement is
 * now structural: the negative cases below are the important ones, because a control that is only
 * demonstrated on the happy path has not been demonstrated at all.
 */
class ApprovalWorkflowTest {

    // ==================================================================
    // The gate blocks execution
    // ==================================================================

    @Nested
    @DisplayName("Execution is impossible without a human")
    class GateEnforcement {

        @Test
        @DisplayName("a proposed A2 action requires approval and starts PENDING")
        void a2StartsPending() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();
            var status = run.caseManagement().approvalStatusFor(run.securityCase());

            assertThat(status.approvalRequired()).isTrue();
            assertThat(status.outcome()).isEqualTo(ApprovalOutcome.PENDING);
            assertThat(run.securityCase().lifecycle()).isEqualTo(CaseLifecycle.ASSESSED);
        }

        @Test
        @DisplayName("remediating with no token at all is refused")
        void noTokenIsRefused() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();

            assertThatThrownBy(() -> run.caseManagement()
                    .remediateAndVerify(run.securityCase(), null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("without an approval token");

            assertThat(run.securityCase().lifecycle())
                    .as("nothing may have been executed")
                    .isEqualTo(CaseLifecycle.ASSESSED);
        }

        @Test
        @DisplayName("there is no token to obtain before a human decides")
        void noTokenBeforeDecision() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();

            assertThat(run.caseManagement().tokenFor(run.securityCase()))
                    .as("an approval token exists only after a human approved")
                    .isEmpty();
        }

        @Test
        @DisplayName("a token cannot be fabricated by another component")
        void tokensCannotBeMintedFreely() {
            assertThatThrownBy(() -> ApprovalToken.mintFor(
                    "com.example.SomeOtherCaller", "CASE-VUL-001", "attacker",
                    java.time.LocalTime.NOON, com.aisecurityguard.domain.ActionImpact.A2))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("may only be issued by the approval gate");
        }

        @Test
        @DisplayName("an approval token cannot authorise a different case")
        void tokenIsBoundToItsCase() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();
            run.caseManagement().decide(run.securityCase(),
                    ApprovalRequest.approvedBy("CASE-VUL-001", "analyst.chris",
                            run.clock().tick()));
            ApprovalToken token = run.caseManagement().tokenFor(run.securityCase()).orElseThrow();

            var otherCase = new com.aisecurityguard.domain.SecurityCase(
                    "CASE-OTHER-999", "some-other-asset", "CVE-2021-41773");

            assertThatThrownBy(() -> run.caseManagement().remediateAndVerify(otherCase, token))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("cannot authorise execution on case");
        }

        @Test
        @DisplayName("a case that needs no approval cannot be approved either")
        void cannotApproveWhatNeedsNoApproval() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.negativeNoApprovalNeeded();

            assertThat(run.caseManagement().approvalStatusFor(run.securityCase()).approvalRequired())
                    .isFalse();
            assertThatThrownBy(() -> run.caseManagement().decide(run.securityCase(),
                    ApprovalRequest.approvedBy("CASE-VUL-002", "analyst.chris",
                            run.clock().tick())))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("is not awaiting a human approval decision");
        }
    }

    // ==================================================================
    // The happy path
    // ==================================================================

    @Nested
    @DisplayName("Approved remediation and verification")
    class ApprovedRemediation {

        @Test
        @DisplayName("approval issues a token and the case reaches RESOLVED")
        void approvedCaseResolves() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveApprovedAndRemediated();

            assertThat(run.securityCase().lifecycle()).isEqualTo(CaseLifecycle.RESOLVED);
            assertThat(new java.util.ArrayList<>(run.auditEventTypes()))
                    .containsSubsequence(
                            "HUMAN_APPROVAL", "REMEDIATION_STARTED", "REMEDIATION_EXECUTED",
                            "TOOL_INVOKED", "VERIFICATION_PASSED", "CASE_RESOLVED");
        }

        @Test
        @DisplayName("verification produces independent evidence for each check")
        void verificationProducesEvidence() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveApprovedAndRemediated();

            // Three post-remediation evidence records, one per check, on top of E-001..E-004.
            assertThat(run.securityCase().evidence())
                    .filteredOn(e -> e.type().contains("post-remediation"))
                    .hasSize(3)
                    .allSatisfy(e -> assertThat(e.reliability())
                            .isEqualTo(EvidenceReliability.HIGH));

            assertThat(run.securityCase().evidenceIds())
                    .containsExactly("E-001", "E-002", "E-003", "E-004", "E-005", "E-006", "E-007");
        }

        @Test
        @DisplayName("a backup is taken because the approval screen promised one")
        void backupIsTaken() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveApprovedAndRemediated();

            assertThat(run.auditTrail()).contains("Creating backup...");
        }

        @Test
        @DisplayName("the post-fix world is a new world, not a mutation of the observed one")
        void observedWorldIsNotMutated() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveApprovedAndRemediated();

            // The world the assessment was formed against must still read as it did, or the audit
            // trail would describe a machine that never existed.
            SimulationWorld observed = run.caseManagement()
                    .observedWorldFor(run.securityCase()).orElseThrow();
            assertThat(observed.runtimeVersion())
                    .as("the investigated world is preserved unchanged")
                    .isEqualTo("2.4.49");
        }

        @Test
        @DisplayName("an approval authorises exactly one execution")
        void approvalIsSingleUse() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();
            run.caseManagement().decide(run.securityCase(),
                    ApprovalRequest.approvedBy("CASE-VUL-001", "analyst.chris",
                            run.clock().tick()));
            ApprovalToken token = run.caseManagement().tokenFor(run.securityCase()).orElseThrow();

            run.caseManagement().remediateAndVerify(run.securityCase(), token);
            assertThat(token.isConsumed()).isTrue();

            assertThatThrownBy(() -> run.caseManagement()
                    .remediateAndVerify(run.securityCase(), token))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("already been used");
        }

        @Test
        @DisplayName("the human decision cannot be re-taken to mint a second token")
        void decisionCannotBeReTaken() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();
            run.caseManagement().decide(run.securityCase(),
                    ApprovalRequest.approvedBy("CASE-VUL-001", "analyst.chris",
                            run.clock().tick()));

            // Re-approval is refused because the case is no longer ASSESSED, and the gate itself
            // also refuses a second decision.
            assertThatThrownBy(() -> run.caseManagement().decide(run.securityCase(),
                    ApprovalRequest.approvedBy("CASE-VUL-001", "analyst.chris",
                            run.clock().tick())))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        @DisplayName("the finding status is never overwritten by resolution")
        void findingStatusSurvivesResolution() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveApprovedAndRemediated();

            assertThat(run.securityCase().assessment().findingStatus())
                    .as("resolution is a lifecycle fact, not a change to what was found")
                    .isEqualTo(FindingStatus.CONFIRMED_VULNERABLE);
            assertThat(run.securityCase().lifecycle()).isEqualTo(CaseLifecycle.RESOLVED);
        }
    }

    // ==================================================================
    // Rejection and failure
    // ==================================================================

    @Nested
    @DisplayName("Rejection and failed verification")
    class RejectionAndFailure {

        @Test
        @DisplayName("rejection executes nothing and routes the case to an analyst")
        void rejectionBlocksEverything() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveRejected();

            assertThat(run.securityCase().lifecycle()).isEqualTo(CaseLifecycle.ESCALATED);
            assertThat(run.securityCase().isAutomaticRemediationBlocked()).isTrue();
            assertThat(run.auditEventTypes())
                    .as("nothing may have been executed")
                    .doesNotContain("REMEDIATION_STARTED", "REMEDIATION_EXECUTED",
                            "VERIFICATION_PASSED");
            assertThat(run.auditTrail()).contains("nothing was executed");
        }

        @Test
        @DisplayName("a rejected case yields no token")
        void rejectionYieldsNoToken() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveRejected();

            assertThat(run.caseManagement().approvalStatusFor(run.securityCase()).outcome())
                    .isEqualTo(ApprovalOutcome.REJECTED);
            assertThat(run.caseManagement().tokenFor(run.securityCase()))
                    .as("a rejection can never authorise execution")
                    .isEmpty();
        }

        @Test
        @DisplayName("a rejection must record a reason")
        void rejectionRequiresReason() {
            assertThatThrownBy(() -> ApprovalRequest.rejectedBy(
                    "CASE-VUL-001", "analyst.chris", java.time.LocalTime.NOON, "  "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must record a reason");
        }

        @Test
        @DisplayName("an unattributable approval is not an approval")
        void approvalMustBeAttributed() {
            assertThatThrownBy(() -> ApprovalRequest.approvedBy(
                    "CASE-VUL-001", "  ", java.time.LocalTime.NOON))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not be blank");
        }

        @Test
        @DisplayName("the gate records who approved and what impact they approved")
        void approvalIsAttributed() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();
            run.caseManagement().decide(run.securityCase(),
                    ApprovalRequest.approvedBy("CASE-VUL-001", "analyst.chris",
                            run.clock().tick()));

            var status = run.caseManagement().approvalStatusFor(run.securityCase());
            assertThat(status.outcome()).isEqualTo(ApprovalOutcome.APPROVED);
            assertThat(run.auditTrail()).contains("APPROVED by analyst.chris");
        }

        @Test
        @DisplayName("the conflict case can never be approved, because it proposes no action")
        void escalatedCaseIsNotApprovable() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.conflictEscalated();

            assertThat(run.securityCase().lifecycle()).isEqualTo(CaseLifecycle.ESCALATED);
            assertThat(run.caseManagement().approvalStatusFor(run.securityCase()).approvalRequired())
                    .isFalse();
            assertThat(run.caseManagement().approvalStatusFor(run.securityCase()).outcome())
                    .isEqualTo(ApprovalOutcome.NOT_REQUIRED);
        }

        @Test
        @DisplayName("a human analyst can take over an escalated case")
        void analystCanTakeOver() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.conflictEscalated();

            run.caseManagement().takeOver(run.securityCase(), "analyst.chris");

            assertThat(run.auditTrail()).contains("CASE_TAKEN_OVER");
            assertThat(run.auditTrail()).contains("assigned to analyst analyst.chris");
        }

        @Test
        @DisplayName("a case that is not escalated cannot be taken over")
        void takeOverRequiresEscalation() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.negativeNoApprovalNeeded();

            assertThatThrownBy(() -> run.caseManagement().takeOver(run.securityCase(), "analyst.chris"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("is not escalated");
        }
    }

    // ==================================================================
    // Containment
    // ==================================================================

    @Nested
    @DisplayName("Remediation is contained")
    class Containment {

        @Test
        @DisplayName("only catalogued remediation actions exist")
        void onlyCataloguedActionsExist() {
            var catalog = new com.aisecurityguard.remediation.RemediationActionCatalog();

            assertThat(catalog.actionIds()).containsExactlyInAnyOrder(
                    "upgrade-apache-httpd", "restrict-service-exposure");
        }

        @Test
        @DisplayName("a vulnerability with no catalogued action cannot be remediated at all")
        void unknownVulnerabilityCannotBeRemediated() {
            var catalog = new com.aisecurityguard.remediation.RemediationActionCatalog();
            var unknownCase = new com.aisecurityguard.domain.SecurityCase(
                    "CASE-UNKNOWN-1", "asset-01", "CVE-9999-00000");

            assertThatThrownBy(() -> catalog.resolveFor(unknownCase))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("no predefined remediation action")
                    .hasMessageContaining("Arbitrary remediation is not permitted");
        }

        @Test
        @DisplayName("a successful fix genuinely changes the observed runtime version")
        void fixChangesTheWorld() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();
            assertThat(run.caseManagement().observedWorldFor(run.securityCase()).orElseThrow()
                    .isRuntimeAffected()).isTrue();

            run.caseManagement().decide(run.securityCase(),
                    ApprovalRequest.approvedBy("CASE-VUL-001", "analyst.chris", run.clock().tick()));
            var result = run.caseManagement().remediateAndVerify(
                    run.securityCase(), run.caseManagement().tokenFor(run.securityCase()).orElseThrow());

            assertThat(result.remediation().postFixWorld().isRuntimeAffected())
                    .as("verification must observe a genuinely patched host")
                    .isFalse();
            assertThat(result.verification().passed()).isTrue();
            assertThat(result.verification().observedVersion()).isEqualTo("2.4.58");
            assertThat(result.verification().checks()).hasSize(3)
                    .allSatisfy(check -> assertThat(check.passed()).isTrue());
        }

        @Test
        @DisplayName("verification fails when the fix did not take effect, and the case does not resolve")
        void verificationFailsWhenFixDidNotTake() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();
            run.caseManagement().decide(run.securityCase(),
                    ApprovalRequest.approvedBy("CASE-VUL-001", "analyst.chris", run.clock().tick()));

            // A world in which the "fix" did not change anything. Verification must observe the
            // still-affected version and refuse to call it resolved.
            var verifier = new com.aisecurityguard.verification.ToolBasedRemediationVerifier(
                    com.aisecurityguard.tool.ToolRegistry.of(
                            new com.aisecurityguard.tool.InspectServiceTool(),
                            new com.aisecurityguard.tool.ValidateVulnerabilityTool(),
                            new com.aisecurityguard.tool.CheckServiceHealthTool()),
                    run.auditLog(), run.clock());

            var verification = verifier.verify(
                    run.securityCase(), com.aisecurityguard.scenario.Scenarios.confirmedVulnerableWorld());

            assertThat(verification.passed())
                    .as("a target still running the affected version is not fixed")
                    .isFalse();
            assertThat(verification.checks())
                    .filteredOn(check -> !check.passed())
                    .extracting(com.aisecurityguard.verification.RemediationVerification.Check::name)
                    .contains("Version Check", "Vulnerability Validation");
            assertThat(run.securityCase().lifecycle())
                    .as("a failed verification must not resolve the case")
                    .isEqualTo(CaseLifecycle.ESCALATED);
            assertThat(run.securityCase().isAutomaticRemediationBlocked()).isTrue();
            assertThat(run.auditEventTypes()).contains("VERIFICATION_FAILED");
        }

        @Test
        @DisplayName("the decision recorded is APPROVED for an approved case")
        void decisionIsRecorded() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();
            run.caseManagement().decide(run.securityCase(),
                    ApprovalRequest.approvedBy("CASE-VUL-001", "analyst.chris", run.clock().tick()));

            assertThat(run.auditTrail()).contains("HUMAN_APPROVAL");
            assertThat(run.securityCase().isAutomaticRemediationBlocked()).isFalse();
        }

        @Test
        @DisplayName("the negative scenario never reaches any remediation stage")
        void negativeCaseNeverRemediates() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.negativeNoApprovalNeeded();

            assertThat(run.securityCase().lifecycle()).isEqualTo(CaseLifecycle.CLEARED);
            assertThat(run.auditEventTypes())
                    .doesNotContain("REMEDIATION_STARTED", "HUMAN_APPROVAL", "VERIFICATION_PASSED");
        }
    }
}
