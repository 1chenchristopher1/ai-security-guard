package com.aisecurityguard;

import com.aisecurityguard.agent.ConflictResolver;
import com.aisecurityguard.agent.ConflictStatus;
import com.aisecurityguard.domain.AgentDecisionType;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.EvidenceReliability;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.ToolStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TEST 3 - EVIDENCE CONFLICT -&gt; ESCALATE.
 *
 * <p>The scanner explicitly claims Apache 2.4.49. Runtime inspection observes 2.4.58. The agent
 * seeks independent confirmation with {@code validate_vulnerability}, and that validation cannot
 * resolve the disagreement. The agent must then escalate rather than force a verdict.
 *
 * <p>The central assertion in this class is a negative one: an inconclusive validation must never
 * be read as NOT_AFFECTED.
 */
class EvidenceConflictScenarioTest {

    @Test
    @DisplayName("Agent detects the conflict and selects validate_vulnerability")
    void detectsConflictAndSelectsIndependentValidation() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.evidenceConflict();

        assertThat(run.toolSequence()).containsExactly(
                "inspect_service",
                "validate_vulnerability");
    }

    @Test
    @DisplayName("validate_vulnerability returns INCONCLUSIVE, recorded as inconclusive evidence")
    void validationIsInconclusive() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.evidenceConflict();

        assertThat(run.securityCase().facts().getString("validationResult"))
                .contains("INCONCLUSIVE");

        // E-003 is the validation result; it must not claim to have resolved anything.
        var validationEvidence = run.securityCase().findEvidence("E-003");
        assertThat(validationEvidence).isPresent();
        assertThat(validationEvidence.get().reliability())
                .isEqualTo(EvidenceReliability.INCONCLUSIVE);
    }

    @Test
    @DisplayName("Agent escalates: UNDETERMINED at C3 with no priority assigned")
    void escalatesWithNoPriority() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.evidenceConflict();
        var assessment = run.securityCase().assessment();

        assertThat(assessment.findingStatus()).isEqualTo(FindingStatus.UNDETERMINED);
        assertThat(assessment.confidence()).isEqualTo(Confidence.C3);
        assertThat(assessment.priority())
                .as("no priority may be assigned when the finding is undetermined")
                .isNull();
    }

    @Test
    @DisplayName("Case is ESCALATED and automatic remediation is blocked on the case itself")
    void automaticRemediationBlocked() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.evidenceConflict();

        assertThat(run.securityCase().lifecycle()).isEqualTo(CaseLifecycle.ESCALATED);
        assertThat(run.securityCase().isAutomaticRemediationBlocked()).isTrue();
        assertThat(run.securityCase().escalationReason()).isPresent();
    }

    @Test
    @DisplayName("The framework infers the conflict is UNRESOLVED, which is what caps confidence")
    void frameworkInfersUnresolvedConflict() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.evidenceConflict();

        // The contradiction is still open: the scanner claims an affected version, the runtime
        // is not affected, and independent validation could not settle it. Crucially this status
        // is worked out from the evidence by the framework - the decision policy does not get to
        // declare its own conflict resolved.
        assertThat(new ConflictResolver().resolve(run.securityCase()))
                .isEqualTo(ConflictStatus.UNRESOLVED);

        var escalateDecision = run.securityCase().decisions().stream()
                .filter(d -> d.decisionType() == AgentDecisionType.ESCALATE)
                .findFirst()
                .orElseThrow();

        assertThat(escalateDecision.missingEvidence())
                .as("the gap that forced the escalation is recorded on the decision")
                .containsExactly("Reliable resolution of the version conflict");

        assertThat(run.securityCase().assessment().confidence()).isEqualTo(Confidence.C3);
        assertThat(run.auditTrail()).contains("C3");
    }

    @Test
    @DisplayName("An undetermined finding asserts no positive facts, so it has no reasons")
    void escalationCarriesNoReasons() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.evidenceConflict();

        assertThat(run.securityCase().assessment().reasons()).isEmpty();
    }

    @Test
    @DisplayName("Inconclusive validation is NOT interpreted as NOT_AFFECTED")
    void inconclusiveIsNotNotAffected() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.evidenceConflict();

        assertThat(run.securityCase().assessment().findingStatus())
                .as("a tool that cannot resolve the question must never dismiss the finding")
                .isNotEqualTo(FindingStatus.NOT_AFFECTED);

        assertThat(run.securityCase().lifecycle())
                .as("an unresolved conflict must not close the case")
                .isNotEqualTo(CaseLifecycle.CLEARED);
    }

    @Test
    @DisplayName("No remediation is proposed and no approval is requested")
    void nothingIsProposed() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.evidenceConflict();
        var assessment = run.securityCase().assessment();

        assertThat(assessment.proposedAction()).isNull();
        assertThat(assessment.actionImpact()).isNull();
        assertThat(assessment.requiresHumanApproval()).isFalse();
        assertThat(run.auditEventTypes()).doesNotContain("REMEDIATION_PROPOSED");
    }

    @Test
    @DisplayName("Tool status is INCONCLUSIVE, not FAILED and not SUCCESS")
    void toolStatusSemantics() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.evidenceConflict();

        var validationEvidence = run.securityCase().findEvidence("E-003").orElseThrow();
        assertThat(validationEvidence.type()).contains("inconclusive");

        // The status recorded by the tool must be a distinct outcome from a plain failure,
        // which is what lets policy distinguish "could not run" from "could not resolve".
        assertThat(ToolStatus.INCONCLUSIVE).isNotEqualTo(ToolStatus.FAILED);
        assertThat(ToolStatus.INCONCLUSIVE).isNotEqualTo(ToolStatus.SUCCESS);
    }

    @Test
    @DisplayName("Audit trail ends with escalate and an explicit remediation block")
    void auditTrail() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.evidenceConflict();

        assertThat(run.auditEventTypes()).containsExactly(
                "CASE_OPENED",
                "AGENT_DECISION", "TOOL_INVOKED", "EVIDENCE_CREATED",
                "AGENT_DECISION", "TOOL_INVOKED", "TOOL_INCONCLUSIVE",
                "AGENT_DECISION",
                "REMEDIATION_BLOCKED");

        System.out.println();
        System.out.println("=== TEST 3: EVIDENCE_CONFLICT -> ESCALATE (CASE-VUL-003) ===");
        System.out.println("--- evidence chain ---");
        System.out.println(run.evidenceChain());
        System.out.println("--- audit trail ---");
        System.out.println(run.auditTrail());
    }
}
