package com.aisecurityguard;

import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.Priority;
import com.aisecurityguard.domain.SecurityCase;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TEST 2 - NOT_AFFECTED.
 *
 * <p>This is the scenario that proves the workflow is evidence-driven rather than a fixed tool
 * sequence. The scanner raised a finding, runtime inspection contradicted it, and because the
 * scanner made no specific version claim there is nothing to resolve. The agent must stop after a
 * single tool, propose nothing, and request nothing.
 */
class NotAffectedScenarioTest {

    @Test
    @DisplayName("Agent stops after inspect_service and calls no other tool")
    void stopsAfterSingleTool() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.notAffected();

        assertThat(run.toolSequence())
                .as("an evidence-driven agent must not run a fixed playbook")
                .containsExactly("inspect_service");
    }

    @Test
    @DisplayName("Only two evidence items: the scanner finding and the runtime version")
    void minimalEvidenceChain() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.notAffected();

        assertThat(run.evidenceIds()).containsExactly("E-001", "E-002");
        assertThat(run.evidenceIds()).hasSize(2);
    }

    @Test
    @DisplayName("Finding status NOT_AFFECTED at P5 / C0 with no action and no action impact")
    void assessmentClassification() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.notAffected();
        var assessment = run.securityCase().assessment();

        assertThat(assessment.findingStatus()).isEqualTo(FindingStatus.NOT_AFFECTED);
        assertThat(assessment.priority()).isEqualTo(Priority.P5);
        assertThat(assessment.confidence()).isEqualTo(Confidence.C0);

        assertThat(assessment.proposedAction()).isNull();
        assertThat(assessment.actionImpact()).isNull();
        assertThat(assessment.requiresHumanApproval()).isFalse();
    }

    @Test
    @DisplayName("A single decisive high-reliability observation is enough for C0")
    void singleDecisiveObservationIsC0() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.notAffected();

        // This is the case that proves C0 does not require many sources: reading the actual
        // running version is decisive about that version. Confidence is derived, so it is
        // computed from one high-reliability observation rather than declared.
        assertThat(run.securityCase().evidence()).hasSize(2);
        assertThat(run.securityCase().assessment().confidence()).isEqualTo(Confidence.C0);

        // A dismissal asserts no positive facts, so it carries no justification bullets.
        assertThat(run.securityCase().assessment().reasons()).isEmpty();
    }

    @Test
    @DisplayName("No remediation proposal and no approval is requested")
    void noRemediationAndNoApproval() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.notAffected();

        assertThat(run.securityCase().lifecycle()).isEqualTo(CaseLifecycle.CLEARED);
        assertThat(run.auditEventTypes())
                .as("nothing may be proposed when the finding is not affected")
                .doesNotContain("REMEDIATION_PROPOSED");
        assertThat(run.auditEventTypes()).contains("INVESTIGATION_STOPPED");
    }

    @Test
    @DisplayName("Scanner finding is still recorded as E-001: it was never silently discarded")
    void scannerFindingIsStillEvidence() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.notAffected();

        var first = run.securityCase().evidence().get(0);
        assertThat(first.evidenceId()).isEqualTo("E-001");
        assertThat(first.source()).isEqualTo("Vulnerability Scanner");
        assertThat(run.securityCase().findEvidence("E-002")).isPresent();
    }

    @Test
    @DisplayName("Audit trail ends at the stop, with no proposal and no action")
    void auditTrail() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.notAffected();

        assertThat(run.auditEventTypes()).containsExactly(
                "CASE_OPENED",
                "AGENT_DECISION", "TOOL_INVOKED", "EVIDENCE_CREATED",
                "AGENT_DECISION",
                "INVESTIGATION_STOPPED");

        assertThat(run.securityCase().lifecycle().isRemediationStage()).isFalse();

        System.out.println();
        System.out.println("=== TEST 2: NOT_AFFECTED (CASE-VUL-002) ===");
        System.out.println("--- evidence chain ---");
        System.out.println(run.evidenceChain());
        System.out.println("--- audit trail ---");
        System.out.println(run.auditTrail());
    }

    @Test
    @DisplayName("Runtime evidence contradicts the scanner finding")
    void runtimeEvidenceContradictsScanner() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.notAffected();
        SecurityCase securityCase = run.securityCase();

        assertThat(securityCase.facts().getString("runtimeVersion")).contains("2.4.58");
        assertThat(securityCase.assessment().rationale())
                .as("the rationale must be an explainable summary, not hidden reasoning")
                .isNotBlank()
                .doesNotContainIgnoringCase("chain of thought");

        assertThat(securityCase.assessment().actionImpact()).isNotEqualTo(ActionImpact.A2);
    }
}
