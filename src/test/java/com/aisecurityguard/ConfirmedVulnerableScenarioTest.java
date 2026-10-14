package com.aisecurityguard;

import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.Evidence;
import com.aisecurityguard.domain.EvidenceReliability;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.Priority;
import com.aisecurityguard.domain.SecurityCase;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * TEST 1 - CONFIRMED_VULNERABLE.
 *
 * <p>The affected runtime is genuinely running on an exposed production asset with known
 * exploitation. The agent must confirm the vulnerability, prioritise it P0, and propose a
 * consequential (A2) action that requires human approval.
 */
class ConfirmedVulnerableScenarioTest {

    @Test
    @DisplayName("E-001 is the scanner finding, before any tool runs")
    void scannerFindingIsFirstEvidence() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.confirmedVulnerable();

        List<Evidence> evidence = run.securityCase().evidence();
        assertThat(evidence).isNotEmpty();

        Evidence first = evidence.get(0);
        assertThat(first.evidenceId()).isEqualTo("E-001");
        assertThat(first.type()).isEqualTo("Scanner Finding");
        assertThat(first.source()).isEqualTo("Vulnerability Scanner");
        assertThat(first.reliability())
                .as("a scanner claim is medium reliability, never authoritative")
                .isEqualTo(EvidenceReliability.MEDIUM);
    }

    @Test
    @DisplayName("Agent selects exactly inspect_service -> lookup_kev -> get_asset_context")
    void toolSequence() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.confirmedVulnerable();

        assertThat(run.toolSequence()).containsExactly(
                "inspect_service",
                "lookup_kev",
                "get_asset_context");
    }

    @Test
    @DisplayName("Evidence chain is E-001..E-004: the scanner finding plus one item per tool, "
            + "and the assessment rests on all of it")
    void evidenceChain() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.confirmedVulnerable();

        assertThat(run.evidenceIds())
                .containsExactly("E-001", "E-002", "E-003", "E-004");
        assertThat(run.securityCase().evidence()).hasSize(4);

        // Each evidence item is pinned to its origin, so an off-by-one in ID assignment or a
        // tool that silently fails to produce evidence cannot pass unnoticed.
        assertThat(run.securityCase().evidence())
                .extracting(Evidence::evidenceId, Evidence::source)
                .containsExactly(
                        tuple("E-001", "Vulnerability Scanner"),
                        tuple("E-002", "inspect_service"),
                        tuple("E-003", "CISA KEV"),
                        tuple("E-004", "get_asset_context"));

        // The assessment was formed after the last tool ran, so it rests on the full chain.
        assertThat(run.securityCase().assessment().supportingEvidenceIds())
                .containsExactly("E-001", "E-002", "E-003", "E-004");
    }

    @Test
    @DisplayName("Finding status CONFIRMED_VULNERABLE at P0 / C0 / A2")
    void assessmentClassification() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.confirmedVulnerable();
        var assessment = run.securityCase().assessment();

        assertThat(assessment.findingStatus()).isEqualTo(FindingStatus.CONFIRMED_VULNERABLE);
        assertThat(assessment.priority()).isEqualTo(Priority.P0);
        assertThat(assessment.confidence()).isEqualTo(Confidence.C0);
        assertThat(assessment.actionImpact()).isEqualTo(ActionImpact.A2);
        assertThat(assessment.proposedAction()).isNotBlank();
    }

    @Test
    @DisplayName("Assessment references the evidence it rests on")
    void assessmentIsEvidenceBacked() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.confirmedVulnerable();
        var assessment = run.securityCase().assessment();

        assertThat(assessment.supportingEvidenceIds())
                .isNotEmpty()
                .allSatisfy(id -> assertThat(run.securityCase().findEvidence(id)).isPresent());
    }

    @Test
    @DisplayName("Confidence C0 is derived from the investigation evidence, not declared")
    void confidenceIsDerivedNotDeclared() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.confirmedVulnerable();

        // Three high-reliability investigation observations that agree. The initial scanner
        // finding is the hypothesis under test, so it does not dilute the rating.
        assertThat(run.securityCase().evidence())
                .filteredOn(e -> !e.source().equals("Vulnerability Scanner"))
                .allSatisfy(e -> assertThat(e.reliability())
                        .isEqualTo(EvidenceReliability.HIGH));

        assertThat(run.securityCase().assessment().confidence()).isEqualTo(Confidence.C0);
        assertThat(run.auditTrail()).contains("C0 (derived)");
    }

    @Test
    @DisplayName("Reasons carry the structured justification bullets shown on the approval screen")
    void reasonsAreStructuredAndOrdered() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.confirmedVulnerable();

        assertThat(run.securityCase().assessment().reasons()).containsExactly(
                "Vulnerable runtime confirmed",
                "Internet-facing service",
                "Production asset",
                "Known exploitation in the wild");

        // The rationale is a summary, never a dump of hidden reasoning.
        assertThat(run.securityCase().assessment().rationale())
                .isNotBlank()
                .doesNotContainIgnoringCase("chain of thought", "step 1", "let me think");
    }

    @Test
    @DisplayName("Case awaits approval; nothing was remediated")
    void awaitingHumanApproval() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.confirmedVulnerable();
        SecurityCase securityCase = run.securityCase();

        assertThat(securityCase.lifecycle()).isEqualTo(CaseLifecycle.ASSESSED);
        assertThat(securityCase.assessment().requiresHumanApproval())
                .as("A2 consequential action must require explicit human approval")
                .isTrue();

        // Milestone 0 must never remediate, and must not pretend it did.
        assertThat(securityCase.lifecycle()).isNotIn(
                CaseLifecycle.REMEDIATING, CaseLifecycle.VERIFYING, CaseLifecycle.RESOLVED);
        assertThat(securityCase.isAutomaticRemediationBlocked()).isFalse();
    }

    @Test
    @DisplayName("Finding status is not mutated into a lifecycle value")
    void findingStatusIsNotResolved() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.confirmedVulnerable();

        assertThat(run.securityCase().assessment().findingStatus())
                .as("CONFIRMED_VULNERABLE must never be overwritten with RESOLVED")
                .isEqualTo(FindingStatus.CONFIRMED_VULNERABLE);
    }

    @Test
    @DisplayName("Audit trail records the full decision -> tool -> evidence -> propose arc")
    void auditTrail() {
        ScenarioHarness.ScenarioRun run = ScenarioHarness.confirmedVulnerable();

        assertThat(run.auditEventTypes()).containsExactly(
                "CASE_OPENED",
                "AGENT_DECISION", "TOOL_INVOKED", "EVIDENCE_CREATED",
                "AGENT_DECISION", "TOOL_INVOKED", "EVIDENCE_CREATED",
                "AGENT_DECISION", "TOOL_INVOKED", "EVIDENCE_CREATED",
                "AGENT_DECISION",
                "REMEDIATION_PROPOSED");

        System.out.println();
        System.out.println("=== TEST 1: CONFIRMED_VULNERABLE (CASE-VUL-001) ===");
        System.out.println("--- evidence chain ---");
        System.out.println(run.evidenceChain());
        System.out.println("--- audit trail ---");
        System.out.println(run.auditTrail());
    }
}
