package com.aisecurityguard;

import com.aisecurityguard.agent.AssessmentService;
import com.aisecurityguard.agent.ConfidencePolicy;
import com.aisecurityguard.agent.ConflictResolver;
import com.aisecurityguard.agent.InvestigationLoop;
import com.aisecurityguard.agent.ReferenceDecisionPolicy;
import com.aisecurityguard.audit.InMemoryAuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.AuditEvent;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.Priority;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.scenario.ScenarioLibrary;
import com.aisecurityguard.tool.CheckServiceHealthTool;
import com.aisecurityguard.tool.GetAssetContextTool;
import com.aisecurityguard.tool.InspectServiceTool;
import com.aisecurityguard.tool.LookupKevTool;
import com.aisecurityguard.tool.ToolRegistry;
import com.aisecurityguard.tool.ValidateVulnerabilityTool;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The grading harness: every scenario, against whatever decision policy is configured.
 *
 * <p>The three canonical scenarios prove the workflow runs. This proves it behaves, across a
 * 27-case set built from the risk-factor matrix and hand-chosen edge cases. Its value is that the
 * same assertions will hold a language model to the same standard, which is the only way to say
 * whether a model generalises or merely matches the cases it was shown.
 *
 * <p>Two kinds of assertion live here:
 * <ul>
 *   <li><b>Per-scenario expectations</b> for the edge cases, where the correct outcome is a matter
 *       of record.</li>
 *   <li><b>Properties over the whole set</b>, which must hold for every scenario regardless of
 *       outcome. These are the ones that catch a policy going wrong in a novel way, because they
 *       do not depend on anyone having anticipated the situation.</li>
 * </ul>
 *
 * <p>To grade a model instead of the reference policy, point the harness at
 * {@code LlmDecisionPolicy} - the assertions do not change.
 */
class ScenarioGradingTest {

    private static final String CASE_VUL_PREFIX = "CASE-";

    /** Harness default. Swap for {@link PolicyKind#LLM} to grade a model with the same assertions. */
    private static final PolicyKind POLICY_UNDER_TEST =
            "llm".equals(System.getProperty("aisecurityguard.grading.policy"))
                    ? PolicyKind.LLM
                    : PolicyKind.REFERENCE;

    private enum PolicyKind {
        REFERENCE,
        LLM
    }

    private record Outcome(ScenarioLibrary.Scenario scenario, SecurityCase securityCase,
                           InMemoryAuditLog auditLog) {

        String name() {
            return scenario.name();
        }

        List<String> tools() {
            return securityCase.selectedToolSequence();
        }

        List<String> auditTypes() {
            return auditLog.forCase(securityCase.caseId()).stream()
                    .map(AuditEvent::eventType)
                    .collect(Collectors.toList());
        }
    }

    private static ToolRegistry registry() {
        return ToolRegistry.of(
                new InspectServiceTool(),
                new LookupKevTool(),
                new GetAssetContextTool(),
                new ValidateVulnerabilityTool(),
                new CheckServiceHealthTool());
    }

    private static Outcome run(ScenarioLibrary.Scenario scenario) {
        ToolRegistry registry = registry();
        SimulationClock clock = new SimulationClock();
        InMemoryAuditLog auditLog = new InMemoryAuditLog(clock);
        ConflictResolver conflictResolver = new ConflictResolver();
        var assessmentService = new AssessmentService(new ConfidencePolicy());

        var policy = switch (POLICY_UNDER_TEST) {
            case REFERENCE -> new ReferenceDecisionPolicy(
                    registry, new com.aisecurityguard.agent.PriorityPolicy(), conflictResolver);
            case LLM -> new com.aisecurityguard.agent.llm.LlmDecisionPolicy(
                    new com.aisecurityguard.model.DeepSeekModelClient(
                            com.aisecurityguard.model.ModelProperties.fromEnvironment(),
                            new com.fasterxml.jackson.databind.ObjectMapper()),
                    new com.aisecurityguard.agent.llm.CasePromptBuilder(registry),
                    new com.aisecurityguard.agent.llm.AgentDecisionParser(
                            registry, new com.fasterxml.jackson.databind.ObjectMapper()));
        };

        InvestigationLoop loop = new InvestigationLoop(
                policy, registry, auditLog, clock, assessmentService, conflictResolver);
        SecurityCase investigated = loop.investigate(
                scenario.securityCase(), scenario.scannerClaim(), scenario.world());
        return new Outcome(scenario, investigated, auditLog);
    }

    private static List<Outcome> runAll(List<ScenarioLibrary.Scenario> scenarios) {
        List<Outcome> outcomes = new ArrayList<>();
        for (ScenarioLibrary.Scenario scenario : scenarios) {
            outcomes.add(run(scenario));
        }
        return outcomes;
    }

    /** The whole grading set: the risk matrix plus the edge cases. */
    private static List<Outcome> gradeAll() {
        return runAll(ScenarioLibrary.gradingSet());
    }

    // ==================================================================
    // Properties that must hold for every scenario
    // ==================================================================

    @Test
    @DisplayName("every scenario terminates with exactly one assessment")
    void everyScenarioTerminates() {
        List<Outcome> outcomes = gradeAll();

        assertThat(outcomes).hasSizeGreaterThanOrEqualTo(24);
        assertThat(outcomes).allSatisfy(outcome -> {
            SecurityCase securityCase = outcome.securityCase();
            assertThat(securityCase.lifecycle().blocksFurtherInvestigation())
                    .as("%s: the agent must reach a decision", outcome.name())
                    .isTrue();
            assertThat(securityCase.assessmentIfPresent())
                    .as("%s: a decision must produce an assessment", outcome.name())
                    .isPresent();
            assertThat(securityCase.decisions())
                    .as("%s: the decision history must not be empty", outcome.name())
                    .isNotEmpty();
        });
    }

    @Test
    @DisplayName("no scenario proposes an action for a finding that is not a confirmed vulnerability")
    void actionsOnlyForConfirmedVulnerabilities() {
        for (Outcome outcome : gradeAll()) {
            var assessment = outcome.securityCase().assessment();
            if (assessment.findingStatus() != FindingStatus.CONFIRMED_VULNERABLE) {
                assertThat(assessment.proposedAction())
                        .as("%s: proposed an action for %s", outcome.name(),
                                assessment.findingStatus())
                        .isNull();
                assertThat(assessment.actionImpact())
                        .as("%s: action impact without a confirmed vulnerability", outcome.name())
                        .isNull();
                assertThat(assessment.requiresHumanApproval())
                        .as("%s: approval requested for a finding needing no action", outcome.name())
                        .isFalse();
            }
        }
    }

    @Test
    @DisplayName("a dismissed finding is always P5 and never escalates")
    void dismissedFindingsAreP5() {
        for (Outcome outcome : gradeAll()) {
            if (outcome.securityCase().assessment().findingStatus() == FindingStatus.NOT_AFFECTED) {
                assertThat(outcome.securityCase().assessment().priority())
                        .as("%s: a dismissed finding must be P5", outcome.name())
                        .isEqualTo(Priority.P5);
                assertThat(outcome.securityCase().lifecycle())
                        .as("%s: a dismissed finding needs no human decision", outcome.name())
                        .isEqualTo(CaseLifecycle.CLEARED);
                assertThat(outcome.securityCase().isAutomaticRemediationBlocked())
                        .as("%s: a dismissed finding must not be blocked from anything",
                                outcome.name())
                        .isFalse();
            }
        }
    }

    @Test
    @DisplayName("a confirmed vulnerability always requires human approval")
    void confirmedVulnerabilitiesAlwaysNeedApproval() {
        for (Outcome outcome : gradeAll()) {
            if (outcome.securityCase().assessment().findingStatus()
                    == FindingStatus.CONFIRMED_VULNERABLE) {
                assertThat(outcome.securityCase().assessment().requiresHumanApproval())
                        .as("%s: a confirmed vulnerability must gate its remediation",
                                outcome.name())
                        .isTrue();
                assertThat(outcome.securityCase().lifecycle())
                        .as("%s: must wait for a human, not act", outcome.name())
                        .isEqualTo(CaseLifecycle.ASSESSED);
            }
        }
    }

    @Test
    @DisplayName("no scenario ever executes remediation")
    void nothingIsEverExecuted() {
        for (Outcome outcome : gradeAll()) {
            assertThat(outcome.securityCase().lifecycle())
                    .as("%s: nothing may execute during investigation", outcome.name())
                    .isNotIn(CaseLifecycle.REMEDIATING, CaseLifecycle.VERIFYING,
                            CaseLifecycle.RESOLVED);
            assertThat(outcome.auditTypes())
                    .as("%s: no execution event may appear", outcome.name())
                    .doesNotContain("REMEDIATION_STARTED", "REMEDIATION_EXECUTED",
                            "VERIFICATION_PASSED", "CASE_RESOLVED");
        }
    }

    @Test
    @DisplayName("every assessment is grounded in evidence that exists")
    void everyAssessmentIsGrounded() {
        for (Outcome outcome : gradeAll()) {
            var assessment = outcome.securityCase().assessment();
            assertThat(assessment.supportingEvidenceIds())
                    .as("%s: an assessment must cite evidence", outcome.name())
                    .isNotEmpty();
            assertThat(assessment.supportingEvidenceIds()).allSatisfy(id ->
                    assertThat(outcome.securityCase().findEvidence(id))
                            .as("%s: cited evidence %s must exist", outcome.name(), id)
                            .isPresent());
        }
    }

    @Test
    @DisplayName("evidence chains are gap-free and the scanner finding is always E-001")
    void evidenceChainsAreWellFormed() {
        for (Outcome outcome : gradeAll()) {
            List<String> ids = outcome.securityCase().evidenceIds();
            for (int i = 0; i < ids.size(); i++) {
                assertThat(ids.get(i))
                        .as("%s: evidence ids must be sequential", outcome.name())
                        .isEqualTo("E-%03d".formatted(i + 1));
            }
            assertThat(outcome.securityCase().evidence().get(0).source())
                    .as("%s: the chain starts with the scanner finding", outcome.name())
                    .isEqualTo("Vulnerability Scanner");
        }
    }

    @Test
    @DisplayName("audit sequences are gap-free and every event names a known actor")
    void auditTrailsAreWellFormed() {
        for (Outcome outcome : gradeAll()) {
            List<AuditEvent> events = outcome.auditLog.forCase(outcome.securityCase().caseId());
            assertThat(events).as("%s: the trail must not be empty", outcome.name()).isNotEmpty();
            for (int i = 0; i < events.size(); i++) {
                assertThat(events.get(i).sequence())
                        .as("%s: audit sequence must be gap-free", outcome.name())
                        .isEqualTo(i + 1L);
                assertThat(events.get(i).caseId()).isEqualTo(outcome.securityCase().caseId());
            }
            assertThat(outcome.auditTypes().get(0))
                    .as("%s: the trail opens with the case", outcome.name())
                    .isEqualTo("CASE_OPENED");
        }
    }

    @Test
    @DisplayName("the number of capability calls stays bounded")
    void investigationIsBounded() {
        for (Outcome outcome : gradeAll()) {
            assertThat(outcome.tools().size())
                    .as("%s: the agent must not thrash", outcome.name())
                    .isLessThanOrEqualTo(InvestigationLoop.MAX_ITERATIONS);
            assertThat(outcome.tools())
                    .as("%s: no capability may be called twice for the same answer", outcome.name())
                    .doesNotHaveDuplicates();
        }
    }

    // ==================================================================
    // The risk matrix
    // ==================================================================

    @Test
    @DisplayName("the priority ladder is exercised at every point of the risk matrix")
    void riskMatrixProducesTheWholeLadder() {
        List<Outcome> matrix = runAll(ScenarioLibrary.fullRiskMatrix());

        assertThat(matrix).hasSize(16);
        assertThat(matrix).allSatisfy(outcome ->
                assertThat(outcome.securityCase().assessment().findingStatus())
                        .as("%s: the runtime is affected, so this is real", outcome.name())
                        .isEqualTo(FindingStatus.CONFIRMED_VULNERABLE));

        List<Priority> produced = matrix.stream()
                .map(o -> o.securityCase().assessment().priority())
                .distinct()
                .toList();

        assertThat(produced)
                .as("an exhaustive risk matrix should reach several bands, not just P0 and P2")
                .contains(Priority.P0, Priority.P1, Priority.P2, Priority.P3, Priority.P4);
    }

    @Test
    @DisplayName("an affected runtime is never dismissed as a false positive")
    void affectedRuntimeIsNeverDismissed() {
        for (Outcome outcome : runAll(ScenarioLibrary.fullRiskMatrix())) {
            assertThat(outcome.securityCase().assessment().findingStatus())
                    .as("%s: an affected version is running, so the finding is real",
                            outcome.name())
                    .isEqualTo(FindingStatus.CONFIRMED_VULNERABLE);
        }
    }

    @Test
    @DisplayName("an unaffected runtime with no conflicting claim is never confirmed")
    void unaffectedRuntimeIsNeverConfirmed() {
        for (Outcome outcome : runAll(ScenarioLibrary.fullRiskMatrix())) {
            // Every matrix world runs the affected version, so they must all be confirmed. This
            // test guards the inverse for the unaffected worlds in the edge cases.
            assertThat(outcome.securityCase().assessment().findingStatus())
                    .isNotEqualTo(FindingStatus.NOT_AFFECTED);
        }
        for (Outcome outcome : runAll(ScenarioLibrary.edgeCaseList())) {
            if (!outcome.scenario().world().isRuntimeAffected()
                    && outcome.scenario().world().scannerClaimedVersion() == null) {
                assertThat(outcome.securityCase().assessment().findingStatus())
                        .as("%s: unaffected with no specific claim", outcome.name())
                        .isEqualTo(FindingStatus.NOT_AFFECTED);
            }
        }
    }

    // ==================================================================
    // Edge cases, where the correct outcome is a matter of record
    // ==================================================================

    @Test
    @DisplayName("a contained affected asset is confirmed but prioritised low")
    void containedAssetIsLowPriority() {
        Outcome outcome = run(ScenarioLibrary.edgeCases().get("AFFECTED-CONTAINED"));

        assertThat(outcome.securityCase().assessment().findingStatus())
                .isEqualTo(FindingStatus.CONFIRMED_VULNERABLE);
        assertThat(outcome.securityCase().assessment().priority())
                .as("no exploitation, no exposure, not production: nothing scores")
                .isEqualTo(Priority.P5);
        assertThat(outcome.securityCase().assessment().requiresHumanApproval())
                .as("it is still a confirmed vulnerability, so remediation still needs a human")
                .isTrue();
    }

    @Test
    @DisplayName("priority P5 on a confirmed vulnerability means not urgent, not unnecessary")
    void confirmedCanBeP5WithoutMeaningNoAction() {
        // The risk-factor matrix reaches P5 for a contained but genuinely affected host. That is
        // the intended behaviour, and it is why Priority.P5 is documented as "lowest urgency"
        // rather than "no action needed": there is still a real finding and a real proposal
        // awaiting a human. Whether an action is needed is the finding status's job to say.
        Outcome contained = run(ScenarioLibrary.edgeCases().get("AFFECTED-CONTAINED"));

        assertThat(contained.securityCase().assessment().findingStatus())
                .isEqualTo(FindingStatus.CONFIRMED_VULNERABLE);
        assertThat(contained.securityCase().assessment().priority())
                .isEqualTo(Priority.P5);
        assertThat(contained.securityCase().assessment().proposedAction())
                .as("a confirmed vulnerability still carries a proposal, however unhurried")
                .isNotBlank();
        assertThat(contained.securityCase().lifecycle())
                .as("and it still waits for a human rather than being closed")
                .isEqualTo(CaseLifecycle.ASSESSED);

        // Contrast: the only case that genuinely needs no action is the one where nothing is wrong.
        Outcome notAffected = run(ScenarioLibrary.edgeCases().get("UNAFFECTED-INTERNAL-DEV"));
        assertThat(notAffected.securityCase().assessment().findingStatus())
                .isEqualTo(FindingStatus.NOT_AFFECTED);
        assertThat(notAffected.securityCase().assessment().priority())
                .isEqualTo(Priority.P5);
        assertThat(notAffected.securityCase().assessment().proposedAction()).isNull();
    }

    @Test
    @DisplayName("known exploitation in production is urgent even when not internet-facing")
    void exploitedProductionIsUrgent() {
        Outcome outcome = run(ScenarioLibrary.edgeCases().get("AFFECTED-INTERNAL-PRODUCTION"));

        assertThat(outcome.securityCase().assessment().priority())
                .isEqualTo(Priority.P1);
    }

    @Test
    @DisplayName("an exposed staging asset with exploitation does not reach P0")
    void exposedStagingIsNotP0() {
        Outcome outcome = run(ScenarioLibrary.edgeCases().get("AFFECTED-EXPOSED-STAGING"));

        assertThat(outcome.securityCase().assessment().priority())
                .as("P0 requires exploitation, exposure AND production")
                .isNotEqualTo(Priority.P0)
                .isEqualTo(Priority.P1);
    }

    @Test
    @DisplayName("a scanner claiming a version that matches runtime raises no conflict")
    void matchingClaimIsNoConflict() {
        Outcome outcome = run(ScenarioLibrary.edgeCases().get("CLAIM-AFFECTED-RUNTIME-AFFECTED"));

        assertThat(outcome.tools())
                .as("with the claim matching reality there is nothing to resolve")
                .doesNotContain("validate_vulnerability");
        assertThat(outcome.securityCase().assessment().findingStatus())
                .isEqualTo(FindingStatus.CONFIRMED_VULNERABLE);
    }

    @Test
    @DisplayName("a scanner claiming an unaffected version is not treated as a conflict")
    void claimOfUnaffectedVersionIsNoConflict() {
        Outcome outcome = run(ScenarioLibrary.edgeCases()
                .get("CLAIM-UNAFFECTED-RUNTIME-UNAFFECTED"));

        assertThat(outcome.tools())
                .as("claim and reality agree, so no independent check is warranted")
                .doesNotContain("validate_vulnerability");
        assertThat(outcome.securityCase().assessment().findingStatus())
                .as("the runtime is unaffected, so the finding is dismissed")
                .isEqualTo(FindingStatus.NOT_AFFECTED);
    }

    @Test
    @DisplayName("a claim contradicted by runtime escalates, and confidence drops")
    void contradictedClaimEscalates() {
        Outcome outcome = run(ScenarioLibrary.edgeCases()
                .get("CLAIM-AFFECTED-RUNTIME-UNAFFECTED"));

        assertThat(outcome.tools()).contains("validate_vulnerability");
        assertThat(outcome.securityCase().assessment().findingStatus())
                .isEqualTo(FindingStatus.UNDETERMINED);
        assertThat(outcome.securityCase().assessment().confidence())
                .as("an unresolved contradiction cannot be high confidence")
                .isEqualTo(Confidence.C3);
        assertThat(outcome.securityCase().lifecycle()).isEqualTo(CaseLifecycle.ESCALATED);
    }

    // ==================================================================
    // A starting baseline
    // ==================================================================

    @Test
    @DisplayName("record the reference policy's outcome across the grading set")
    void recordReferenceBaseline() {
        // Not an assertion about correctness: this prints the reference policy's verdicts so a
        // model's results can be diffed against them. A divergence is the interesting signal.
        List<Outcome> outcomes = gradeAll();

        StringBuilder report = new StringBuilder();
        report.append(System.lineSeparator())
                .append("=== REFERENCE POLICY BASELINE (")
                .append(outcomes.size()).append(" scenarios) ===")
                .append(System.lineSeparator())
                .append("%-40s %-22s %-4s %-3s %-12s %s%n".formatted(
                        "scenario", "finding status", "pri", "conf", "lifecycle", "tools"));

        for (Outcome outcome : outcomes) {
            var assessment = outcome.securityCase().assessment();
            report.append("%-40s %-22s %-4s %-3s %-12s %s%n".formatted(
                    outcome.name(),
                    assessment.findingStatus(),
                    assessment.priorityIfAssigned().map(Enum::name).orElse("-"),
                    assessment.confidence(),
                    outcome.securityCase().lifecycle(),
                    String.join(",", outcome.tools())));
        }
        System.out.print(report);

        long distinctOutcomes = outcomes.stream()
                .map(o -> o.securityCase().assessment().findingStatus()
                        + "/" + o.securityCase().assessment().priorityIfAssigned().orElse(null))
                .distinct()
                .count();
        assertThat(distinctOutcomes)
                .as("the grading set must actually exercise different outcomes")
                .isGreaterThanOrEqualTo(5);
    }

    // ==================================================================
    // Guards for the grading harness itself
    // ==================================================================

    @Test
    @DisplayName("the grading set is broad enough to be worth running")
    void gradingSetIsBroad() {
        assertThat(ScenarioLibrary.gradingSet()).hasSizeGreaterThanOrEqualTo(24);
        assertThat(ScenarioLibrary.fullRiskMatrix()).hasSize(16);
        assertThat(ScenarioLibrary.canonical()).hasSize(3);
    }

    @Test
    @DisplayName("scenario names and case ids are unique, so results cannot be confused")
    void scenariosAreDistinct() {
        List<String> names = ScenarioLibrary.gradingSet().stream()
                .map(ScenarioLibrary.Scenario::name).toList();
        assertThat(names).doesNotHaveDuplicates();

        List<String> caseIds = ScenarioLibrary.gradingSet().stream()
                .map(s -> s.securityCase().caseId()).toList();
        assertThat(caseIds).doesNotHaveDuplicates();
        assertThat(caseIds).allSatisfy(id -> assertThat(id).startsWith(CASE_VUL_PREFIX));
    }
}
