package com.aisecurityguard;

import com.aisecurityguard.agent.AssessmentService;
import com.aisecurityguard.agent.ConfidencePolicy;
import com.aisecurityguard.agent.ConflictResolver;
import com.aisecurityguard.agent.DecisionPolicy;
import com.aisecurityguard.agent.InvestigationLoop;
import com.aisecurityguard.agent.PriorityPolicy;
import com.aisecurityguard.agent.ReferenceDecisionPolicy;
import com.aisecurityguard.audit.InMemoryAuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.AgentDecisionType;
import com.aisecurityguard.domain.Assessment;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.Priority;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.scenario.Scenarios;
import com.aisecurityguard.tool.GetAssetContextTool;
import com.aisecurityguard.tool.InspectServiceTool;
import com.aisecurityguard.tool.LookupKevTool;
import com.aisecurityguard.tool.SecurityTool;
import com.aisecurityguard.tool.ToolRegistry;
import com.aisecurityguard.tool.ValidateVulnerabilityTool;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Invariants the workflow must hold regardless of which scenario runs.
 *
 * <p>These are the rules that make the system safe and auditable, and they are the rules most
 * likely to be eroded when the reference policy is replaced by an LLM. They are therefore asserted
 * directly rather than only through the three scenario tests.
 */
class WorkflowInvariantTest {

    private static ToolRegistry allTools() {
        return ToolRegistry.of(
                new InspectServiceTool(),
                new LookupKevTool(),
                new GetAssetContextTool(),
                new ValidateVulnerabilityTool());
    }

    private static InvestigationLoop loopWith(DecisionPolicy policy, ToolRegistry registry,
                                             InMemoryAuditLog auditLog, SimulationClock clock) {
        return new InvestigationLoop(policy, registry, auditLog, clock,
                new AssessmentService(new ConfidencePolicy()), new ConflictResolver());
    }

    private static ReferenceDecisionPolicy referencePolicy(ToolRegistry registry) {
        return new ReferenceDecisionPolicy(registry, new PriorityPolicy(), new ConflictResolver());
    }

    // ==================================================================

    @Nested
    @DisplayName("Tool registry")
    class ToolRegistryInvariants {

        @Test
        @DisplayName("registers exactly the four V1 tools")
        void registersFourTools() {
            assertThat(allTools().toolNames()).containsExactlyInAnyOrder(
                    "inspect_service", "lookup_kev", "get_asset_context", "validate_vulnerability");
        }

        @Test
        @DisplayName("rejects a tool name that is not registered")
        void rejectsUnknownTool() {
            assertThatThrownBy(() -> allTools().require("execute_remediation"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("no security tool registered");
        }

        @Test
        @DisplayName("rejects duplicate tool registration")
        void rejectsDuplicateRegistration() {
            SecurityTool duplicate = new InspectServiceTool();

            assertThatThrownBy(() -> ToolRegistry.of(new InspectServiceTool(), duplicate))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("duplicate security tool");
        }

        @Test
        @DisplayName("exposes no shell, file-write or remediation capability")
        void exposesNoDangerousCapability() {
            assertThat(allTools().toolNames())
                    .as("the agent gets named typed capabilities only")
                    .doesNotContain("bash", "shell", "exec", "write_file", "execute_remediation",
                            "docker", "read_file", "search_files");
        }
    }

    // ==================================================================

    @Nested
    @DisplayName("Investigation loop")
    class LoopInvariants {

        @Test
        @DisplayName("an assessment citing evidence that does not exist is rejected")
        void rejectsAssessmentWithUnknownSupportingEvidence() {
            SecurityCase securityCase = Scenarios.confirmedVulnerableCase();
            SimulationClock clock = new SimulationClock();
            InMemoryAuditLog auditLog = new InMemoryAuditLog(clock);

            // A policy that claims to have assessed the case while citing evidence that was
            // never collected. The loop must refuse to store it.
            DecisionPolicy smugglingPolicy = (c, world) -> new AgentDecision(
                    AgentDecisionType.ASSESS,
                    List.of("E-999"),
                    List.of(),
                    "Fabricated assessment citing evidence that does not exist.",
                    null,
                    null,
                    new Assessment(
                            FindingStatus.CONFIRMED_VULNERABLE,
                            Priority.P0,
                            Confidence.C4,
                            List.of("E-999"),
                            "Fabricated assessment citing evidence that does not exist.",
                            List.of(),
                            "Upgrade Apache HTTP Server to a patched version.",
                            ActionImpact.A2));

            InvestigationLoop loop = loopWith(smugglingPolicy, allTools(), auditLog, clock);

            // The policy cannot self-correct (it does not implement CorrectionAwarePolicy), so the
            // refusal becomes an escalation rather than a stored assessment or a crash.
            loop.investigate(securityCase, Scenarios.POSITIVE_SCANNER_CLAIM,
                    Scenarios.confirmedVulnerableWorld());

            assertThat(securityCase.lifecycle())
                    .as("a verdict the evidence cannot support must reach a human")
                    .isEqualTo(CaseLifecycle.ESCALATED);
            assertThat(securityCase.assessment().findingStatus())
                    .as("the fabricated finding must never be stored")
                    .isNotEqualTo(FindingStatus.CONFIRMED_VULNERABLE);
            assertThat(securityCase.isAutomaticRemediationBlocked()).isTrue();
            assertThat(securityCase.selectedToolSequence())
                    .as("no capability may be invoked while smuggling a verdict")
                    .isEmpty();
            assertThat(auditLog.forCase(securityCase.caseId()))
                    .extracting(com.aisecurityguard.domain.AuditEvent::eventType)
                    .doesNotContain("REMEDIATION_STARTED", "REMEDIATION_EXECUTED");
        }

        @Test
        @DisplayName("a policy that never reaches a terminal decision is stopped by MAX_ITERATIONS")
        void maxIterationsGuard() {
            SecurityCase securityCase = Scenarios.confirmedVulnerableCase();
            SimulationClock clock = new SimulationClock();
            InMemoryAuditLog auditLog = new InMemoryAuditLog(clock);

            // A policy that always asks for the same tool and never concludes.
            DecisionPolicy loopingPolicy = (c, world) -> new AgentDecision(
                    AgentDecisionType.INVESTIGATE,
                    c.evidenceIds(),
                    List.of("Something that will never be enough"),
                    "Keep investigating forever.",
                    "inspect_service",
                    com.aisecurityguard.domain.ToolArguments.of(c.assetId()),
                    null);

            InvestigationLoop loop = loopWith(loopingPolicy, allTools(), auditLog, clock);

            assertThatThrownBy(() -> loop.investigate(
                    securityCase, Scenarios.POSITIVE_SCANNER_CLAIM,
                    Scenarios.confirmedVulnerableWorld()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("exceeded MAX_ITERATIONS");

            assertThat(InvestigationLoop.MAX_ITERATIONS).isPositive();
        }

        @Test
        @DisplayName("every scenario converges well within MAX_ITERATIONS")
        void scenariosConvergeQuickly() {
            assertThat(ScenarioHarness.confirmedVulnerable().securityCase().decisions())
                    .hasSizeLessThanOrEqualTo(InvestigationLoop.MAX_ITERATIONS);
            assertThat(ScenarioHarness.notAffected().securityCase().decisions())
                    .hasSizeLessThanOrEqualTo(InvestigationLoop.MAX_ITERATIONS);
            assertThat(ScenarioHarness.evidenceConflict().securityCase().decisions())
                    .hasSizeLessThanOrEqualTo(InvestigationLoop.MAX_ITERATIONS);
        }

        @Test
        @DisplayName("a terminal case cannot be advanced further")
        void terminalCaseIsFrozen() {
            SecurityCase securityCase = ScenarioHarness.notAffected().securityCase();

            assertThat(securityCase.lifecycle()).isEqualTo(CaseLifecycle.CLEARED);
            assertThat(securityCase.isTerminal()).isTrue();
            assertThatThrownBy(() -> securityCase.moveTo(CaseLifecycle.ASSESSED))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("terminal lifecycle");
        }

        @Test
        @DisplayName("an assessment is immutable once recorded")
        void assessmentIsImmutable() {
            SecurityCase securityCase = ScenarioHarness.confirmedVulnerable().securityCase();
            Assessment original = securityCase.assessment();

            assertThatThrownBy(() -> securityCase.recordAssessment(original))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("assessments are immutable");
        }

        @Test
        @DisplayName("evidence IDs are gap-free and never reused")
        void evidenceIdsAreGapFree() {
            assertThat(ScenarioHarness.confirmedVulnerable().evidenceIds())
                    .containsExactly("E-001", "E-002", "E-003", "E-004");
            assertThat(ScenarioHarness.notAffected().evidenceIds())
                    .containsExactly("E-001", "E-002");
            assertThat(ScenarioHarness.evidenceConflict().evidenceIds())
                    .containsExactly("E-001", "E-002", "E-003");
        }
    }

    // ==================================================================

    @Nested
    @DisplayName("Safety gate")
    class SafetyGate {

        @Test
        @DisplayName("every real workflow leaves a hash-chain verifiable audit trail")
        void auditTrailsAreVerifiable() {
            for (ScenarioHarness.ScenarioRun run : List.of(
                    ScenarioHarness.confirmedVulnerable(),
                    ScenarioHarness.notAffected(),
                    ScenarioHarness.evidenceConflict())) {

                var report = run.auditLog().verifyIntegrity();
                assertThat(report.isValid())
                        .as("%s: %s", run.securityCase().caseId(), report.describe())
                        .isTrue();
                assertThat(report.eventsChecked()).isPositive();
            }
        }

        @Test
        @DisplayName("no scenario executes remediation")
        void noRemediationIsExecuted() {
            for (ScenarioHarness.ScenarioRun run : List.of(
                    ScenarioHarness.confirmedVulnerable(),
                    ScenarioHarness.notAffected(),
                    ScenarioHarness.evidenceConflict())) {

                assertThat(run.securityCase().lifecycle())
                        .as("the investigation proposes but never executes")
                        .isNotIn(CaseLifecycle.REMEDIATING, CaseLifecycle.VERIFYING,
                                CaseLifecycle.RESOLVED);
                assertThat(run.auditEventTypes())
                        .doesNotContain("REMEDIATION_EXECUTED", "VERIFICATION_STARTED");
            }
        }

        @Test
        @DisplayName("only the A2 proposal requires approval, and it is never auto-approved")
        void onlyConsequentialActionNeedsApproval() {
            ScenarioHarness.ScenarioRun positive = ScenarioHarness.confirmedVulnerable();
            assertThat(positive.securityCase().assessment().actionImpact())
                    .isEqualTo(ActionImpact.A2);
            assertThat(positive.securityCase().assessment().requiresHumanApproval()).isTrue();
            assertThat(positive.auditEventTypes()).doesNotContain("HUMAN_APPROVAL");

            assertThat(ScenarioHarness.notAffected().securityCase()
                    .assessment().requiresHumanApproval()).isFalse();
            assertThat(ScenarioHarness.evidenceConflict().securityCase()
                    .assessment().requiresHumanApproval()).isFalse();
        }

        @Test
        @DisplayName("audit sequence numbers are gap-free and strictly increasing")
        void auditSequenceIsGapFree() {
            for (ScenarioHarness.ScenarioRun run : List.of(
                    ScenarioHarness.confirmedVulnerable(),
                    ScenarioHarness.notAffected(),
                    ScenarioHarness.evidenceConflict())) {

                List<com.aisecurityguard.domain.AuditEvent> events =
                        run.auditLog().forCase(run.securityCase().caseId());

                assertThat(events).isNotEmpty();
                for (int i = 0; i < events.size(); i++) {
                    assertThat(events.get(i).sequence()).isEqualTo(i + 1L);
                }
            }
        }

        @Test
        @DisplayName("audit timestamps are non-decreasing")
        void auditTimestampsAreMonotonic() {
            var events = ScenarioHarness.confirmedVulnerable()
                    .auditLog().forCase("CASE-VUL-001");

            LocalTime previous = LocalTime.MIN;
            for (var event : events) {
                assertThat(event.timestamp()).isAfterOrEqualTo(previous);
                previous = event.timestamp();
            }
        }
    }

    // ==================================================================

    @Nested
    @DisplayName("Decision policy seam")
    class PolicySeam {

        @Test
        @DisplayName("ReferenceDecisionPolicy is a DecisionPolicy and is stateless across cases")
        void referencePolicyIsInterchangeable() {
            ToolRegistry registry = allTools();
            DecisionPolicy policy = referencePolicy(registry);

            SecurityCase first = Scenarios.confirmedVulnerableCase();
            InvestigationLoop loop = loopWith(policy, registry,
                    new InMemoryAuditLog(new SimulationClock()), new SimulationClock());

            // Reusing the same policy instance for a second, unrelated case must not leak state.
            loop.investigate(first, Scenarios.POSITIVE_SCANNER_CLAIM,
                    Scenarios.confirmedVulnerableWorld());

            SecurityCase second = Scenarios.notAffectedCase();
            InvestigationLoop secondLoop = loopWith(policy, registry,
                    new InMemoryAuditLog(new SimulationClock()), new SimulationClock());
            secondLoop.investigate(second, Scenarios.NEGATIVE_SCANNER_CLAIM,
                    Scenarios.notAffectedWorld());

            assertThat(first.selectedToolSequence())
                    .containsExactly("inspect_service", "lookup_kev", "get_asset_context");
            assertThat(second.selectedToolSequence())
                    .as("the second case must not inherit the first case's history")
                    .containsExactly("inspect_service");
        }

        @Test
        @DisplayName("deciding does not mutate the case")
        void decideIsPure() {
            SecurityCase securityCase = Scenarios.notAffectedCase();
            ToolRegistry registry = allTools();
            SimulationClock clock = new SimulationClock();

            // Give the case some evidence so the policy has something to reason over.
            new InvestigationLoop(referencePolicy(registry), registry,
                    new InMemoryAuditLog(clock), clock,
                    new AssessmentService(new ConfidencePolicy()), new ConflictResolver())
                    .investigate(securityCase, Scenarios.NEGATIVE_SCANNER_CLAIM,
                            Scenarios.notAffectedWorld());

            int evidenceBefore = securityCase.evidenceCount();
            int decisionsBefore = securityCase.decisions().size();
            CaseLifecycle lifecycleBefore = securityCase.lifecycle();

            referencePolicy(registry).decide(securityCase, Scenarios.notAffectedWorld());

            assertThat(securityCase.evidenceCount()).isEqualTo(evidenceBefore);
            assertThat(securityCase.decisions()).hasSize(decisionsBefore);
            assertThat(securityCase.lifecycle()).isEqualTo(lifecycleBefore);
        }
    }

    // ==================================================================

    @Nested
    @DisplayName("Case facts")
    class CaseFactInvariants {

        @Test
        @DisplayName("conflicting facts are rejected rather than silently overwritten")
        void conflictingFactsAreRejected() {
            var facts = new com.aisecurityguard.domain.CaseFacts();
            facts.merge(java.util.Map.of("runtimeVersion", "2.4.49"));

            assertThatThrownBy(() -> facts.merge(java.util.Map.of("runtimeVersion", "2.4.58")))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("conflicting case facts");
        }

        @Test
        @DisplayName("re-merging an identical fact is idempotent")
        void identicalFactsAreIdempotent() {
            var facts = new com.aisecurityguard.domain.CaseFacts();
            facts.merge(java.util.Map.of("knownExploited", true));
            facts.merge(java.util.Map.of("knownExploited", true));

            assertThat(facts.getString("knownExploited")).contains("true");
        }
    }
}
