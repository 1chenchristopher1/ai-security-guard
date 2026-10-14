package com.aisecurityguard.agent.llm;

import com.aisecurityguard.agent.AssessmentService;
import com.aisecurityguard.agent.ConfidencePolicy;
import com.aisecurityguard.agent.ConflictResolver;
import com.aisecurityguard.agent.InvestigationLoop;
import com.aisecurityguard.approval.DefaultApprovalGate;
import com.aisecurityguard.audit.InMemoryAuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.casefile.CaseManagementService;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.model.DeepSeekModelClient;
import com.aisecurityguard.model.ModelProperties;
import com.aisecurityguard.remediation.ControlledRemediationExecutor;
import com.aisecurityguard.remediation.RemediationActionCatalog;
import com.aisecurityguard.scenario.Scenarios;
import com.aisecurityguard.tool.GetAssetContextTool;
import com.aisecurityguard.tool.InspectServiceTool;
import com.aisecurityguard.tool.LookupKevTool;
import com.aisecurityguard.tool.SimulationWorld;
import com.aisecurityguard.tool.ToolRegistry;
import com.aisecurityguard.tool.ValidateVulnerabilityTool;
import com.aisecurityguard.verification.ToolBasedRemediationVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The real agent, against the reference oracle.
 *
 * <p>This is the point of the whole exercise. The reference policy reproduces the prototype's
 * behaviour exactly and is covered by 154 deterministic tests; this test asks whether a real
 * language model, given the same case and the same capabilities, reaches the same conclusions.
 *
 * <p>Runs only when {@code DEEPSEEK_API_KEY} is set, so the build stays offline-safe and
 * deterministic by default. It makes real network calls and costs tokens.
 *
 * <p>What is asserted is the <b>decision-relevant behaviour</b>, not the model's exact wording:
 * which capabilities it selects, what it concludes, and - most importantly - that it stops when
 * it should stop and escalates when it should escalate. Wording is allowed to vary; the workflow
 * is not.
 */
@EnabledIfEnvironmentVariable(named = "DEEPSEEK_API_KEY", matches = ".+")
@DisplayName("Live LLM agent vs the reference oracle")
class LiveLlmAgentComparisonTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ToolRegistry registry() {
        return ToolRegistry.of(
                new InspectServiceTool(),
                new LookupKevTool(),
                new GetAssetContextTool(),
                new ValidateVulnerabilityTool(),
                new com.aisecurityguard.tool.CheckServiceHealthTool());
    }

    private static CaseManagementService caseManagementWith(ToolRegistry registry,
                                                            SimulationClock clock,
                                                            InMemoryAuditLog auditLog) {
        ModelProperties properties = ModelProperties.fromEnvironment();
        LlmDecisionPolicy policy = new LlmDecisionPolicy(
                new DeepSeekModelClient(properties, MAPPER),
                new CasePromptBuilder(registry),
                new AgentDecisionParser(registry, MAPPER));

        ConflictResolver conflictResolver = new ConflictResolver();
        InvestigationLoop loop = new InvestigationLoop(
                policy, registry, auditLog, clock,
                new AssessmentService(new ConfidencePolicy()), conflictResolver);

        return new CaseManagementService(
                loop,
                new DefaultApprovalGate(auditLog),
                new ControlledRemediationExecutor(new RemediationActionCatalog(), auditLog, clock),
                new ToolBasedRemediationVerifier(registry, auditLog, clock),
                conflictResolver,
                new com.aisecurityguard.casefile.InMemoryCaseRepository(),
                auditLog,
                clock);
    }

    private record Run(SecurityCase securityCase, InMemoryAuditLog auditLog) {
    }

    private static Run investigate(SecurityCase securityCase, String claim, SimulationWorld world) {
        ToolRegistry registry = registry();
        SimulationClock clock = new SimulationClock();
        InMemoryAuditLog auditLog = new InMemoryAuditLog(clock);
        CaseManagementService service = caseManagementWith(registry, clock, auditLog);
        return new Run(service.investigate(securityCase, claim, world), auditLog);
    }

    // ==================================================================

    @Test
    @DisplayName("TEST 1 CONFIRMED_VULNERABLE: the model investigates then confirms, at P0")
    void confirmedVulnerable() {
        Run run = investigate(Scenarios.confirmedVulnerableCase(),
                Scenarios.POSITIVE_SCANNER_CLAIM, Scenarios.confirmedVulnerableWorld());

        System.out.println("[LLM TEST 1] tools=" + run.securityCase().selectedToolSequence()
                + " status=" + run.securityCase().assessment().findingStatus()
                + " priority=" + run.securityCase().assessment().priority()
                + " confidence=" + run.securityCase().assessment().confidence());

        // The model must have gathered runtime evidence before concluding. Which capabilities it
        // chooses, and in which order, is its own business - but it cannot confirm a vulnerability
        // without inspecting the running service.
        assertThat(run.securityCase().selectedToolSequence())
                .as("the model must inspect the service before confirming a vulnerability")
                .contains("inspect_service");

        assertThat(run.securityCase().assessment().findingStatus())
                .as("the affected version is running, so the finding is real")
                .isEqualTo(FindingStatus.CONFIRMED_VULNERABLE);

        assertThat(run.securityCase().lifecycle())
                .as("a confirmed vulnerability must wait for a human, not act")
                .isEqualTo(CaseLifecycle.ASSESSED);

        assertThat(run.securityCase().assessment().requiresHumanApproval())
                .as("the proposed remediation is consequential")
                .isTrue();

        assertThat(run.auditLog().forCase(run.securityCase().caseId()))
                .as("nothing may have been executed")
                .noneSatisfy(event -> assertThat(event.eventType())
                        .isIn("REMEDIATION_EXECUTED", "VERIFICATION_PASSED", "CASE_RESOLVED"));
    }

    @Test
    @DisplayName("TEST 2 NOT_AFFECTED: the model stops after one capability and asks for nothing")
    void notAffected() {
        Run run = investigate(Scenarios.notAffectedCase(),
                Scenarios.NEGATIVE_SCANNER_CLAIM, Scenarios.notAffectedWorld());

        System.out.println("[LLM TEST 2] tools=" + run.securityCase().selectedToolSequence()
                + " status=" + run.securityCase().assessment().findingStatus()
                + " priority=" + run.securityCase().assessment().priority());

        // This is the anti-playbook proof. A model that keeps calling capabilities for a finding it
        // has already disproved has failed the exercise even if its conclusion is right.
        assertThat(run.securityCase().selectedToolSequence())
                .as("the model must not run a fixed sequence of capabilities")
                .hasSizeLessThanOrEqualTo(2)
                .contains("inspect_service");

        assertThat(run.securityCase().assessment().findingStatus())
                .isEqualTo(FindingStatus.NOT_AFFECTED);

        assertThat(run.securityCase().lifecycle())
                .as("a dismissed finding needs no action and no approval")
                .isEqualTo(CaseLifecycle.CLEARED);

        assertThat(run.securityCase().assessment().proposedAction())
                .as("nothing may be proposed for a finding that is not affected")
                .isNull();
    }

    @Test
    @DisplayName("TEST 3 EVIDENCE_CONFLICT: the model refuses to force a verdict and escalates")
    void evidenceConflict() {
        Run run = investigate(Scenarios.evidenceConflictCase(),
                Scenarios.CONFLICT_SCANNER_CLAIM, Scenarios.evidenceConflictWorld());

        System.out.println("[LLM TEST 3] tools=" + run.securityCase().selectedToolSequence()
                + " status=" + run.securityCase().assessment().findingStatus()
                + " confidence=" + run.securityCase().assessment().confidence());

        // The scanner claims an affected version; the runtime shows otherwise. The model must not
        // simply trust either side.
        assertThat(run.securityCase().selectedToolSequence())
                .as("the model must seek independent confirmation of a contradicted claim")
                .contains("validate_vulnerability");

        assertThat(run.securityCase().assessment().findingStatus())
                .as("an unresolved contradiction must not be resolved into a verdict")
                .isNotEqualTo(FindingStatus.NOT_AFFECTED);

        assertThat(run.securityCase().lifecycle())
                .as("the model must escalate rather than act on conflicting evidence")
                .isEqualTo(CaseLifecycle.ESCALATED);

        assertThat(run.securityCase().isAutomaticRemediationBlocked())
                .as("automatic remediation must be blocked on an escalation")
                .isTrue();
    }
}
