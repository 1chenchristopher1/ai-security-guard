package com.aisecurityguard;

import com.aisecurityguard.agent.AssessmentService;
import com.aisecurityguard.agent.ConfidencePolicy;
import com.aisecurityguard.agent.ConflictResolver;
import com.aisecurityguard.agent.InvestigationLoop;
import com.aisecurityguard.agent.PriorityPolicy;
import com.aisecurityguard.agent.ReferenceDecisionPolicy;
import com.aisecurityguard.approval.DefaultApprovalGate;
import com.aisecurityguard.audit.AuditLog;
import com.aisecurityguard.audit.InMemoryAuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.casefile.CaseManagementService;
import com.aisecurityguard.domain.ApprovalRequest;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.remediation.ControlledRemediationExecutor;
import com.aisecurityguard.remediation.RemediationActionCatalog;
import com.aisecurityguard.scenario.Scenarios;
import com.aisecurityguard.tool.CheckServiceHealthTool;
import com.aisecurityguard.tool.GetAssetContextTool;
import com.aisecurityguard.tool.InspectServiceTool;
import com.aisecurityguard.tool.LookupKevTool;
import com.aisecurityguard.tool.ToolRegistry;
import com.aisecurityguard.tool.ValidateVulnerabilityTool;
import com.aisecurityguard.verification.ToolBasedRemediationVerifier;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Shared, explicit wiring for the acceptance tests.
 *
 * <p>The harness is assembled by hand rather than by {@code @SpringBootTest} so that a test reads
 * as the whole system: four tools, a registry, a policy, an audit log and a clock. If a reader can
 * hold that in their head, the milestone is the right size.
 */
final class ScenarioHarness {

    private ScenarioHarness() {
    }

    /** Everything a scenario produced, so tests can assert on the outcome. */
    record ScenarioRun(SecurityCase securityCase, AuditLog auditLog, ToolRegistry toolRegistry) {

        /** Tool names in the order the agent selected them. */
        List<String> toolSequence() {
            return securityCase.selectedToolSequence();
        }

        /** Evidence IDs in chain order. */
        List<String> evidenceIds() {
            return securityCase.evidenceIds();
        }

        /** Audit event types in append order, for trajectory assertions. */
        List<String> auditEventTypes() {
            return auditLog.forCase(securityCase.caseId()).stream()
                    .map(com.aisecurityguard.domain.AuditEvent::eventType)
                    .collect(Collectors.toList());
        }

        /** Renders the audit trail, for the milestone report. */
        String auditTrail() {
            return auditLog.forCase(securityCase.caseId()).stream()
                    .map(e -> "%2d %s %-14s %-22s %s".formatted(
                            e.sequence(), e.timestamp(), e.actor(), e.eventType(), e.result()))
                    .collect(Collectors.joining(System.lineSeparator()));
        }

        /** Renders the evidence chain, for the milestone report. */
        String evidenceChain() {
            return securityCase.evidence().stream()
                    .map(e -> "%s %-12s %-22s [%s] %s".formatted(
                            e.evidenceId(), e.timestamp(), e.source(), e.reliability(), e.finding()))
                    .collect(Collectors.joining(System.lineSeparator()));
        }
    }

    private static ToolRegistry fullToolRegistry() {
        return ToolRegistry.of(
                new InspectServiceTool(),
                new LookupKevTool(),
                new GetAssetContextTool(),
                new ValidateVulnerabilityTool(),
                new CheckServiceHealthTool());
    }

    private static ScenarioRun run(SecurityCase securityCase, String scannerClaim,
                                   com.aisecurityguard.tool.SimulationWorld world,
                                   SimulationClock clock) {
        ToolRegistry registry = fullToolRegistry();

        AuditLog auditLog = new InMemoryAuditLog(clock);
        AssessmentService assessmentService = new AssessmentService(new ConfidencePolicy());
        ConflictResolver conflictResolver = new ConflictResolver();
        ReferenceDecisionPolicy policy = new ReferenceDecisionPolicy(
                registry, new PriorityPolicy(), conflictResolver);
        InvestigationLoop loop = new InvestigationLoop(
                policy, registry, auditLog, clock, assessmentService, conflictResolver);

        loop.investigate(securityCase, scannerClaim, world);
        return new ScenarioRun(securityCase, auditLog, registry);
    }

    // ==================================================================
    // Full lifecycle: investigation, human decision, remediation, verification
    // ==================================================================

    /** Everything a completed remediation cycle produced, for the approval tests. */
    record LifecycleRun(
            SecurityCase securityCase,
            AuditLog auditLog,
            CaseManagementService caseManagement,
            SimulationClock clock) {

        List<String> auditEventTypes() {
            return auditLog.forCase(securityCase.caseId()).stream()
                    .map(com.aisecurityguard.domain.AuditEvent::eventType)
                    .collect(Collectors.toList());
        }

        String auditTrail() {
            return auditLog.forCase(securityCase.caseId()).stream()
                    .map(e -> "%2d %s %-14s %-22s %s".formatted(
                            e.sequence(), e.timestamp(), e.actor(), e.eventType(), e.result()))
                    .collect(Collectors.joining(System.lineSeparator()));
        }

        String evidenceChain() {
            return securityCase.evidence().stream()
                    .map(e -> "%s %-12s %-22s [%s] %s".formatted(
                            e.evidenceId(), e.timestamp(), e.source(), e.reliability(), e.finding()))
                    .collect(Collectors.joining(System.lineSeparator()));
        }
    }

    /** Wires the full lifecycle harness around a fresh clock and audit log. */
    private static LifecycleRun lifecycle() {
        SimulationClock clock = new SimulationClock();
        AuditLog auditLog = new InMemoryAuditLog(clock);
        ToolRegistry registry = fullToolRegistry();
        AssessmentService assessmentService = new AssessmentService(new ConfidencePolicy());
        ConflictResolver conflictResolver = new ConflictResolver();
        ReferenceDecisionPolicy policy = new ReferenceDecisionPolicy(
                registry, new PriorityPolicy(), conflictResolver);
        InvestigationLoop loop = new InvestigationLoop(
                policy, registry, auditLog, clock, assessmentService, conflictResolver);

        CaseManagementService caseManagement = new CaseManagementService(
                loop,
                new DefaultApprovalGate(auditLog),
                new ControlledRemediationExecutor(
                        new RemediationActionCatalog(), auditLog, clock),
                new ToolBasedRemediationVerifier(registry, auditLog, clock),
                conflictResolver,
                new com.aisecurityguard.casefile.InMemoryCaseRepository(),
                auditLog,
                clock);

        return new LifecycleRun(null, auditLog, caseManagement, clock);
    }

    /** Investigates the positive scenario and leaves it awaiting approval. */
    static LifecycleRun positiveAwaitingApproval() {
        LifecycleRun base = lifecycle();
        SecurityCase securityCase = base.caseManagement()
                .investigate(Scenarios.confirmedVulnerableCase(),
                        Scenarios.POSITIVE_SCANNER_CLAIM,
                        Scenarios.confirmedVulnerableWorld());
        return new LifecycleRun(securityCase, base.auditLog(), base.caseManagement(), base.clock());
    }

    /** Investigates the positive scenario, approves it, remediates and verifies. */
    static LifecycleRun positiveApprovedAndRemediated() {
        LifecycleRun run = positiveAwaitingApproval();
        run.caseManagement().decide(run.securityCase(),
                ApprovalRequest.approvedBy("CASE-VUL-001", "analyst.chris",
                        run.clock().tick()));
        run.caseManagement().remediateAndVerify(
                run.securityCase(), run.caseManagement().tokenFor(run.securityCase()).orElseThrow());
        return run;
    }

    /** Investigates the positive scenario and rejects the proposal. */
    static LifecycleRun positiveRejected() {
        LifecycleRun run = positiveAwaitingApproval();
        run.caseManagement().decide(run.securityCase(),
                ApprovalRequest.rejectedBy("CASE-VUL-001", "analyst.chris",
                        run.clock().tick(), "change freeze in effect"));
        return run;
    }

    /** Investigates the negative scenario, which needs no approval at all. */
    static LifecycleRun negativeNoApprovalNeeded() {
        LifecycleRun base = lifecycle();
        SecurityCase securityCase = base.caseManagement()
                .investigate(Scenarios.notAffectedCase(),
                        Scenarios.NEGATIVE_SCANNER_CLAIM,
                        Scenarios.notAffectedWorld());
        return new LifecycleRun(securityCase, base.auditLog(), base.caseManagement(), base.clock());
    }

    /** Investigates the conflict scenario, which escalates. */
    static LifecycleRun conflictEscalated() {
        LifecycleRun base = lifecycle();
        SecurityCase securityCase = base.caseManagement()
                .investigate(Scenarios.evidenceConflictCase(),
                        Scenarios.CONFLICT_SCANNER_CLAIM,
                        Scenarios.evidenceConflictWorld());
        return new LifecycleRun(securityCase, base.auditLog(), base.caseManagement(), base.clock());
    }

    private static SimulationClock freshClock() {
        return new SimulationClock();
    }

    /** Scenario 1 - CONFIRMED_VULNERABLE. */
    static ScenarioRun confirmedVulnerable() {
        return run(Scenarios.confirmedVulnerableCase(), Scenarios.POSITIVE_SCANNER_CLAIM,
                Scenarios.confirmedVulnerableWorld(), freshClock());
    }

    /** Scenario 2 - NOT_AFFECTED. */
    static ScenarioRun notAffected() {
        return run(Scenarios.notAffectedCase(), Scenarios.NEGATIVE_SCANNER_CLAIM,
                Scenarios.notAffectedWorld(), freshClock());
    }

    /** Scenario 3 - EVIDENCE_CONFLICT, escalating. */
    static ScenarioRun evidenceConflict() {
        return run(Scenarios.evidenceConflictCase(), Scenarios.CONFLICT_SCANNER_CLAIM,
                Scenarios.evidenceConflictWorld(), freshClock());
    }
}
