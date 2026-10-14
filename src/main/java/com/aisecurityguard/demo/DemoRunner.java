package com.aisecurityguard.demo;

import com.aisecurityguard.agent.AssessmentService;
import com.aisecurityguard.agent.ConfidencePolicy;
import com.aisecurityguard.agent.ConflictResolver;
import com.aisecurityguard.agent.DecisionPolicy;
import com.aisecurityguard.agent.InvestigationLoop;
import com.aisecurityguard.agent.PriorityPolicy;
import com.aisecurityguard.agent.ReferenceDecisionPolicy;
import com.aisecurityguard.approval.DefaultApprovalGate;
import com.aisecurityguard.audit.AuditIntegrityReport;
import com.aisecurityguard.audit.InMemoryAuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.casefile.CaseManagementService;
import com.aisecurityguard.casefile.InMemoryCaseRepository;
import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.ApprovalRequest;
import com.aisecurityguard.domain.AuditEvent;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.Evidence;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.model.DeepSeekModelClient;
import com.aisecurityguard.model.ModelProperties;
import com.aisecurityguard.remediation.ControlledRemediationExecutor;
import com.aisecurityguard.remediation.RemediationActionCatalog;
import com.aisecurityguard.scenario.Scenarios;
import com.aisecurityguard.tool.CheckServiceHealthTool;
import com.aisecurityguard.tool.GetAssetContextTool;
import com.aisecurityguard.tool.InspectServiceTool;
import com.aisecurityguard.tool.LookupKevTool;
import com.aisecurityguard.tool.SimulationWorld;
import com.aisecurityguard.tool.ToolRegistry;
import com.aisecurityguard.tool.ValidateVulnerabilityTool;
import com.aisecurityguard.verification.ToolBasedRemediationVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

/**
 * Terminal demonstration of the whole workflow.
 *
 * <p>Not a test and not a mock-up: it drives the same components the tests drive, against either
 * the reference policy or a live language model, and prints what actually happened. Anything shown
 * here can be reproduced by running it.
 *
 * <p>Designed to be recorded, so it prints in segments with clear headers and pauses between them.
 *
 * <pre>
 *   mvnw.cmd exec:java -Dexec.mainClass=com.aisecurityguard.demo.DemoRunner
 *   mvnw.cmd exec:java -Dexec.mainClass=com.aisecurityguard.demo.DemoRunner -Dexec.args="--llm"
 * </pre>
 */
public final class DemoRunner {

    private static final String RULE = "=".repeat(78);
    private static final String THIN = "-".repeat(78);

    /** Pause between segments, so a recording can breathe and a presenter can talk. */
    private static final long SEGMENT_PAUSE_MS = 1200;

    private final boolean pause;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** Whether the language model will actually be used, after checking for a key. */
    private boolean useLlm;

    private DemoRunner(boolean useLlm, boolean pause) {
        this.useLlm = useLlm;
        this.pause = pause;
    }

    public static void main(String[] args) {
        silenceFrameworkLogging();
        boolean llm = List.of(args).contains("--llm");
        boolean fast = List.of(args).contains("--fast");
        new DemoRunner(llm, !fast).run();
    }

    /**
     * Quietens framework logging so the demonstration output stands alone.
     *
     * <p>The agent logs a line per model call, which is right for operations and wrong for a
     * recording: it interleaves with the narration. Set here rather than in a config file so the
     * test suite keeps its logging.
     */
    private static void silenceFrameworkLogging() {
        try {
            org.slf4j.Logger root = org.slf4j.LoggerFactory.getLogger(
                    org.slf4j.Logger.ROOT_LOGGER_NAME);
            if (root instanceof ch.qos.logback.classic.Logger logbackRoot) {
                logbackRoot.setLevel(ch.qos.logback.classic.Level.WARN);
            }
        } catch (Throwable ignored) {
            // Logging is a presentation concern here; failing to quieten it must not stop the demo.
        }
    }

    // ==================================================================
    // The demonstration
    // ==================================================================

    private void run() {
        banner();

        if (useLlm) {
            ModelProperties properties = ModelProperties.fromEnvironment();
            if (!properties.hasApiKey()) {
                System.out.println("  !! --llm was requested but " + ModelProperties.API_KEY_ENV_VAR
                        + " is not set.");
                System.out.println("  !! Running with the reference policy so the demo still works.");
                System.out.println();
                useLlm = false;
            } else {
                System.out.println("  Decision maker : DeepSeek (" + properties.model() + ")");
            }
        }
        if (!useLlm) {
            System.out.println("  Decision maker : reference policy (deterministic)");
        }
        System.out.println("  Add --llm to use the live language model instead.");
        pause();

        segment1Problem();
        segment2Confirmed();
        segment3NotAffected();
        segment4Conflict();
        segment5Approval();
        segment6AuditIntegrity();

        closing();
    }

    // ------------------------------------------------------------------

    private void segment1Problem() {
        header("SEGMENT 1 - THE PROBLEM");

        System.out.println("""
                A vulnerability scanner reports:  Apache HTTP Server 2.4.49, CVE-2021-41773, CVSS 9.8.

                A traditional tool files a P0 ticket and moves on. But a scanner finding is not a
                confirmed vulnerability:

                  - the affected version may not actually be running
                  - the service may not be reachable
                  - the asset may not matter
                  - nobody may be exploiting it
                  - and the scanner may simply be wrong

                A small IT team has no security analyst to check any of that. Below, an agent does
                it: it decides for itself what evidence to gather, and every decision is recorded.
                """);
        pause();
    }

    // ------------------------------------------------------------------

    private void segment2Confirmed() {
        header("SEGMENT 2 - CASE 1: A REAL VULNERABILITY (evidence-driven, not a script)");

        Run run = investigate(Scenarios.confirmedVulnerableCase(),
                Scenarios.POSITIVE_SCANNER_CLAIM, Scenarios.confirmedVulnerableWorld());

        printDecisions(run);
        printEvidence(run);
        printAssessment(run);
        printAudit(run);

        System.out.println("""
                Note what just happened: NOBODY WROTE THAT TOOL SEQUENCE. The agent chose each
                capability from what was still missing. Change the world and the sequence changes,
                as the next two cases show.
                """);
        pause();
    }

    private void segment3NotAffected() {
        header("SEGMENT 3 - CASE 2: THE SCANNER WAS WRONG");

        Run run = investigate(Scenarios.notAffectedCase(),
                Scenarios.NEGATIVE_SCANNER_CLAIM, Scenarios.notAffectedWorld());

        printDecisions(run);
        printEvidence(run);
        printAssessment(run);

        System.out.println("""
                The agent called ONE capability and stopped. It did not run a checklist, it did not
                keep gathering evidence to look thorough, and it did not trust the scanner. The
                finding is dismissed, no action is proposed, and no human is asked to approve
                anything.

                This is the case that proves the workflow is evidence-driven rather than a fixed
                automation sequence.
                """);
        pause();
    }

    private void segment4Conflict() {
        header("SEGMENT 4 - CASE 3: CONFLICTING EVIDENCE, AND THE AGENT REFUSES TO GUESS");

        Run run = investigate(Scenarios.evidenceConflictCase(),
                Scenarios.CONFLICT_SCANNER_CLAIM, Scenarios.evidenceConflictWorld());

        printDecisions(run);
        printEvidence(run);
        printAssessment(run);

        System.out.println("""
                The scanner named a specific version. The runtime shows a different one. The agent
                asked for an independent check, and that check could NOT settle the question.

                It escalated instead of picking a side. Note what an INCONCLUSIVE result means here:
                it is not evidence that the finding is false - it is the reason no verdict is
                possible. Automatic remediation is now blocked and a human is required.

                This is the behaviour that separates an agentic system from a script.
                """);
        pause();
    }

    // ------------------------------------------------------------------

    private void segment5Approval() {
        header("SEGMENT 5 - THE HUMAN GATE, REMEDIATION AND VERIFICATION");

        Harness harness = newHarness();
        SecurityCase securityCase = harness.caseManagement().investigate(
                Scenarios.confirmedVulnerableCase(), Scenarios.POSITIVE_SCANNER_CLAIM,
                Scenarios.confirmedVulnerableWorld());

        var assessment = securityCase.assessment();
        System.out.println("  The agent has produced a verdict and a proposal:");
        System.out.println();
        System.out.println("    finding status : " + assessment.findingStatus());
        System.out.println("    priority       : " + assessment.priority());
        System.out.println("    confidence     : " + assessment.confidence());
        System.out.println("    proposed action: " + assessment.proposedAction());
        System.out.println("    action impact  : " + assessment.actionImpact());
        System.out.println();
        System.out.println("  Action impact A2 means CONSEQUENTIAL: this changes a running service.");
        System.out.println("  Approval is therefore required - and it is enforced by the runtime, not by");
        System.out.println("  asking the model nicely. Try to execute without approval:");
        System.out.println();

        try {
            harness.caseManagement().remediateAndVerify(securityCase, null);
            System.out.println("    !! UNEXPECTED: execution was allowed without approval");
        } catch (IllegalStateException refused) {
            System.out.println("    REFUSED: " + refused.getMessage());
        }

        System.out.println();
        System.out.println("  The agent itself cannot manufacture an approval either:");
        System.out.println("    token available to the agent: "
                + harness.caseManagement().tokenFor(securityCase).isPresent());
        System.out.println();
        System.out.println("  So a human decides. APPROVING now...");
        pause();

        harness.caseManagement().decide(securityCase, ApprovalRequest.approvedBy(
                "CASE-VUL-001", "analyst.chris", harness.clock().tick()));

        // Held so the single-use property can be demonstrated after execution.
        var usedToken = harness.caseManagement().tokenFor(securityCase).orElseThrow();

        var result = harness.caseManagement().remediateAndVerify(securityCase, usedToken);

        System.out.println();
        System.out.println("  Remediation steps actually executed:");
        for (String step : result.remediation().steps()) {
            System.out.println("    - " + step);
        }
        System.out.println("    backup reference: " + result.remediation().backupReference());
        System.out.println();
        System.out.println("  Independent verification, against the CHANGED host:");
        for (var check : result.verification().checks()) {
            System.out.println("    [" + (check.passed() ? "PASS" : "FAIL") + "] "
                    + pad(check.name(), 26) + check.observation());
        }
        System.out.println();
        System.out.println("  Verification produced its own evidence: "
                + result.verification().evidenceIds());
        System.out.println("  Case lifecycle: " + securityCase.lifecycle());
        System.out.println();

        System.out.println("  An approval authorises exactly ONE execution. Replaying the same token:");
        System.out.println();
        try {
            harness.caseManagement().remediateAndVerify(securityCase, usedToken);
            System.out.println("    !! UNEXPECTED: the token was accepted a second time");
        } catch (IllegalStateException refused) {
            System.out.println("    REFUSED: " + refused.getMessage());
        }
        System.out.println();
        System.out.println("""
                And if a human REJECTS instead, nothing is executed at all: the case is routed to
                an analyst and the audit trail records that no action was taken.
                """);
        pause();
    }

    // ------------------------------------------------------------------

    private void segment6AuditIntegrity() {
        header("SEGMENT 6 - THE AUDIT TRAIL IS TAMPER-EVIDENT");

        SimulationClock clock = new SimulationClock();
        InMemoryAuditLog log = new InMemoryAuditLog(clock);
        log.append("CASE-DEMO", "System", "CASE_OPENED", "demo");
        log.append("CASE-DEMO", "AI Agent", "AGENT_DECISION", "INVESTIGATE inspect_service");
        log.append("CASE-DEMO", "Security Tool", "EVIDENCE_CREATED", "E-002");
        log.append("CASE-DEMO", "Human", "HUMAN_APPROVAL", "APPROVED by analyst.chris");

        System.out.println("  Every audit entry is SHA-256 hash-chained to the one before it, and the");
        System.out.println("  hash covers every field. A chain that is intact:");
        System.out.println();
        for (AuditEvent event : log.all()) {
            System.out.println("    #" + event.sequence() + " " + pad(event.eventType(), 20)
                    + " hash " + event.hash().substring(0, 16) + "...");
        }
        System.out.println();
        AuditIntegrityReport intact = log.verifyIntegrity();
        System.out.println("    verifyIntegrity() -> " + intact.describe());
        System.out.println();

        System.out.println("  Now someone edits entry #2 in place, to hide what the agent decided.");
        System.out.println("  They keep the stored hash, so only the entry's own content check catches it.");
        System.out.println();

        List<AuditEvent> tampered = new ArrayList<>(log.all());
        AuditEvent original = tampered.get(1);
        tampered.set(1, new AuditEvent(original.sequence(), original.timestamp(),
                original.actor(), original.eventType(), "ESCALATE (edited)",
                original.caseId(), original.previousHash(), original.hash()));
        log.replaceEntriesForTest(tampered);

        AuditIntegrityReport broken = log.verifyIntegrity();
        System.out.println("    verifyIntegrity() -> " + broken.describe());
        System.out.println();
        System.out.println("""
                It reports WHERE it broke and HOW, not merely that it did - because a break at
                entry 2 means something different from a break at the last entry.

                This is tamper-EVIDENT, not tamper-proof: someone with write access to the whole
                log could recompute the entire chain. What it buys is that a partial or careless
                edit - the realistic case - cannot pass silently.
                """);
        pause();
    }

    // ------------------------------------------------------------------

    private void closing() {
        header("WHAT WAS DEMONSTRATED");

        System.out.println("""
                1. An agent investigates a scanner finding and DECIDES FOR ITSELF what to check.
                2. It stops when the evidence is sufficient, even when that means dismissing the
                   finding it was handed.
                3. It refuses to guess when evidence conflicts, and escalates instead.
                4. A consequential action cannot execute without a human, enforced structurally.
                5. Remediation uses a predefined catalogued action, and is independently verified.
                6. Every decision, tool call, piece of evidence and approval is in a tamper-evident
                   audit trail.

                The claim is not that the agent is always right. It is that when the agent IS
                wrong, the system is still safe: nothing executes, and a human is asked.
                """);
        System.out.println(RULE);
    }

    // ==================================================================
    // Running a case
    // ==================================================================

    private record Harness(CaseManagementService caseManagement, InMemoryAuditLog auditLog,
                           SimulationClock clock) {
    }

    private record Run(SecurityCase securityCase, InMemoryAuditLog auditLog) {
    }

    private static ToolRegistry registry() {
        return ToolRegistry.of(
                new InspectServiceTool(),
                new LookupKevTool(),
                new GetAssetContextTool(),
                new ValidateVulnerabilityTool(),
                new CheckServiceHealthTool());
    }

    private DecisionPolicy policy(ToolRegistry registry, ConflictResolver conflictResolver) {
        if (!useLlm) {
            return new ReferenceDecisionPolicy(registry, new PriorityPolicy(), conflictResolver);
        }
        return new com.aisecurityguard.agent.llm.LlmDecisionPolicy(
                new DeepSeekModelClient(ModelProperties.fromEnvironment(), objectMapper),
                new com.aisecurityguard.agent.llm.CasePromptBuilder(registry),
                new com.aisecurityguard.agent.llm.AgentDecisionParser(registry, objectMapper));
    }

    private Harness newHarness() {
        SimulationClock clock = new SimulationClock();
        InMemoryAuditLog auditLog = new InMemoryAuditLog(clock);
        ToolRegistry registry = registry();
        ConflictResolver conflictResolver = new ConflictResolver();

        InvestigationLoop loop = new InvestigationLoop(
                policy(registry, conflictResolver), registry, auditLog, clock,
                new AssessmentService(new ConfidencePolicy(), new PriorityPolicy()),
                conflictResolver);

        CaseManagementService caseManagement = new CaseManagementService(
                loop,
                new DefaultApprovalGate(auditLog),
                new ControlledRemediationExecutor(new RemediationActionCatalog(), auditLog, clock),
                new ToolBasedRemediationVerifier(registry, auditLog, clock),
                conflictResolver,
                new InMemoryCaseRepository(),
                auditLog,
                clock);

        return new Harness(caseManagement, auditLog, clock);
    }

    private Run investigate(SecurityCase securityCase, String claim, SimulationWorld world) {
        Harness harness = newHarness();
        SecurityCase investigated = harness.caseManagement().investigate(securityCase, claim, world);
        return new Run(investigated, harness.auditLog());
    }

    // ==================================================================
    // Rendering
    // ==================================================================

    private void printDecisions(Run run) {
        System.out.println("  THE AGENT'S DECISIONS");
        System.out.println("  " + THIN);
        int n = 0;
        for (AgentDecision decision : run.securityCase().decisions()) {
            n++;
            System.out.println("  Decision #" + n + ": " + decision.decisionType()
                    + (decision.selectedTool() != null ? " -> " + decision.selectedTool() : ""));
            System.out.println("    why      : " + decision.rationale());
            if (!decision.missingEvidence().isEmpty()) {
                System.out.println("    missing  : " + String.join("; ", decision.missingEvidence()));
            }
            System.out.println("    saw      : " + decision.observedEvidenceIds());
            System.out.println();
        }
    }

    private void printEvidence(Run run) {
        System.out.println("  EVIDENCE CHAIN");
        System.out.println("  " + THIN);
        for (Evidence evidence : run.securityCase().evidence()) {
            System.out.println("  " + evidence.evidenceId() + "  " + pad(evidence.source(), 24)
                    + "[" + evidence.reliability() + "]");
            System.out.println("        " + wrap(evidence.finding(), 66, "        "));
        }
        System.out.println();
    }

    private void printAssessment(Run run) {
        var assessment = run.securityCase().assessment();
        System.out.println("  ASSESSMENT");
        System.out.println("  " + THIN);
        System.out.println("    finding status : " + assessment.findingStatus());
        System.out.println("    priority       : "
                + (assessment.priority() == null ? "(none - a human must decide)" : assessment.priority()));
        System.out.println("    confidence     : " + assessment.confidence() + "   (derived from the evidence)");
        System.out.println("    action impact  : "
                + (assessment.actionImpact() == null ? "(no action proposed)" : assessment.actionImpact()));
        if (assessment.proposedAction() != null) {
            System.out.println("    proposal       : " + assessment.proposedAction());
        }
        System.out.println("    lifecycle      : " + run.securityCase().lifecycle());
        System.out.println();
    }

    private void printAudit(Run run) {
        System.out.println("  AUDIT TRAIL  (append-only, hash-chained)");
        System.out.println("  " + THIN);
        for (AuditEvent event : run.auditLog().forCase(run.securityCase().caseId())) {
            System.out.println("  " + String.format("%2d", event.sequence()) + " "
                    + pad(event.actor(), 15) + pad(event.eventType(), 21) + event.result());
        }
        System.out.println();
        System.out.println("    integrity: " + run.auditLog().verifyIntegrity().describe());
        System.out.println();
    }

    // ==================================================================

    private void banner() {
        System.out.println();
        System.out.println(RULE);
        System.out.println("  AI SECURITY GUARD - AGENTIC VULNERABILITY INVESTIGATION");
        System.out.println("  A scanner finding is not a confirmed vulnerability.");
        System.out.println(RULE);
        System.out.println();
    }

    private void header(String title) {
        System.out.println();
        System.out.println(RULE);
        System.out.println("  " + title);
        System.out.println(RULE);
        System.out.println();
    }

    private void pause() {
        if (!pause) {
            return;
        }
        try {
            Thread.sleep(SEGMENT_PAUSE_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String pad(String value, int width) {
        if (value == null) {
            value = "";
        }
        return value.length() >= width ? value + " " : value + " ".repeat(width - value.length());
    }

    private static String wrap(String text, int width, String indent) {
        StringBuilder out = new StringBuilder();
        int lineLength = 0;
        for (String word : text.split(" ")) {
            if (lineLength + word.length() + 1 > width) {
                out.append(System.lineSeparator()).append(indent);
                lineLength = 0;
            } else if (lineLength > 0) {
                out.append(' ');
                lineLength++;
            }
            out.append(word);
            lineLength += word.length();
        }
        return out.toString();
    }
}
