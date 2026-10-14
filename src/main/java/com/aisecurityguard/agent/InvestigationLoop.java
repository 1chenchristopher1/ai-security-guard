package com.aisecurityguard.agent;

import com.aisecurityguard.audit.AuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.AgentDecisionType;
import com.aisecurityguard.domain.Assessment;
import com.aisecurityguard.domain.AuditActors;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.Evidence;
import com.aisecurityguard.domain.EvidenceMetadata;
import com.aisecurityguard.domain.EvidenceReliability;
import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.Priority;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.domain.ToolArguments;
import com.aisecurityguard.domain.ToolResult;
import com.aisecurityguard.tool.SecurityTool;
import com.aisecurityguard.tool.SimulationWorld;
import com.aisecurityguard.tool.ToolRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The agent runtime loop: the heart of the prototype.
 *
 * <pre>
 *   Scanner Finding  -&gt; Evidence E-001
 *   while not terminal and iterations &lt; MAX_ITERATIONS:
 *       decision = decisionPolicy.decide(case)
 *       record decision + audit
 *       INVESTIGATE -&gt; validate tool exists -&gt; execute -&gt; ToolResult -&gt; Evidence -&gt; merge facts -&gt; continue
 *       ASSESS      -&gt; validate supporting evidence -&gt; store immutable Assessment -&gt; transition -&gt; stop
 *       ESCALATE    -&gt; transition + block automatic remediation -&gt; stop
 * </pre>
 *
 * <p>Responsibilities are deliberately split three ways, and the split is the point:
 * <ul>
 *   <li>{@link ReferenceDecisionPolicy} decides <em>what</em> to do (pure function of case state);</li>
 *   <li>{@link SecurityTool} implementations produce evidence (the replaceable part);</li>
 *   <li>this loop owns sequencing, state transitions, invariants and the audit trail.</li>
 * </ul>
 * A later LLM agent replaces only the first of those three.
 *
 * <p>Note what is absent by design: the loop contains no scenario branching and no tool sequence.
 * It cannot know which tools will run until the policy tells it, one decision at a time.
 *
 * <p>Milestone 0 is synchronous and deterministic - no concurrency, no virtual threads, no
 * timeouts - so that a scenario can be replayed and diffed decision for decision.
 */
@Component
public class InvestigationLoop {

    /** Hard stop so a policy defect can never spin forever. */
    public static final int MAX_ITERATIONS = 16;

    /**
     * How many times a policy may be asked to correct a refused verdict before the case is
     * escalated.
     *
     * <p>Small on purpose. One refusal is usually a premature assessment that a further capability
     * fixes; several in a row means the policy does not understand what is missing, and a human
     * should look at it rather than the loop grinding on.
     */
    public static final int MAX_REFINEMENTS = 3;

    private static final Logger log = LoggerFactory.getLogger(InvestigationLoop.class);

    private final DecisionPolicy decisionPolicy;
    private final ToolRegistry toolRegistry;
    private final AuditLog auditLog;
    private final SimulationClock clock;
    private final AssessmentService assessmentService;
    private final ConflictResolver conflictResolver;

    public InvestigationLoop(DecisionPolicy decisionPolicy,
                             ToolRegistry toolRegistry,
                             AuditLog auditLog,
                             SimulationClock clock,
                             AssessmentService assessmentService,
                             ConflictResolver conflictResolver) {
        this.decisionPolicy = Objects.requireNonNull(decisionPolicy);
        this.toolRegistry = Objects.requireNonNull(toolRegistry);
        this.auditLog = Objects.requireNonNull(auditLog);
        this.clock = Objects.requireNonNull(clock);
        this.assessmentService = Objects.requireNonNull(assessmentService);
        this.conflictResolver = Objects.requireNonNull(conflictResolver);
    }

    /**
     * Opens a case from an initial scanner finding and drives it to a terminal lifecycle.
     *
     * <p>The scanner finding becomes evidence {@code E-001}: a scanner result is input evidence,
     * never a tool call and never a parameter.
     *
     * @param securityCase the newly created case
     * @param scannerClaim the initial scanner finding text
     * @param world        the environment the tools observe
     * @return the same case instance, now carrying evidence, decisions and an assessment
     */
    public SecurityCase investigate(SecurityCase securityCase, String scannerClaim, SimulationWorld world) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        Objects.requireNonNull(world, "world must not be null");
        if (scannerClaim == null || scannerClaim.isBlank()) {
            throw new IllegalArgumentException("scannerClaim must not be blank");
        }
        if (securityCase.evidenceCount() != 0) {
            throw new IllegalStateException(
                    "case " + securityCase.caseId() + " already has evidence; "
                            + "an investigation must start from a fresh case");
        }

        // ---- 1. The scanner finding is the first evidence item, E-001. ----
        Evidence scannerEvidence = securityCase.appendEvidence(
                new EvidenceMetadata(
                        "Scanner Finding",
                        "Vulnerability Scanner",
                        scannerClaim + " This is initial evidence only, not a confirmed vulnerability.",
                        EvidenceReliability.MEDIUM,
                        Map.of()),
                clock.tick());

        auditLog.append(securityCase.caseId(), AuditActors.SYSTEM,
                "CASE_OPENED",
                securityCase.cveId() + " | initial evidence " + scannerEvidence.evidenceId());

        // The scanner's specific version claim, if it made one, is recorded as a fact so that
        // whether it contradicts the observed runtime is a question about evidence the framework
        // can answer - rather than something the scanner's own prose has to be re-parsed for.
        if (world.scannerClaimedVersion() != null && !world.scannerClaimedVersion().isBlank()) {
            securityCase.facts().merge(
                    Map.of(FactKeys.SCANNER_CLAIMED_VERSION, world.scannerClaimedVersion()));
        }

        // ---- 2. The investigation loop. ----
        int iterations = 0;
        while (!securityCase.blocksFurtherInvestigation()) {
            if (iterations >= MAX_ITERATIONS) {
                throw new IllegalStateException(
                        "case " + securityCase.caseId() + " exceeded MAX_ITERATIONS ("
                                + MAX_ITERATIONS + "). The decision policy failed to reach a "
                                + "terminal decision; this is a defect, not a runtime condition.");
            }
            iterations++;

            AgentDecision decision = decisionPolicy.decide(securityCase, world);

            // A conclusive decision can be refused: an assessment may cite evidence that does not
            // exist, or confirm a vulnerability without the facts its priority needs. Refusing is
            // correct, but it must not end the investigation - the agent is given the refusal and
            // asked to decide again, and only escalates if it cannot or will not.
            List<String> refinements = new ArrayList<>();
            while (true) {
                try {
                    switch (decision.decisionType()) {
                        case INVESTIGATE -> executeTool(securityCase, decision, world);
                        case ASSESS -> applyAssessment(securityCase, decision);
                        case ESCALATE -> applyEscalation(securityCase, decision);
                    }
                    break;
                } catch (VerdictRefusedException refused) {
                    refinements.add(refused.getMessage());
                    if (!(decisionPolicy instanceof CorrectionAwarePolicy aware)
                            || refinements.size() > MAX_REFINEMENTS) {
                        // The policy cannot self-correct, or has had enough chances. Escalating is
                        // the honest outcome: the case needs a human.
                        log.info("case {}: verdict refused {} time(s) and cannot be refined; "
                                        + "escalating. {}",
                                securityCase.caseId(), refinements.size(), refused.getMessage());
                        applyRefusalEscalation(securityCase, refinements);
                        break;
                    }
                    log.info("case {}: verdict refused, asking the agent to decide again. {}",
                            securityCase.caseId(), refused.getMessage());
                    decision = aware.decideRefined(securityCase, world, List.copyOf(refinements));
                }
            }
        }

        return securityCase;
    }

    // ------------------------------------------------------------------
    // INVESTIGATE
    // ------------------------------------------------------------------

    private void executeTool(SecurityCase securityCase, AgentDecision decision, SimulationWorld world) {
        String toolName = decision.selectedTool();
        ToolArguments arguments = decision.toolArguments();

        // The policy selected a capability; the runtime verifies it is actually available.
        // An unregistered tool is a configuration defect and must fail loudly.
        SecurityTool tool = toolRegistry.require(toolName);

        // The decision is recorded before execution, so a tool failure cannot erase the fact
        // that the agent chose to call it.
        securityCase.recordDecision(decision);
        auditLog.append(securityCase.caseId(), AuditActors.AI_AGENT,
                "AGENT_DECISION",
                AgentDecisionType.INVESTIGATE + " | " + arguments.describe(toolName));

        ToolResult result = tool.execute(securityCase, arguments, world);
        auditLog.append(securityCase.caseId(), AuditActors.SECURITY_TOOL,
                "TOOL_INVOKED",
                toolName + " | " + result.summary());

        // A tool result always becomes evidence - including when the tool failed or was
        // inconclusive. Tool failure is never interpreted as "the finding is false".
        Evidence evidence = securityCase.appendEvidence(result.evidence(), clock.tick());

        // Machine-readable facts feed the decision policy.
        securityCase.facts().merge(result.facts());

        auditLog.append(securityCase.caseId(), AuditActors.SECURITY_TOOL,
                statusEvent(result),
                evidence.evidenceId() + " | " + toolName + " | " + result.status());
    }

    private String statusEvent(ToolResult result) {
        return switch (result.status()) {
            case SUCCESS -> "EVIDENCE_CREATED";
            case FAILED -> "TOOL_FAILED";
            case INCONCLUSIVE -> "TOOL_INCONCLUSIVE";
        };
    }

    // ------------------------------------------------------------------
    // ASSESS
    // ------------------------------------------------------------------

    private void applyAssessment(SecurityCase securityCase, AgentDecision decision) {
        // The draft becomes admissible (or not) here: supporting evidence is checked and the
        // confidence is derived. A policy cannot record a verdict its evidence cannot carry.
        // Whether a contradiction stands is worked out by the framework, not self-reported.
        Assessment assessment = assessmentService.finalise(
                securityCase, decision.assessment(), conflictResolver.isConflictSettled(securityCase));

        securityCase.recordDecision(decision);
        securityCase.recordAssessment(assessment);

        CaseLifecycle next = assessment.isStopWithoutAction()
                ? CaseLifecycle.CLEARED
                : CaseLifecycle.ASSESSED;
        securityCase.moveTo(next);

        auditLog.append(securityCase.caseId(), AuditActors.AI_AGENT,
                "AGENT_DECISION",
                AgentDecisionType.ASSESS.name() + " | " + assessment.findingStatus()
                        + " / " + priorityLabel(assessment) + " / " + assessment.confidence()
                        + " (derived)");

        if (assessment.isStopWithoutAction()) {
            auditLog.append(securityCase.caseId(), AuditActors.AI_AGENT,
                    "INVESTIGATION_STOPPED",
                    "No remediation required and no approval requested");
            return;
        }

        if (assessment.proposedActionIfPresent().isPresent()) {
            auditLog.append(securityCase.caseId(), AuditActors.AI_AGENT,
                    "REMEDIATION_PROPOSED",
                    assessment.actionImpact() + " | "
                            + (assessment.requiresHumanApproval()
                                    ? "awaiting human approval"
                                    : "no approval required"));
        }
        // NOTE: no remediation is executed. Proposing is not doing.
    }

    // ------------------------------------------------------------------
    // ESCALATE
    // ------------------------------------------------------------------

    private void applyEscalation(SecurityCase securityCase, AgentDecision decision) {
        Assessment assessment = assessmentService.finalise(
                securityCase, decision.assessment(), conflictResolver.isConflictSettled(securityCase));

        securityCase.recordDecision(decision);
        securityCase.recordAssessment(assessment);

        // Automatic remediation is blocked as a property of the case, not as a UI condition.
        securityCase.blockAutomaticRemediation(assessment.rationale());
        securityCase.moveTo(CaseLifecycle.ESCALATED);

        auditLog.append(securityCase.caseId(), AuditActors.AI_AGENT,
                "AGENT_DECISION",
                AgentDecisionType.ESCALATE.name() + " | " + assessment.findingStatus()
                        + " / " + priorityLabel(assessment) + " / " + assessment.confidence());
        auditLog.append(securityCase.caseId(), AuditActors.AI_AGENT,
                "REMEDIATION_BLOCKED",
                "Human security review required; automatic remediation disabled");
    }

    // ------------------------------------------------------------------

    /**
     * Escalates a case whose verdict the runtime refused and the policy could not repair.
     *
     * <p>Recorded as an ordinary escalation, so the trail reads the same way whatever route the
     * case took to reach a human.
     */
    private void applyRefusalEscalation(SecurityCase securityCase, List<String> refinements) {
        String reason = "The runtime refused the assessment and it could not be corrected: "
                + String.join("; ", refinements);

        Assessment assessment = new Assessment(
                com.aisecurityguard.domain.FindingStatus.UNDETERMINED,
                null,
                Confidence.C4,      // overwritten by AssessmentService
                securityCase.evidenceIds(),
                reason,
                List.of(),
                null,
                null);

        AgentDecision escalation = new AgentDecision(
                AgentDecisionType.ESCALATE,
                securityCase.evidenceIds(),
                List.of("A verdict the evidence can support"),
                reason,
                null,
                null,
                assessment);

        applyEscalation(securityCase, escalation);
    }

    private String priorityLabel(Assessment assessment) {
        return assessment.priorityIfAssigned().map(Priority::name).orElse("UNASSIGNED");
    }
}
