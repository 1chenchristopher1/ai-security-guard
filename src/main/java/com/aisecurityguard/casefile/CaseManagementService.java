package com.aisecurityguard.casefile;

import com.aisecurityguard.agent.ConflictResolver;
import com.aisecurityguard.agent.InvestigationLoop;
import com.aisecurityguard.approval.ApprovalGate;
import com.aisecurityguard.approval.ApprovedExecution;
import com.aisecurityguard.audit.AuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.domain.ApprovalOutcome;
import com.aisecurityguard.domain.ApprovalRequest;
import com.aisecurityguard.domain.ApprovalToken;
import com.aisecurityguard.domain.AuditActors;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.remediation.RemediationExecutor;
import com.aisecurityguard.remediation.RemediationOutcome;
import com.aisecurityguard.tool.SimulationWorld;
import com.aisecurityguard.verification.RemediationVerification;
import com.aisecurityguard.verification.RemediationVerifier;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The end-to-end case workflow: investigate, then handle the human decision, then remediate and
 * verify.
 *
 * <p>This is the component the UI layer will talk to. It exists so that the ordering constraints
 * between the stages live in one place, and so that no caller can reach remediation without going
 * through the approval gate.
 *
 * <p>The critical property is what is <em>absent</em>: there is no method to execute remediation
 * that takes anything other than an {@link ApprovalToken}. A caller with a case, an assessment and
 * good intentions cannot remediate anything.
 */
@Service
public class CaseManagementService {

    /** The lifecycle states from which an approved execution may proceed. */
    private static final CaseLifecycle REQUIRED_STATE_FOR_APPROVAL = CaseLifecycle.ASSESSED;

    private final InvestigationLoop investigationLoop;
    private final ApprovalGate approvalGate;
    private final RemediationExecutor remediationExecutor;
    private final RemediationVerifier remediationVerifier;
    private final ConflictResolver conflictResolver;
    private final CaseRepository caseRepository;
    private final AuditLog auditLog;
    private final SimulationClock clock;

    public CaseManagementService(InvestigationLoop investigationLoop,
                                 ApprovalGate approvalGate,
                                 RemediationExecutor remediationExecutor,
                                 RemediationVerifier remediationVerifier,
                                 ConflictResolver conflictResolver,
                                 CaseRepository caseRepository,
                                 AuditLog auditLog,
                                 SimulationClock clock) {
        this.investigationLoop = Objects.requireNonNull(investigationLoop);
        this.approvalGate = Objects.requireNonNull(approvalGate);
        this.remediationExecutor = Objects.requireNonNull(remediationExecutor);
        this.remediationVerifier = Objects.requireNonNull(remediationVerifier);
        this.conflictResolver = Objects.requireNonNull(conflictResolver);
        this.caseRepository = Objects.requireNonNull(caseRepository);
        this.auditLog = Objects.requireNonNull(auditLog);
        this.clock = Objects.requireNonNull(clock);
    }

    /** Opens a case from a scanner finding and runs the agent investigation to a conclusion. */
    public SecurityCase investigate(SecurityCase securityCase, String scannerClaim,
                                    SimulationWorld world) {
        SecurityCase investigated = investigationLoop.investigate(securityCase, scannerClaim, world);
        persist(investigated, world);
        return investigated;
    }

    /**
     * Loads a previously investigated case, so a case can be continued after the process that
     * investigated it has moved on.
     */
    public Optional<SecurityCase> load(String caseId) {
        return caseRepository.find(caseId).map(CaseRepository.StoredCase::securityCase);
    }

    /** Every stored case, in the order they were first opened. */
    public List<SecurityCase> allCases() {
        return caseRepository.all().stream()
                .map(CaseRepository.StoredCase::securityCase)
                .toList();
    }

    /**
     * Forgets every case.
     *
     * <p>A demonstration affordance for resetting between takes, not a domain operation: real
     * cases are never deleted. The audit trail is intentionally left alone - a trail that can be
     * cleared on demand proves nothing.
     */
    public void reset() {
        caseRepository.clear();
        auditLog.append("-", AuditActors.SYSTEM, "DEMO_RESET",
                "case storage cleared for a fresh demonstration; audit history retained");
    }

    /** The environment a case was investigated against, as recorded with the case. */
    public Optional<SimulationWorld> observedWorldFor(SecurityCase securityCase) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        return caseRepository.find(securityCase.caseId())
                .map(CaseRepository.StoredCase::observedWorld);
    }

    /** Writes the case's current state back to storage. */
    private void persist(SecurityCase securityCase, SimulationWorld observedWorld) {
        caseRepository.save(securityCase, observedWorld, clock.tick());
    }

    /**
     * Records a human decision on a case awaiting approval.
     *
     * @return the resulting gate state; {@link ApprovalOutcome#APPROVED} means execution may now
     *         be attempted with the token from {@link #tokenFor}
     * @throws IllegalStateException if the case is not awaiting a human decision
     */
    public ApprovalOutcome decide(SecurityCase securityCase, ApprovalRequest request) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        if (securityCase.lifecycle() != REQUIRED_STATE_FOR_APPROVAL) {
            throw new IllegalStateException(
                    "case " + securityCase.caseId() + " is in lifecycle " + securityCase.lifecycle()
                            + " and is not awaiting a human approval decision");
        }

        ApprovalOutcome outcome = approvalGate.decide(securityCase, request);

        if (outcome != ApprovalOutcome.APPROVED) {
            // A rejection is a routing decision, not a dead end: nothing was executed, and the
            // case goes to an analyst. The gate has already recorded the human's decision itself.
            securityCase.blockAutomaticRemediation("rejected by " + request.approverId()
                    + ": " + request.reason());
            securityCase.moveTo(CaseLifecycle.ESCALATED);
            auditLog.append(securityCase.caseId(), AuditActors.SYSTEM, "REMEDIATION_BLOCKED",
                    "nothing was executed; case escalated to an analyst");
        }
        return outcome;
    }

    /**
     * Executes an approved remediation and verifies it.
     *
     * <p>Neither stage can be reached without passing an {@link ApprovalToken} that the gate
     * validates and consumes.
     *
     * @throws IllegalStateException if execution is not authorised
     */
    public RemediationResult remediateAndVerify(SecurityCase securityCase, ApprovalToken token) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");

        // The gate validates the token, checks the case, the approver and the approved impact,
        // and consumes the token so this approval cannot authorise a second execution.
        ApprovedExecution execution = approvalGate.authoriseExecution(securityCase, token);

        SimulationWorld observedWorld = observedWorldFor(securityCase).orElseThrow(() ->
                new IllegalStateException("case " + securityCase.caseId()
                        + " has no recorded environment to remediate. A case must be investigated "
                        + "through this service before it can be remediated."));

        RemediationOutcome remediation = remediationExecutor.execute(
                securityCase, execution, observedWorld);

        // Verification observes the *changed* world, which is what makes it a real check.
        RemediationVerification verification = remediationVerifier.verify(
                securityCase, remediation.postFixWorld());

        // Note what is deliberately NOT done here: the stored environment is not updated to the
        // post-fix state. The observed world is evidence - it is the target as the assessment was
        // formed against - and overwriting it would make the audit trail describe a machine that
        // never existed. The post-fix state is reported in the outcome for anyone who needs it.
        persist(securityCase, observedWorld);

        return new RemediationResult(remediation, verification);
    }

    /**
     * The token issued for an approved case, if there is one.
     *
     * <p>Deliberately only present after {@link #decide} returned
     * {@link ApprovalOutcome#APPROVED}: obtaining the token is the reward for a human decision, not
     * something a caller can look up independently. Returning empty rather than throwing lets the
     * approval screen ask "is this approved yet?" without treating a normal state as an error.
     */
    public Optional<ApprovalToken> tokenFor(SecurityCase securityCase) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        return approvalGate.tokenFor(securityCase);
    }

    /** Hands an escalated case to a named human analyst. */
    public void takeOver(SecurityCase securityCase, String analystId) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        if (analystId == null || analystId.isBlank()) {
            throw new IllegalArgumentException("an analyst must be named to take over a case");
        }
        if (securityCase.lifecycle() != CaseLifecycle.ESCALATED) {
            throw new IllegalStateException(
                    "case " + securityCase.caseId() + " is not escalated and cannot be taken over");
        }
        auditLog.append(securityCase.caseId(), AuditActors.HUMAN, "CASE_TAKEN_OVER",
                "assigned to analyst " + analystId);
    }

    /** The current approval requirement and gate state for a case, for the approval screen. */
    public ApprovalStatus approvalStatusFor(SecurityCase securityCase) {
        var assessment = securityCase.assessmentIfPresent();
        boolean required = assessment.map(approvalGate::requiresHumanApproval).orElse(false);
        ApprovalOutcome outcome = required
                ? approvalGate.outcomeFor(securityCase)
                : ApprovalOutcome.NOT_REQUIRED;
        return new ApprovalStatus(
                required,
                outcome,
                assessment.map(CaseManagementService::describe).orElse("no assessment yet"),
                conflictResolver.resolve(securityCase),
                securityCase.isAutomaticRemediationBlocked(),
                approvalGate.approverFor(securityCase).orElse(null));
    }

    /** A one-line, human-readable summary of an assessment for the approval screen. */
    private static String describe(com.aisecurityguard.domain.Assessment assessment) {
        return assessment.findingStatus()
                + " / " + assessment.priorityIfAssigned().map(Enum::name).orElse("unassigned")
                + " / " + assessment.confidence();
    }

    /** Convenience view of a case's approval situation. */
    public record ApprovalStatus(
            boolean approvalRequired,
            ApprovalOutcome outcome,
            String assessmentSummary,
            com.aisecurityguard.agent.ConflictStatus conflictStatus,
            boolean automaticRemediationBlocked,
            String approverId) {
    }

    /** What a completed remediation cycle produced. */
    public record RemediationResult(RemediationOutcome remediation,
                                    RemediationVerification verification) {
    }
}
