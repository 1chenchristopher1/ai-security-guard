package com.aisecurityguard.approval;

import com.aisecurityguard.audit.AuditLog;
import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.ApprovalDecision;
import com.aisecurityguard.domain.ApprovalOutcome;
import com.aisecurityguard.domain.ApprovalRequest;
import com.aisecurityguard.domain.ApprovalToken;
import com.aisecurityguard.domain.Assessment;
import com.aisecurityguard.domain.AuditActors;
import com.aisecurityguard.domain.SecurityCase;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of the human-in-the-loop gate.
 *
 * <p>State is held per case and is deliberately not on the case itself: whether a human has
 * approved an action is a decision by an external actor, not a property of the finding.
 *
 * <p>See {@link ApprovalGate} for why this exists. The short version: a consequential action is
 * unreachable without a token, and a token is unreachable without a human.
 */
@Component
public class DefaultApprovalGate implements ApprovalGate {

    /** Per-case approval state. */
    private record GateState(ApprovalOutcome outcome, ApprovalDecision decision,
                             ActionImpact approvedImpact, ApprovalToken token) {
    }

    private static final GateState NOT_REQUIRED_STATE =
            new GateState(ApprovalOutcome.NOT_REQUIRED, null, null, null);

    private final Map<String, GateState> states = new ConcurrentHashMap<>();
    private final Map<String, ApprovalRequest> requests = new ConcurrentHashMap<>();
    private final AuditLog auditLog;

    public DefaultApprovalGate(AuditLog auditLog) {
        this.auditLog = Objects.requireNonNull(auditLog);
    }

    @Override
    public boolean requiresHumanApproval(Assessment assessment) {
        Objects.requireNonNull(assessment, "assessment must not be null");
        return assessment.requiresHumanApproval();
    }

    @Override
    public ApprovalOutcome decide(SecurityCase securityCase, ApprovalRequest request) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        Objects.requireNonNull(request, "request must not be null");

        if (!securityCase.caseId().equals(request.caseId())) {
            throw new IllegalStateException(
                    "approval for case " + request.caseId() + " cannot be applied to case "
                            + securityCase.caseId());
        }

        Assessment assessment = securityCase.assessmentIfPresent().orElseThrow(() ->
                new IllegalStateException(
                        "case " + securityCase.caseId() + " has no assessment to approve"));
        if (!requiresHumanApproval(assessment)) {
            throw new IllegalStateException(
                    "case " + securityCase.caseId() + " proposes no consequential action, so "
                            + "there is nothing for a human to approve");
        }

        if (states.containsKey(securityCase.caseId())) {
            throw new IllegalStateException(
                    "case " + securityCase.caseId() + " has already been decided by a human; "
                            + "an approval cannot be re-taken");
        }

        requests.put(securityCase.caseId(), request);

        if (request.decision().authorisesExecution()) {
            // The token carries the impact the human was actually shown, so a later mismatch
            // between what was approved and what is attempted is detectable.
            ApprovalToken token = ApprovalToken.mintFor(
                    ApprovalToken.issuerKeyForGate(),
                    securityCase.caseId(),
                    request.approverId(),
                    request.approvedAt(),
                    assessment.actionImpact());

            states.put(securityCase.caseId(), new GateState(
                    ApprovalOutcome.APPROVED, request.decision(),
                    assessment.actionImpact(), token));

            // The gate owns the record of the decision, so exactly one component writes it.
            auditLog.append(securityCase.caseId(), AuditActors.HUMAN, "HUMAN_APPROVAL",
                    "APPROVED by " + request.approverId() + " | " + assessment.actionImpact()
                            + " | " + assessment.proposedActionIfPresent().orElse("no action"));
            return ApprovalOutcome.APPROVED;
        }

        states.put(securityCase.caseId(), new GateState(
                ApprovalOutcome.REJECTED, request.decision(), null, null));
        auditLog.append(securityCase.caseId(), AuditActors.HUMAN, "HUMAN_DECISION",
                "REJECTED by " + request.approverId() + " | " + request.reason());
        return ApprovalOutcome.REJECTED;
    }

    @Override
    public ApprovedExecution authoriseExecution(SecurityCase securityCase, ApprovalToken token) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");

        if (token == null) {
            throw new IllegalStateException(
                    "case " + securityCase.caseId() + " cannot execute a consequential action "
                            + "without an approval token");
        }
        if (!securityCase.caseId().equals(token.caseId())) {
            throw new IllegalStateException(
                    "approval token was issued for case " + token.caseId()
                            + " and cannot authorise execution on case " + securityCase.caseId());
        }

        GateState state = states.get(securityCase.caseId());
        if (state == null || state.outcome() != ApprovalOutcome.APPROVED) {
            throw new IllegalStateException(
                    "case " + securityCase.caseId() + " has no recorded human approval");
        }
        if (state.token() != token) {
            throw new IllegalStateException(
                    "approval token does not correspond to the approval recorded for case "
                            + securityCase.caseId());
        }

        Assessment assessment = securityCase.assessmentIfPresent().orElseThrow(() ->
                new IllegalStateException(
                        "case " + securityCase.caseId() + " has no assessment to execute"));

        // The human approved a specific action impact. If what is now proposed is more
        // consequential than what was approved, the approval does not cover it.
        if (assessment.actionImpact() != token.approvedImpact()) {
            throw new IllegalStateException(
                    "case " + securityCase.caseId() + " now proposes " + assessment.actionImpact()
                            + " but the human approved " + token.approvedImpact());
        }

        if (!token.consume()) {
            throw new IllegalStateException(
                    "approval token for case " + securityCase.caseId() + " has already been used; "
                            + "one approval authorises one execution");
        }

        return new ApprovedExecution(
                token, token.approvedImpact(), token.approverId(),
                remediationPlanFor(assessment));
    }

    @Override
    public ApprovalOutcome outcomeFor(SecurityCase securityCase) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");

        GateState state = states.get(securityCase.caseId());
        if (state != null) {
            return state.outcome();
        }

        // No decision recorded. That is only "not required" when the case proposes nothing
        // consequential; if it proposes an A2 action and nobody has decided, the honest answer is
        // that it is still waiting. Reporting NOT_REQUIRED here would tell the approval screen
        // there is nothing to approve at the exact moment approval is mandatory.
        boolean approvalRequired = securityCase.assessmentIfPresent()
                .map(this::requiresHumanApproval)
                .orElse(false);

        return approvalRequired ? ApprovalOutcome.PENDING : ApprovalOutcome.NOT_REQUIRED;
    }

    @Override
    public ActionImpact approvedImpactFor(SecurityCase securityCase) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        return states.getOrDefault(securityCase.caseId(), NOT_REQUIRED_STATE).approvedImpact();
    }

    @Override
    public ApprovalDecision decisionFor(SecurityCase securityCase) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        return states.getOrDefault(securityCase.caseId(), NOT_REQUIRED_STATE).decision();
    }

    @Override
    public Optional<ApprovalToken> tokenFor(SecurityCase securityCase) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        GateState state = states.get(securityCase.caseId());
        if (state == null || state.outcome() != ApprovalOutcome.APPROVED) {
            return Optional.empty();
        }
        return Optional.ofNullable(state.token());
    }

    @Override
    public Optional<String> approverFor(SecurityCase securityCase) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        // Read from the recorded decision rather than the token, so the approver is still
        // reportable after the token has been consumed by execution.
        ApprovalRequest request = requests.get(securityCase.caseId());
        return request == null ? Optional.empty() : Optional.of(request.approverId());
    }

    /** The human decision recorded for a case, as a request, if any. */
    public Optional<ApprovalRequest> requestFor(SecurityCase securityCase) {
        return Optional.ofNullable(requests.get(securityCase.caseId()));
    }

    private String remediationPlanFor(Assessment assessment) {
        return assessment.proposedActionIfPresent().orElse("no action");
    }
}
