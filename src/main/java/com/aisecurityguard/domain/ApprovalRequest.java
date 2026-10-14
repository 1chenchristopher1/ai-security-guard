package com.aisecurityguard.domain;

import java.time.LocalTime;
import java.util.Objects;

/**
 * The record of a human approving or rejecting a proposed consequential action.
 *
 * <p>This is the evidence that a human was in the loop. It names the approver, so a later
 * milestone can attribute the decision to a real identity rather than to "a human, somewhere".
 *
 * @param caseId      the case the decision applies to
 * @param decision    what the human decided
 * @param approverId  who decided; never blank, because an unattributable approval is not one
 * @param approvedAt  when the decision was made
 * @param reason      optional free-text reason, required for a rejection
 */
public record ApprovalRequest(
        String caseId,
        ApprovalDecision decision,
        String approverId,
        LocalTime approvedAt,
        String reason) {

    public ApprovalRequest {
        if (caseId == null || caseId.isBlank()) {
            throw new IllegalArgumentException("approval caseId must not be blank");
        }
        Objects.requireNonNull(decision, "approval decision must not be null");
        if (approverId == null || approverId.isBlank()) {
            throw new IllegalArgumentException(
                    "approverId must not be blank: an approval that cannot be attributed to a "
                            + "person is not an approval");
        }
        Objects.requireNonNull(approvedAt, "approval timestamp must not be null");
        if (decision == ApprovalDecision.REJECTED_AND_ESCALATED
                && (reason == null || reason.isBlank())) {
            throw new IllegalArgumentException("a rejection must record a reason");
        }
    }

    /** An approval by a named human. */
    public static ApprovalRequest approvedBy(String caseId, String approverId, LocalTime at) {
        return new ApprovalRequest(caseId, ApprovalDecision.APPROVED, approverId, at, null);
    }

    /** A rejection by a named human, which routes the case to an analyst. */
    public static ApprovalRequest rejectedBy(String caseId, String approverId, LocalTime at,
                                             String reason) {
        return new ApprovalRequest(caseId, ApprovalDecision.REJECTED_AND_ESCALATED,
                approverId, at, reason);
    }
}
