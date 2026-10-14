package com.aisecurityguard.approval;

import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.ApprovalToken;

import java.util.Objects;

/**
 * A validated authorisation to execute, produced only by
 * {@link ApprovalGate#authoriseExecution}.
 *
 * <p>Its existence is the permission. Code that executes a consequential action accepts this type
 * and nothing weaker, which is what makes "was this approved?" a question the type system answers
 * rather than a question a reviewer has to check by hand.
 *
 * @param token            the token that was validated and consumed
 * @param approvedImpact   the impact the human actually approved
 * @param approverId       who approved it
 * @param remediationPlan  the narration of steps that was shown to the approver
 */
public record ApprovedExecution(
        ApprovalToken token,
        ActionImpact approvedImpact,
        String approverId,
        String remediationPlan) {

    public ApprovedExecution {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(approvedImpact, "approvedImpact must not be null");
        if (approverId == null || approverId.isBlank()) {
            throw new IllegalArgumentException("approverId must not be blank");
        }
        if (remediationPlan == null || remediationPlan.isBlank()) {
            throw new IllegalArgumentException("remediationPlan must not be blank");
        }
    }
}
