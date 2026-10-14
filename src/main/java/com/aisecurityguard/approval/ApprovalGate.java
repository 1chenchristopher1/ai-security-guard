package com.aisecurityguard.approval;

import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.ApprovalDecision;
import com.aisecurityguard.domain.ApprovalOutcome;
import com.aisecurityguard.domain.ApprovalRequest;
import com.aisecurityguard.domain.ApprovalToken;
import com.aisecurityguard.domain.Assessment;
import com.aisecurityguard.domain.SecurityCase;

import java.util.Optional;

/**
 * The human-in-the-loop gate.
 *
 * <p>This is the component the prototype described but did not have: "approval is enforced by the
 * runtime policy layer, not merely by an AI prompt". The enforcement is structural rather than
 * declarative - {@link #authoriseExecution} is the <em>only</em> way to obtain an
 * {@link ApprovalToken}, and the remediation executor requires a token to do anything. There is
 * deliberately no boolean flag, no "skipApproval" parameter, and no path from an assessment to
 * execution that does not pass through a human decision.
 */
public interface ApprovalGate {

    /**
     * Whether the assessment proposes an action the runtime will not execute unattended.
     *
     * @return true when the action impact is consequential (A2)
     */
    boolean requiresHumanApproval(Assessment assessment);

    /**
     * Records a human decision and, if it was an approval, issues a single-use execution token.
     *
     * @param securityCase the case being decided
     * @param request      the human's decision
     * @return the resulting gate state
     * @throws IllegalStateException when the case proposes nothing that needs approval
     */
    ApprovalOutcome decide(SecurityCase securityCase, ApprovalRequest request);

    /**
     * Exchanges an approval token for permission to execute.
     *
     * <p>Every check here exists because of a specific way a gate can be bypassed: the case must
     * match, the token must not have been used, the impact must be the one the human saw, and the
     * token must correspond to an approval that actually happened.
     *
     * @param securityCase the case about to execute
     * @param token        the token presented as authorisation
     * @throws IllegalStateException if execution is not authorised for any reason
     */
    ApprovedExecution authoriseExecution(SecurityCase securityCase, ApprovalToken token);

    /** The current gate state for a case. */
    ApprovalOutcome outcomeFor(SecurityCase securityCase);

    /** The impact a human actually approved, if any. */
    ActionImpact approvedImpactFor(SecurityCase securityCase);

    /** The human decision recorded for a case, if any. */
    ApprovalDecision decisionFor(SecurityCase securityCase);

    /**
     * The execution token issued for a case, if a human approved it.
     *
     * <p>Empty unless {@link #outcomeFor} is {@link ApprovalOutcome#APPROVED}. This is the only
     * way to obtain a token, and obtaining one is the reward for a human decision rather than
     * something a caller can look up independently.
     */
    Optional<ApprovalToken> tokenFor(SecurityCase securityCase);

    /**
     * Who approved or rejected the case, if anyone has.
     *
     * <p>Separate from {@link #tokenFor} because the approver is a matter of record and outlives
     * the token, which is consumed on execution.
     */
    Optional<String> approverFor(SecurityCase securityCase);
}
