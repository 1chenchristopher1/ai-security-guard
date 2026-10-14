package com.aisecurityguard.agent.llm;

import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.AgentDecisionType;
import com.aisecurityguard.domain.Assessment;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.SecurityCase;

import java.util.List;

/**
 * Raised when a model reply could not be turned into a usable decision.
 *
 * <p>Distinct from {@link com.aisecurityguard.model.ModelUnavailableException}: here a reply
 * <em>was</em> obtained, but it was unparseable, structurally invalid, or asked for something the
 * runtime will not permit (an unknown capability, an absent rationale, a proposal to act without
 * approval).
 *
 * <p>Both cases are handled the same way by the runtime - stop and hand the case to a human -
 * because neither is evidence about the vulnerability.
 */
public class DecisionRejectedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public DecisionRejectedException(String message) {
        super(message);
    }

    public DecisionRejectedException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Builds the decision the runtime takes when the agent cannot decide.
     *
     * <p>This is the safety net that makes degradation honest. Whatever went wrong - no API key, no
     * connectivity, a malformed reply, a capability that does not exist - the outcome is the same:
     * the case is escalated to a human, no action is proposed, and nothing is remediated.
     *
     * <p>Crucially this is <b>not</b> read as "not vulnerable". A model that failed to answer has
     * told us nothing about the asset.
     *
     * @param securityCase the case that could not be decided
     * @param reason       why no decision was possible; recorded in the audit trail
     */
    public static AgentDecision escalateBecauseUnavailable(SecurityCase securityCase, String reason) {
        String rationale = "The agent runtime could not produce a decision: " + reason
                + " No automated verdict is possible, so this case requires human review.";

        Assessment assessment = new Assessment(
                FindingStatus.UNDETERMINED,
                null,
                // Confidence is derived by AssessmentService; this placeholder is overwritten.
                // The evidence may be fine - it is the decision that is missing, not the evidence.
                Confidence.C4,
                securityCase.evidenceIds(),
                rationale,
                List.of(),
                null,
                null);

        return new AgentDecision(
                AgentDecisionType.ESCALATE,
                securityCase.evidenceIds(),
                List.of("A decision from the agent runtime"),
                rationale,
                null,
                null,
                assessment);
    }
}
