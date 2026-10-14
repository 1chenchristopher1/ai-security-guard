package com.aisecurityguard.agent;

/**
 * Raised when the runtime refuses a conclusive verdict.
 *
 * <p>Distinct from a malformed decision: the decision was well formed, and the agent was entitled
 * to reach it, but the case cannot carry it. Two things cause this:
 * <ul>
 *   <li>the assessment cites evidence that does not exist in the case;</li>
 *   <li>the assessment confirms a vulnerability without the facts its priority is derived from.</li>
 * </ul>
 *
 * <p>Being a refusal rather than a fault, it is recoverable: {@link InvestigationLoop} hands the
 * reason to the policy and asks it to decide again, so an agent that was merely premature can go
 * and gather what it was missing. Escalation is the fallback, not the first response.
 */
public class VerdictRefusedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public VerdictRefusedException(String message) {
        super(message);
    }
}
