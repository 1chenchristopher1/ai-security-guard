package com.aisecurityguard.domain;

/**
 * Where a case stands with respect to human authorisation.
 *
 * <p>Distinct from {@link CaseLifecycle}: the lifecycle says what the process is doing, this says
 * whether the human gate has been passed. A case can be {@code ASSESSED} and
 * {@link #PENDING}, or {@code ASSESSED} and {@link #APPROVED}.
 */
public enum ApprovalOutcome {

    /** A consequential action is proposed and no human has decided yet. Execution is blocked. */
    PENDING,

    /** A human authorised execution. Exactly one execution may proceed. */
    APPROVED,

    /** A human refused, and the case is routed to an analyst. Execution is blocked permanently. */
    REJECTED,

    /** No authorisation is required because no consequential action was proposed. */
    NOT_REQUIRED
}
