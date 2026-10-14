package com.aisecurityguard.domain;

/**
 * A human decision on a proposed consequential action.
 *
 * <p>Rejection is deliberately not a dead end: it routes the case to a human analyst rather than
 * simply blocking execution. That distinction matters operationally - the finding still needs
 * someone to deal with it, and "nothing was executed" is a different outcome from "nothing
 * happens next".
 */
public enum ApprovalDecision {

    /** Execute the proposal. Only this decision can produce an execution token. */
    APPROVED,

    /** Do not execute, and hand the case to a human analyst. */
    REJECTED_AND_ESCALATED;

    /** True when this decision authorises execution. */
    public boolean authorisesExecution() {
        return this == APPROVED;
    }
}
