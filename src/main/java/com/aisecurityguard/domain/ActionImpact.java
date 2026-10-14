package com.aisecurityguard.domain;

/**
 * Operational risk of the <em>action</em>, independent of the risk of the vulnerability.
 *
 * <p>This is the axis that drives the human-in-the-loop gate. It is deliberately a separate
 * concept: a P0 vulnerability with a read-only validation action is A0, while the same
 * vulnerability with a remediation action is A2 and requires approval.
 */
public enum ActionImpact {

    /** Informational / read-only. No change to the target. No approval required. */
    A0,

    /** Low impact, reversible, non-disruptive. Approval may still be required by policy. */
    A1,

    /** Consequential action. May modify a running service, so human approval is mandatory. */
    A2;

    /** True when this action impact requires explicit human approval before execution. */
    public boolean requiresHumanApproval() {
        return this == A2;
    }
}
