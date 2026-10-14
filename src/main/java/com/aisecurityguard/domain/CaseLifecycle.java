package com.aisecurityguard.domain;

/**
 * Lifecycle of a security case: <em>where the workflow is</em>.
 *
 * <p>Deliberately kept separate from {@link FindingStatus}: the lifecycle says what the process is
 * doing, the finding status says what is true about the asset. Resolving a case must never
 * overwrite the finding status - the prototype's
 * {@code c.assessment = {...c.assessment, status:'RESOLVED'}} mutation is explicitly NOT
 * reproduced here.
 */
public enum CaseLifecycle {

    /** Actor: System. The case exists and the agent has not yet produced a decision. */
    INVESTIGATING,

    /**
     * Actor: AI Agent. An assessment was produced and it proposes a consequential action.
     * The case is now waiting for a human; it is not finished.
     */
    ASSESSED,

    /** Actor: AI Agent. The finding was dismissed; no action and no human decision is required. */
    CLEARED,

    /** Actor: AI Agent, or Human. No reliable verdict; automatic remediation is blocked. */
    ESCALATED,

    // ---- remediation stages, reachable only through an approved execution ----

    /** Actor: Human. An approved remediation is executing. */
    REMEDIATING,

    /** Actor: Security Tool. An approved remediation is being independently verified. */
    VERIFYING,

    /** Actor: System. The fix was verified. */
    RESOLVED;

    /**
     * True when the case has reached a state that nothing further happens in.
     *
     * <p>Note that {@link #ASSESSED} is deliberately <em>not</em> terminal: it means the agent's
     * investigation is complete and the case is waiting for a human, which is a live obligation
     * rather than an end state. An unreviewed critical finding is not a finished one.
     */
    public boolean isTerminal() {
        return this == CLEARED || this == ESCALATED || this == RESOLVED;
    }

    /**
     * True when the agent must not take further investigative decisions.
     *
     * <p>This is what the investigation loop terminates on. It is broader than
     * {@link #isTerminal()} because the agent also stops once it has produced an assessment -
     * even though the case itself remains open and awaiting approval.
     */
    public boolean blocksFurtherInvestigation() {
        return this != INVESTIGATING;
    }

    /** True while an assessed case is waiting for a human decision. */
    public boolean isAwaitingHumanDecision() {
        return this == ASSESSED;
    }

    /** True while the case is waiting on, or executing, remediation. */
    public boolean isRemediationStage() {
        return this == REMEDIATING || this == VERIFYING || this == RESOLVED;
    }
}
