package com.aisecurityguard.agent;

/**
 * Whether the evidence in a case contains a contradiction between sources, and if so whether it
 * has been settled.
 *
 * <p>This is a property of the <em>evidence</em>, not an opinion a decision policy is entitled to
 * hold. Distinguishing {@link #PENDING} from {@link #UNRESOLVED} is what stops a policy from
 * declaring a conflict resolved simply because it has stopped looking.
 */
public enum ConflictStatus {

    /** No contradiction: no conflicting claim was made, or none remains. */
    NONE,

    /**
     * A conflicting claim has been identified but not yet challenged by an independent check.
     * The agent still has a tool it can use to try to settle the question.
     */
    PENDING,

    /**
     * A conflicting claim remains after the framework used every available means to settle it.
     * This is the honest end state: the contradiction stands.
     */
    UNRESOLVED;

    /** True when a contradiction still stands and no further automatic resolution is possible. */
    public boolean isUnresolvedConflict() {
        return this == UNRESOLVED;
    }

    /**
     * Whether the evidence can support a confident verdict. Only a resolved (or absent) conflict
     * can: {@link #PENDING} is not an error state, but it is not a settled one either.
     */
    public boolean isSettled() {
        return this == NONE;
    }
}
