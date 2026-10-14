package com.aisecurityguard.domain;

/**
 * The agent's conclusion about the vulnerability itself: <em>what is true about the asset</em>.
 *
 * <p>Independent of {@link CaseLifecycle} and of {@link Priority}. A finding can be
 * {@link #CONFIRMED_VULNERABLE} at {@link Priority#P0} or at {@link Priority#P2}; a finding can be
 * {@link #UNDETERMINED} with no priority at all.
 */
public enum FindingStatus {

    /** Runtime evidence confirms the affected version and the assessment is well supported. */
    CONFIRMED_VULNERABLE,

    /** Runtime evidence contradicts the scanner finding. The finding is a false positive. */
    NOT_AFFECTED,

    /** Evidence conflicts or is inconclusive. The agent refuses to force a verdict. */
    UNDETERMINED
}
