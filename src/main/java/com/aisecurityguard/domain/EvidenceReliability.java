package com.aisecurityguard.domain;

/**
 * How much a single piece of evidence can be trusted.
 *
 * <p>Reliability decides whether a verdict is allowed. In particular
 * {@link #INCONCLUSIVE} evidence can never be read as "the finding is false" - it can only block
 * a verdict, which is why the conflict scenario escalates instead of closing the case.
 */
public enum EvidenceReliability {

    /** Authoritative, directly observed. */
    HIGH,

    /** Plausible but not independently corroborated. A scanner claim is typically medium. */
    MEDIUM,

    /** Could not be established. Blocks a verdict; does NOT mean "not vulnerable". */
    INCONCLUSIVE
}
