package com.aisecurityguard.domain;

/**
 * How strongly the current assessment is supported by evidence. Lower ordinal = stronger support
 * (C0 is very high confidence, C4 is very low confidence).
 *
 * <p>This is the system's honesty valve. Evidence conflict must lower confidence rather than be
 * papered over: conflicting evidence prevents a C0/C1 rating even when one source looks
 * authoritative.
 */
public enum Confidence {

    /** Multiple independent evidence sources consistently support the assessment. */
    C0,

    /** Strong evidence with a minor unresolved gap. */
    C1,

    /** Reasonable evidence, but at least one material gap remains. */
    C2,

    /** Evidence conflicts or a key tool was unavailable. No reliable automated verdict. */
    C3,

    /** Almost no usable evidence. */
    C4
}
