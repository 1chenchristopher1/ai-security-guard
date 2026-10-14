package com.aisecurityguard.domain;

/**
 * Remediation urgency. Lower ordinal = more urgent (P0 is most urgent, P5 is no action needed).
 *
 * <p>Orthogonal to {@link FindingStatus} and to {@link Confidence}: priority answers
 * "how soon must this be fixed", not "is it real" and not "how sure are we".
 *
 * <p>An assessment may legitimately have <em>no</em> priority assigned - see
 * {@link Assessment#priority()}, which is nullable for exactly that reason.
 */
public enum Priority {

    /** Confirmed vulnerability, known exploitation, exposed production asset. Immediate remediation. */
    P0,

    /** Concrete, imminent risk that should be scheduled for immediate work. */
    P1,

    /** Confirmed but not immediately exploitable in context. Scheduled remediation. */
    P2,

    /** Confirmed but only reachable from a trusted network segment. */
    P3,

    /** Low impact and low exposure; fix as capacity allows. */
    P4,

    /**
     * Lowest urgency: no scheduled remediation.
     *
     * <p>Deliberately <b>not</b> phrased as "no action needed". The risk-factor matrix can reach P5
     * for a <em>confirmed</em> vulnerability that is contained - for example an affected version on
     * an internal development host with no known exploitation. In that case there is still a real
     * finding and a real remediation proposal awaiting a human; what P5 says is that the work is
     * not urgent, not that it is unnecessary.
     *
     * <p>Whether an action is needed at all is a different axis: it is expressed by the finding
     * status ({@link FindingStatus#NOT_AFFECTED} means no action) and by the presence or absence of
     * a proposed action, never by the priority.
     */
    P5
}
