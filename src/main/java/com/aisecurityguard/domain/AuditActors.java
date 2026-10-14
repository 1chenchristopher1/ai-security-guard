package com.aisecurityguard.domain;

/** The four audit actors, mirroring the prototype's audit icons. */
public final class AuditActors {

    /** The platform itself: case creation, lifecycle transitions. */
    public static final String SYSTEM = "System";

    /** The agent runtime: decisions and assessment proposals. */
    public static final String AI_AGENT = "AI Agent";

    /** A security tool: execution and the evidence it produced. */
    public static final String SECURITY_TOOL = "Security Tool";

    /** A human being: approval, rejection, case takeover. */
    public static final String HUMAN = "Human";

    private AuditActors() {
    }
}
