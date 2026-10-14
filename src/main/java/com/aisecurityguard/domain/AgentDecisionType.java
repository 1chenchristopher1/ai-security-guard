package com.aisecurityguard.domain;

/**
 * The three decisions the agent runtime is allowed to make. Mirrors {@code DEC} in the prototype.
 *
 * <p>There is intentionally no "REMEDIATE" decision: the agent may investigate, assess and
 * propose, but executing a consequential action is a separate, human-gated step.
 */
public enum AgentDecisionType {

    /** Evidence is insufficient. The agent selects a tool to obtain the next piece of evidence. */
    INVESTIGATE,

    /** Evidence is sufficient and consistent. The agent forms an assessment. */
    ASSESS,

    /**
     * Evidence conflicts, a key capability failed, or no reliable verdict is possible.
     * The case is handed to a human and automatic remediation is blocked.
     */
    ESCALATE
}
