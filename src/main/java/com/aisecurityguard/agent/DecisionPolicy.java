package com.aisecurityguard.agent;

import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.SimulationWorld;

/**
 * Decides what the agent should do next, from the current state of a case.
 *
 * <p>This is the seam a real LLM agent replaces. It is deliberately the <em>only</em> thing that
 * has to be swapped: {@link InvestigationLoop} owns sequencing, state transitions, invariants and
 * the audit trail, and knows nothing about how a decision is reached.
 *
 * <p>Implementations must be pure with respect to the case: decide from what is there, do not
 * mutate it, do not call tools, do not advance state. The loop does all of that.
 */
public interface DecisionPolicy {

    /**
     * @param securityCase the case as it currently stands
     * @param world        the environment the tools will observe
     * @return the next decision, never {@code null}
     */
    AgentDecision decide(SecurityCase securityCase, SimulationWorld world);
}
