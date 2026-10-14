package com.aisecurityguard.agent;

import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.SimulationWorld;

import java.util.List;

/**
 * A decision policy that can be told its last decision was refused, and why.
 *
 * <p>The runtime refuses certain verdicts outright - an assessment citing evidence that does not
 * exist, or a confirmed vulnerability that cannot be prioritised because the exploitation and
 * asset-context facts were never gathered. Refusing is right, but crashing is not, and silently
 * escalating wastes the agent's ability to fix its own mistake.
 *
 * <p>A policy implementing this can be handed the refusal and asked to decide again. A language
 * model can genuinely use that: it is told what is missing and chooses the capability that
 * supplies it, which is the behaviour an agent should have. The reference policy does not need it,
 * because its rules structurally cannot produce an unprioritisable confirmation.
 *
 * <p>This is an optional capability rather than part of {@link DecisionPolicy}, so a policy that
 * cannot self-correct is still a valid policy - the loop simply escalates instead.
 */
public interface CorrectionAwarePolicy {

    /**
     * Decides again, in the light of the runtime's refusal of the previous decision.
     *
     * @param securityCase the case, unchanged by the refusal
     * @param world        the environment the tools observe
     * @param refinements  one human-readable explanation per refusal, oldest first
     * @return a fresh decision, which may itself be refused again
     */
    AgentDecision decideRefined(SecurityCase securityCase, SimulationWorld world,
                                List<String> refinements);
}
