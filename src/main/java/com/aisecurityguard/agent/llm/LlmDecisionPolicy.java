package com.aisecurityguard.agent.llm;

import com.aisecurityguard.agent.CorrectionAwarePolicy;
import com.aisecurityguard.agent.DecisionPolicy;
import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.model.ModelClient;
import com.aisecurityguard.model.ModelMessage;
import com.aisecurityguard.model.ModelRequest;
import com.aisecurityguard.model.ModelResponse;
import com.aisecurityguard.model.ModelUnavailableException;
import com.aisecurityguard.tool.SimulationWorld;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

/**
 * The real agent: a language model decides the next step.
 *
 * <p>This is the production {@link DecisionPolicy}. It replaces
 * {@code ReferenceDecisionPolicy}, which is now the regression oracle rather than the agent.
 *
 * <p>The loop around it does not change. The model produces a decision; the runtime still owns
 * sequencing, grounding validation, confidence derivation, the approval gate, and the audit
 * trail. Everything the model is <em>not</em> trusted with is enforced outside this class.
 *
 * <p>Two behaviours are deliberate:
 * <ul>
 *   <li><b>It is a pure function of case state</b>, like the reference policy. It reads the case,
 *       asks the model, and returns a decision. It never mutates the case, never invokes a tool
 *       and never advances state.</li>
 *   <li><b>Failure degrades to escalation, never to a verdict.</b> If the model is unreachable or
 *       its reply is unusable, the case goes to a human. An agent that has failed to think has not
 *       concluded that the asset is safe.</li>
 * </ul>
 *
 * <p>Enabled by {@code aisecurityguard.agent.policy=llm}. The default remains the reference
 * policy so the test suite stays deterministic and offline.
 */
@Component
@ConditionalOnProperty(name = "aisecurityguard.agent.policy", havingValue = "llm")
public class LlmDecisionPolicy implements DecisionPolicy, CorrectionAwarePolicy {

    private static final Logger log = LoggerFactory.getLogger(LlmDecisionPolicy.class);

    /** Kept modest: a decision is a small JSON object, not an essay. */
    private static final int DECISION_MAX_TOKENS = 1200;

    private final ModelClient modelClient;
    private final CasePromptBuilder promptBuilder;
    private final AgentDecisionParser parser;

    public LlmDecisionPolicy(ModelClient modelClient,
                             CasePromptBuilder promptBuilder,
                             AgentDecisionParser parser) {
        this.modelClient = Objects.requireNonNull(modelClient);
        this.promptBuilder = Objects.requireNonNull(promptBuilder);
        this.parser = Objects.requireNonNull(parser);
    }

    @Override
    public AgentDecision decide(SecurityCase securityCase, SimulationWorld world) {
        return decideWithRefinements(securityCase, world, List.of());
    }

    @Override
    public AgentDecision decideRefined(SecurityCase securityCase, SimulationWorld world,
                                       List<String> refinements) {
        return decideWithRefinements(securityCase, world, refinements);
    }

    private AgentDecision decideWithRefinements(SecurityCase securityCase, SimulationWorld world,
                                                List<String> refinements) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");

        String casePrompt = promptBuilder.casePrompt(securityCase);
        if (!refinements.isEmpty()) {
            casePrompt = casePrompt + refinementNotice(refinements);
        }

        ModelRequest request = new ModelRequest(
                promptBuilder.systemPrompt(),
                List.of(ModelMessage.user(casePrompt)),
                ModelRequest.DECISION_TEMPERATURE,
                true,
                DECISION_MAX_TOKENS);

        ModelResponse response;
        try {
            response = modelClient.complete(request);
        } catch (ModelUnavailableException e) {
            log.warn("model unavailable for case {}; escalating to human review: {}",
                    securityCase.caseId(), e.getMessage());
            return DecisionRejectedException.escalateBecauseUnavailable(
                    securityCase, e.getMessage());
        }

        try {
            AgentDecision decision = parser.parse(securityCase, response);
            log.info("case {}: model decided {} ({} tokens)",
                    securityCase.caseId(), decision.decisionType(), response.totalTokens());
            return decision;
        } catch (DecisionRejectedException e) {
            log.warn("model reply for case {} was rejected; escalating to human review: {}",
                    securityCase.caseId(), e.getMessage());
            return DecisionRejectedException.escalateBecauseUnavailable(
                    securityCase, e.getMessage());
        }
    }

    /**
     * States the runtime's refusals in the user turn.
     *
     * <p>Phrased as a correction from the runtime rather than as a hint, because that is what it
     * is: the previous decision was not accepted, and repeating it will not work.
     */
    private String refinementNotice(List<String> refinements) {
        StringBuilder notice = new StringBuilder();
        notice.append("\n*** YOUR PREVIOUS DECISION WAS REFUSED BY THE RUNTIME ***\n");
        for (String refinement : refinements) {
            notice.append("  - ").append(refinement).append('\n');
        }
        notice.append("  Choose a different capability that supplies what is missing, or\n")
                .append("  ESCALATE. Repeating the refused decision will be refused again.\n")
                .append("***********************************************************\n");
        return notice.toString();
    }
}
