package com.aisecurityguard.agent.llm;

import com.aisecurityguard.agent.DecisionPolicy;
import com.aisecurityguard.agent.ReferenceDecisionPolicy;
import com.aisecurityguard.domain.AgentDecisionType;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.scenario.Scenarios;
import com.aisecurityguard.casefile.CaseManagementService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Switching the harness to the LLM policy must be a configuration change, nothing more.
 *
 * <p>This is the whole point of the {@code DecisionPolicy} seam: the same loop, the same tools,
 * the same approval gate and the same audit trail, with a different decider. It is also the test
 * that proves the application wires correctly in LLM mode on a machine with no API key - because
 * "the model is not configured" is a normal state that must degrade safely, not a startup crash.
 */
@SpringBootTest(properties = "aisecurityguard.agent.policy=llm")
@TestPropertySource(properties = "aisecurityguard.agent.policy=llm")
class LlmPolicyWiringTest {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private DecisionPolicy decisionPolicy;

    @Autowired
    private CaseManagementService caseManagement;

    @Test
    @DisplayName("the LLM policy is the active DecisionPolicy and the reference policy is absent")
    void llmPolicyIsSelected() {
        assertThat(decisionPolicy).isInstanceOf(LlmDecisionPolicy.class);
        assertThat(context.getBeansOfType(ReferenceDecisionPolicy.class))
                .as("exactly one policy must be registered, so the two can never disagree")
                .isEmpty();
    }

    @Test
    @DisplayName("the model layer assembles even with no API key configured")
    void modelLayerAssemblesWithoutKey() {
        assertThat(context.getBean(com.aisecurityguard.model.ModelClient.class)).isNotNull();
        assertThat(context.getBean(com.aisecurityguard.model.ModelProperties.class)).isNotNull();
    }

    @Test
    @DisplayName("with no key, an LLM run escalates to a human instead of concluding anything")
    void missingKeyEscalatesSafely() {
        // Whether or not a key happens to be set in the environment, this must never produce a
        // remediation, and if the model is unreachable it must escalate rather than give a verdict.
        var securityCase = caseManagement.investigate(
                Scenarios.notAffectedCase(),
                Scenarios.NEGATIVE_SCANNER_CLAIM,
                Scenarios.notAffectedWorld());

        assertThat(securityCase.lifecycle())
                .as("no model run may ever execute remediation")
                .isNotIn(CaseLifecycle.REMEDIATING, CaseLifecycle.VERIFYING, CaseLifecycle.RESOLVED);

        if (!context.getBean(com.aisecurityguard.model.ModelProperties.class).hasApiKey()) {
            assertThat(securityCase.lifecycle())
                    .as("without a key the agent cannot decide, so a human must")
                    .isEqualTo(CaseLifecycle.ESCALATED);
            assertThat(securityCase.assessment().findingStatus())
                    .as("a model that never ran has said nothing about the asset")
                    .isEqualTo(FindingStatus.UNDETERMINED);
            assertThat(securityCase.isAutomaticRemediationBlocked()).isTrue();
        } else {
            // A key is present, so the model actually reasoned. Whatever it concluded, it must be
            // a real decision and it must still respect the gate.
            assertThat(securityCase.assessment().findingStatus())
                    .isIn(FindingStatus.CONFIRMED_VULNERABLE, FindingStatus.NOT_AFFECTED,
                            FindingStatus.UNDETERMINED);
        }
    }

    @Test
    @DisplayName("the loop stops even when the decider is a model")
    void loopStillTerminates() {
        var securityCase = caseManagement.investigate(
                Scenarios.notAffectedCase(),
                Scenarios.NEGATIVE_SCANNER_CLAIM,
                Scenarios.notAffectedWorld());

        assertThat(securityCase.lifecycle().blocksFurtherInvestigation())
                .as("the loop must terminate on a terminal decision, not on a model being polite")
                .isTrue();
        assertThat(securityCase.decisions()).isNotEmpty();
        assertThat(securityCase.decisions().get(securityCase.decisions().size() - 1)
                .decisionType())
                .isIn(AgentDecisionType.ASSESS, AgentDecisionType.ESCALATE);
    }
}
