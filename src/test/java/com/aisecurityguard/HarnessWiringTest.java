package com.aisecurityguard;

import com.aisecurityguard.agent.DecisionPolicy;
import com.aisecurityguard.agent.InvestigationLoop;
import com.aisecurityguard.agent.ReferenceDecisionPolicy;
import com.aisecurityguard.audit.AuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.scenario.Scenarios;
import com.aisecurityguard.tool.ToolRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the Spring wiring actually assembles the harness, so the milestone is a running
 * application and not just a set of classes that happen to compile.
 *
 * <p>This is also the end-to-end proof: the whole workflow is driven through the Spring-managed
 * beans rather than through hand-constructed objects.
 */
@SpringBootTest
class HarnessWiringTest {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private DecisionPolicy decisionPolicy;

    @Autowired
    private ToolRegistry toolRegistry;

    @Autowired
    private InvestigationLoop investigationLoop;

    @Autowired
    private AuditLog auditLog;

    @Autowired
    private SimulationClock clock;

    @Test
    @DisplayName("the harness assembles from the application context")
    void contextLoads() {
        assertThat(context).isNotNull();
        assertThat(decisionPolicy).isInstanceOf(ReferenceDecisionPolicy.class);
        assertThat(investigationLoop).isNotNull();
        assertThat(auditLog).isNotNull();
        assertThat(clock).isNotNull();
    }

    @Test
    @DisplayName("all tools are discovered as components")
    void allToolsAreDiscovered() {
        // The investigation capabilities plus the service-health check used by verification.
        assertThat(toolRegistry.toolNames()).containsExactlyInAnyOrder(
                "inspect_service", "lookup_kev", "get_asset_context", "validate_vulnerability",
                "check_service_health");
    }

    @Test
    @DisplayName("the case workflow beans are wired for the UI layer")
    void caseWorkflowBeansAreWired() {
        assertThat(context.getBean(com.aisecurityguard.casefile.CaseManagementService.class))
                .isNotNull();
        assertThat(context.getBean(com.aisecurityguard.approval.ApprovalGate.class)).isNotNull();
        assertThat(context.getBean(com.aisecurityguard.remediation.RemediationExecutor.class))
                .isNotNull();
        assertThat(context.getBean(com.aisecurityguard.verification.RemediationVerifier.class))
                .isNotNull();
    }

    @Test
    @DisplayName("the full confirmed-vulnerable scenario runs through Spring-managed beans")
    void endToEndThroughSpring() {
        var securityCase = Scenarios.confirmedVulnerableCase();

        investigationLoop.investigate(securityCase, Scenarios.POSITIVE_SCANNER_CLAIM,
                Scenarios.confirmedVulnerableWorld());

        assertThat(securityCase.selectedToolSequence()).containsExactly(
                "inspect_service", "lookup_kev", "get_asset_context");
        assertThat(securityCase.assessment().findingStatus())
                .isEqualTo(com.aisecurityguard.domain.FindingStatus.CONFIRMED_VULNERABLE);
        assertThat(securityCase.assessment().priority())
                .isEqualTo(com.aisecurityguard.domain.Priority.P0);
        assertThat(auditLog.forCase("CASE-VUL-001")).isNotEmpty();
    }
}
