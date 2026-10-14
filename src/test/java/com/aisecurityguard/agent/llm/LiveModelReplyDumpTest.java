package com.aisecurityguard.agent.llm;

import com.aisecurityguard.agent.AssessmentService;
import com.aisecurityguard.agent.ConfidencePolicy;
import com.aisecurityguard.agent.ConflictResolver;
import com.aisecurityguard.agent.InvestigationLoop;
import com.aisecurityguard.audit.InMemoryAuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.model.DeepSeekModelClient;
import com.aisecurityguard.model.ModelProperties;
import com.aisecurityguard.model.ModelRequest;
import com.aisecurityguard.model.ModelResponse;
import com.aisecurityguard.model.ModelUnavailableException;
import com.aisecurityguard.scenario.Scenarios;
import com.aisecurityguard.tool.CheckServiceHealthTool;
import com.aisecurityguard.tool.GetAssetContextTool;
import com.aisecurityguard.tool.InspectServiceTool;
import com.aisecurityguard.tool.LookupKevTool;
import com.aisecurityguard.tool.ToolRegistry;
import com.aisecurityguard.tool.ValidateVulnerabilityTool;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.List;

/**
 * Diagnostic: dump the model's raw replies for the canonical scenarios.
 *
 * <p>Not an assertion. Prompt engineering needs the model's actual words, not a pass/fail signal -
 * "the reply was rejected" does not say what the model believed.
 *
 * <p>Costs real tokens. Run explicitly: {@code -Dtest=LiveModelReplyDumpTest}
 */
@EnabledIfEnvironmentVariable(named = "DEEPSEEK_API_KEY", matches = ".+")
class LiveModelReplyDumpTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ToolRegistry registry() {
        return ToolRegistry.of(
                new InspectServiceTool(),
                new LookupKevTool(),
                new GetAssetContextTool(),
                new ValidateVulnerabilityTool(),
                new CheckServiceHealthTool());
    }

    /** Logs every raw reply, then delegates to the real policy. */
    private static final class DumpingClient implements com.aisecurityguard.model.ModelClient {

        private final com.aisecurityguard.model.ModelClient delegate = new DeepSeekModelClient(
                ModelProperties.fromEnvironment(), MAPPER);
        private int call = 0;

        @Override
        public ModelResponse complete(ModelRequest request) {
            call++;
            ModelResponse response = delegate.complete(request);
            System.out.println();
            System.out.println("---------- RAW MODEL REPLY #" + call + " ----------");
            System.out.println(response.content());
            System.out.println("---------- END REPLY (" + response.totalTokens() + " tokens) ----------");
            return response;
        }
    }

    private void dump(String label, com.aisecurityguard.domain.SecurityCase securityCase,
                      String claim, com.aisecurityguard.tool.SimulationWorld world) {
        System.out.println();
        System.out.println("############################################################");
        System.out.println("### " + label + "   asset=" + securityCase.assetId()
                + "  scannerClaim=" + world.scannerClaimedVersion()
                + "  runtime=" + world.runtimeVersion());
        System.out.println("############################################################");

        ToolRegistry registry = registry();
        SimulationClock clock = new SimulationClock();
        InMemoryAuditLog auditLog = new InMemoryAuditLog(clock);
        ConflictResolver conflictResolver = new ConflictResolver();

        var policy = new LlmDecisionPolicy(new DumpingClient(),
                new CasePromptBuilder(registry),
                new AgentDecisionParser(registry, MAPPER));

        var loop = new InvestigationLoop(policy, registry, auditLog, clock,
                new AssessmentService(new ConfidencePolicy()), conflictResolver);

        var result = loop.investigate(securityCase, claim, world);

        System.out.println();
        System.out.println("### OUTCOME: lifecycle=" + result.lifecycle()
                + " status=" + result.assessment().findingStatus()
                + " priority=" + result.assessment().priority()
                + " confidence=" + result.assessment().confidence()
                + " action=" + result.assessment().proposedAction());
        System.out.println("### TOOLS: " + result.selectedToolSequence());
    }

    @Test
    @DisplayName("dump raw model replies for the three canonical scenarios")
    void dumpReplies() {
        dump("TEST 1 CONFIRMED_VULNERABLE", Scenarios.confirmedVulnerableCase(),
                Scenarios.POSITIVE_SCANNER_CLAIM, Scenarios.confirmedVulnerableWorld());
        dump("TEST 2 NOT_AFFECTED", Scenarios.notAffectedCase(),
                Scenarios.NEGATIVE_SCANNER_CLAIM, Scenarios.notAffectedWorld());
        dump("TEST 3 EVIDENCE_CONFLICT", Scenarios.evidenceConflictCase(),
                Scenarios.CONFLICT_SCANNER_CLAIM, Scenarios.evidenceConflictWorld());
    }
}
