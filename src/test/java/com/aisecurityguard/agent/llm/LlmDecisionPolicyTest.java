package com.aisecurityguard.agent.llm;

import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.AgentDecisionType;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.model.FakeModelClient;
import com.aisecurityguard.model.ModelMessage;
import com.aisecurityguard.model.ModelRequest;
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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The LLM agent's contract.
 *
 * <p>The model's output is the most untrusted input in the system, so these tests are mostly
 * negative: they establish what the runtime refuses to accept. That matters more than the happy
 * path, because a model that is wrong must be caught by the runtime rather than by luck.
 */
class LlmDecisionPolicyTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ToolRegistry registry() {
        return ToolRegistry.of(
                new InspectServiceTool(),
                new LookupKevTool(),
                new GetAssetContextTool(),
                new ValidateVulnerabilityTool(),
                new CheckServiceHealthTool());
    }

    /** A case with only the scanner finding present, as the loop presents it on the first cycle. */
    private static SecurityCase freshCase() {
        SecurityCase securityCase = Scenarios.confirmedVulnerableCase();
        securityCase.appendEvidence(
                new com.aisecurityguard.domain.EvidenceMetadata(
                        "Scanner Finding", "Vulnerability Scanner",
                        "Scanner reports a potential vulnerability.",
                        com.aisecurityguard.domain.EvidenceReliability.MEDIUM, Map.of()),
                java.time.LocalTime.of(9, 12, 1));
        return securityCase;
    }

    private static LlmDecisionPolicy policyWith(FakeModelClient client, ToolRegistry registry) {
        return new LlmDecisionPolicy(client,
                new CasePromptBuilder(registry),
                new AgentDecisionParser(registry, MAPPER));
    }

    // ==================================================================

    @Nested
    @DisplayName("Deciding")
    class Deciding {

        @Test
        @DisplayName("a well-formed INVESTIGATE reply becomes a decision selecting that capability")
        void parsesInvestigate() {
            FakeModelClient client = new FakeModelClient().thenReply("""
                    {"decision":"INVESTIGATE",
                     "missingEvidence":["Actual runtime version"],
                     "rationale":"Scanner severity alone does not confirm the runtime version.",
                     "capability":"inspect_service"}
                    """);
            SecurityCase securityCase = freshCase();

            AgentDecision decision = policyWith(client, registry()).decide(
                    securityCase, Scenarios.confirmedVulnerableWorld());

            assertThat(decision.decisionType()).isEqualTo(AgentDecisionType.INVESTIGATE);
            assertThat(decision.selectedTool()).isEqualTo("inspect_service");
            assertThat(decision.missingEvidence()).containsExactly("Actual runtime version");
            assertThat(decision.toolArguments().target()).isEqualTo("customer-portal-prod-01");
        }

        @Test
        @DisplayName("a well-formed ASSESS reply becomes a decision with a draft assessment")
        void parsesAssess() {
            FakeModelClient client = new FakeModelClient().thenReply("""
                    {"decision":"ASSESS",
                     "rationale":"Runtime evidence confirms the affected version.",
                     "findingStatus":"CONFIRMED_VULNERABLE",
                     "proposedAction":"Upgrade Apache HTTP Server to a patched version.",
                     "actionImpact":"A2"}
                    """);
            SecurityCase securityCase = freshCase();

            AgentDecision decision = policyWith(client, registry()).decide(
                    securityCase, Scenarios.confirmedVulnerableWorld());

            assertThat(decision.decisionType()).isEqualTo(AgentDecisionType.ASSESS);
            assertThat(decision.selectedTool()).isNull();
            assertThat(decision.assessment().findingStatus())
                    .isEqualTo(FindingStatus.CONFIRMED_VULNERABLE);
            assertThat(decision.assessment().actionImpact()).isEqualTo(ActionImpact.A2);
            assertThat(decision.assessment().proposedAction()).isNotBlank();
        }

        @Test
        @DisplayName("an ESCALATE reply becomes an escalation carrying the unresolved gap")
        void parsesEscalate() {
            FakeModelClient client = new FakeModelClient().thenReply("""
                    {"decision":"ESCALATE",
                     "missingEvidence":["Reliable resolution of the version conflict"],
                     "rationale":"Conflicting evidence prevents a reliable automated assessment.",
                     "findingStatus":"UNDETERMINED"}
                    """);
            SecurityCase securityCase = freshCase();

            AgentDecision decision = policyWith(client, registry()).decide(
                    securityCase, Scenarios.evidenceConflictWorld());

            assertThat(decision.decisionType()).isEqualTo(AgentDecisionType.ESCALATE);
            assertThat(decision.missingEvidence())
                    .containsExactly("Reliable resolution of the version conflict");
            assertThat(decision.assessment().findingStatus()).isEqualTo(FindingStatus.UNDETERMINED);
            assertThat(decision.assessment().proposedAction()).isNull();
        }

        @Test
        @DisplayName("markdown fences around the JSON are tolerated")
        void toleratesCodeFences() {
            FakeModelClient client = new FakeModelClient().thenReply("""
                    ```json
                    {"decision":"INVESTIGATE","missingEvidence":["runtime version"],
                     "rationale":"Need the running version.","capability":"inspect_service"}
                    ```
                    """);

            AgentDecision decision = policyWith(client, registry()).decide(
                    freshCase(), Scenarios.confirmedVulnerableWorld());

            assertThat(decision.selectedTool()).isEqualTo("inspect_service");
        }

        @Test
        @DisplayName("deciding does not mutate the case")
        void decideIsPure() {
            FakeModelClient client = new FakeModelClient().thenReply("""
                    {"decision":"INVESTIGATE","missingEvidence":["runtime version"],
                     "rationale":"Need the running version.","capability":"inspect_service"}
                    """);
            SecurityCase securityCase = freshCase();
            int evidenceBefore = securityCase.evidenceCount();

            policyWith(client, registry()).decide(securityCase, Scenarios.confirmedVulnerableWorld());

            assertThat(securityCase.evidenceCount()).isEqualTo(evidenceBefore);
            assertThat(securityCase.decisions()).isEmpty();
            assertThat(securityCase.lifecycle())
                    .isEqualTo(com.aisecurityguard.domain.CaseLifecycle.INVESTIGATING);
        }
    }

    // ==================================================================

    @Nested
    @DisplayName("What the runtime refuses to accept")
    class Rejection {

        private AgentDecision decideWith(String reply) {
            FakeModelClient client = new FakeModelClient().thenReply(reply);
            return policyWith(client, registry()).decide(
                    freshCase(), Scenarios.confirmedVulnerableWorld());
        }

        private void assertEscalated(AgentDecision decision, String reasonFragment) {
            assertThat(decision.decisionType())
                    .as("an unusable reply must escalate, never conclude")
                    .isEqualTo(AgentDecisionType.ESCALATE);
            assertThat(decision.assessment().findingStatus())
                    .as("a failed agent has said nothing about the asset")
                    .isEqualTo(FindingStatus.UNDETERMINED);
            assertThat(decision.assessment().proposedAction())
                    .as("nothing may be proposed off the back of a failure")
                    .isNull();
            assertThat(decision.rationale()).contains(reasonFragment);
        }

        @Test
        @DisplayName("a reply that is not JSON escalates")
        void rejectsNonJson() {
            assertEscalated(decideWith("I think you should inspect the service."),
                    "not a single well-formed JSON object");
        }

        @Test
        @DisplayName("a reply that is JSON but not an object escalates")
        void rejectsNonObjectJson() {
            assertEscalated(decideWith("[1,2,3]"), "not a JSON object");
        }

        @Test
        @DisplayName("an unrecognised decision type escalates")
        void rejectsUnknownDecision() {
            assertEscalated(decideWith("""
                    {"decision":"REMEDIATE","rationale":"Just fix it.","findingStatus":"CONFIRMED_VULNERABLE"}
                    """), "unrecognised decision");
        }

        @Test
        @DisplayName("a decision with no rationale escalates")
        void rejectsMissingRationale() {
            assertEscalated(decideWith("""
                    {"decision":"INVESTIGATE","missingEvidence":["x"],"capability":"inspect_service"}
                    """), "no rationale");
        }

        @Test
        @DisplayName("a capability that does not exist escalates rather than being ignored")
        void rejectsHallucinatedCapability() {
            assertEscalated(decideWith("""
                    {"decision":"INVESTIGATE","missingEvidence":["runtime"],
                     "rationale":"Inspect the host.","capability":"run_nmap_scan"}
                    """), "not available");
        }

        @Test
        @DisplayName("a hallucinated shell capability is refused")
        void rejectsShellCapability() {
            assertEscalated(decideWith("""
                    {"decision":"INVESTIGATE","missingEvidence":["runtime"],
                     "rationale":"Run a command.","capability":"bash"}
                    """), "not available");
        }

        @Test
        @DisplayName("an INVESTIGATE with no missing evidence escalates")
        void rejectsInvestigateWithoutGap() {
            assertEscalated(decideWith("""
                    {"decision":"INVESTIGATE","rationale":"Look around.","capability":"inspect_service"}
                    """), "must state what evidence is missing");
        }

        @Test
        @DisplayName("an ASSESS with no finding status escalates")
        void rejectsAssessWithoutStatus() {
            assertEscalated(decideWith("""
                    {"decision":"ASSESS","rationale":"Looks bad."}
                    """), "must state findingStatus");
        }

        @Test
        @DisplayName("an A0 closure note may accompany a non-vulnerable finding")
        void allowsInformationalNoteOnNonVulnerableFinding() {
            // Recording a closure is bookkeeping, not a change to the target, so A0 is accepted.
            AgentDecision decision = decideWith("""
                    {"decision":"ASSESS","rationale":"Not affected.",
                     "findingStatus":"NOT_AFFECTED",
                     "proposedAction":"Close the finding and record the evidence.",
                     "actionImpact":"A0"}
                    """);

            assertThat(decision.decisionType()).isEqualTo(AgentDecisionType.ASSESS);
            assertThat(decision.assessment().findingStatus())
                    .isEqualTo(com.aisecurityguard.domain.FindingStatus.NOT_AFFECTED);
            assertThat(decision.assessment().actionImpact())
                    .isEqualTo(com.aisecurityguard.domain.ActionImpact.A0);
            assertThat(decision.assessment().requiresHumanApproval())
                    .as("an informational note needs no approval")
                    .isFalse();
        }

        @Test
        @DisplayName("a consequential action on a non-vulnerable finding is refused")
        void rejectsConsequentialActionOnNonVulnerableFinding() {
            // This is the case that matters: an agent must not obtain permission to change a
            // machine it has just said is unaffected.
            assertEscalated(decideWith("""
                    {"decision":"ASSESS","rationale":"Not affected, but upgrade anyway.",
                     "findingStatus":"NOT_AFFECTED",
                     "proposedAction":"Upgrade Apache HTTP Server.","actionImpact":"A2"}
                    """), "only an informational A0 note may accompany");
        }

        @Test
        @DisplayName("an action proposed without an impact still escalates")
        void rejectsActionOnNonVulnerableFindingWithoutImpact() {
            assertEscalated(decideWith("""
                    {"decision":"ASSESS","rationale":"Not affected.",
                     "findingStatus":"NOT_AFFECTED",
                     "proposedAction":"Close the finding."}
                    """), "only an informational A0 note may accompany");
        }

        @Test
        @DisplayName("an action without an impact escalates, so impact cannot be guessed")
        void rejectsActionWithoutImpact() {
            assertEscalated(decideWith("""
                    {"decision":"ASSESS","rationale":"Confirmed.",
                     "findingStatus":"CONFIRMED_VULNERABLE",
                     "proposedAction":"Upgrade Apache HTTP Server."}
                    """), "must come with an actionImpact");
        }

        @Test
        @DisplayName("a truncated reply escalates, because its JSON is incomplete")
        void rejectsTruncatedReply() {
            FakeModelClient client = new FakeModelClient().thenReply(
                    new com.aisecurityguard.model.ModelResponse(
                            "{\"decision\":\"INVESTI", "fake-model", 10, "length"));

            AgentDecision decision = policyWith(client, registry()).decide(
                    freshCase(), Scenarios.confirmedVulnerableWorld());

            assertEscalated(decision, "truncated");
        }

        @Test
        @DisplayName("an unreachable model escalates instead of concluding anything")
        void modelUnavailableEscalates() {
            FakeModelClient client = new FakeModelClient().thenFail(
                    new ModelUnavailableException("no API key configured"));

            AgentDecision decision = policyWith(client, registry()).decide(
                    freshCase(), Scenarios.confirmedVulnerableWorld());

            assertEscalated(decision, "could not produce a decision");
        }
    }

    // ==================================================================

    @Nested
    @DisplayName("What the model is not trusted with")
    class UntrustedValues {

        @Test
        @DisplayName("priority and confidence supplied by the model are discarded")
        void priorityAndConfidenceAreIgnored() {
            FakeModelClient client = new FakeModelClient().thenReply("""
                    {"decision":"ASSESS","rationale":"Confirmed.",
                     "findingStatus":"CONFIRMED_VULNERABLE",
                     "priority":"P5","confidence":"C0",
                     "proposedAction":"Upgrade Apache HTTP Server.","actionImpact":"A2"}
                    """);

            AgentDecision decision = policyWith(client, registry()).decide(
                    freshCase(), Scenarios.confirmedVulnerableWorld());

            // Priority is not read from the model at all...
            assertThat(decision.assessment().priority()).isNull();
            // ...and confidence is a placeholder that AssessmentService overwrites.
            assertThat(decision.assessment().confidence())
                    .as("a model must not be able to declare its own certainty")
                    .isEqualTo(com.aisecurityguard.domain.Confidence.C4);
        }

        @Test
        @DisplayName("observed evidence is taken from the case, not from the model")
        void observedEvidenceComesFromTheCase() {
            FakeModelClient client = new FakeModelClient().thenReply("""
                    {"decision":"ASSESS","rationale":"Confirmed.",
                     "findingStatus":"CONFIRMED_VULNERABLE",
                     "observedEvidenceIds":["E-999","E-998"],
                     "proposedAction":"Upgrade Apache HTTP Server.","actionImpact":"A2"}
                    """);
            SecurityCase securityCase = freshCase();

            AgentDecision decision = policyWith(client, registry()).decide(
                    securityCase, Scenarios.confirmedVulnerableWorld());

            assertThat(decision.observedEvidenceIds())
                    .as("a model must not be able to claim it considered evidence that "
                            + "does not exist")
                    .containsExactly("E-001")
                    .doesNotContain("E-999");
        }

        @Test
        @DisplayName("a model cannot widen its own capability set")
        void capabilityListCannotBeWidened() {
            ToolRegistry registry = registry();
            CasePromptBuilder builder = new CasePromptBuilder(registry);

            assertThat(builder.advertisedCapabilities())
                    .isEqualTo(registry.toolNames())
                    .doesNotContain("execute_remediation", "bash", "write_file");
            assertThat(builder.systemPrompt())
                    .as("the prompt must only ever name granted capabilities")
                    .doesNotContain("execute_remediation")
                    .contains("inspect_service");
        }
    }

    // ==================================================================

    @Nested
    @DisplayName("The prompt")
    class Prompt {

        @Test
        @DisplayName("the case facts and evidence are actually given to the model")
        void promptCarriesTheCase() {
            FakeModelClient client = new FakeModelClient().thenReply("""
                    {"decision":"INVESTIGATE","missingEvidence":["exploitation status"],
                     "rationale":"Need intelligence.","capability":"lookup_kev"}
                    """);
            SecurityCase securityCase = freshCase();
            securityCase.facts().merge(Map.of("runtimeVersion", "2.4.49"));

            policyWith(client, registry()).decide(securityCase, Scenarios.confirmedVulnerableWorld());

            String userTurn = client.lastRequest().messages().stream()
                    .filter(m -> m.role() == ModelMessage.Role.USER)
                    .map(ModelMessage::content)
                    .findFirst()
                    .orElseThrow();

            assertThat(userTurn).contains("CASE-VUL-001")
                    .contains("customer-portal-prod-01")
                    .contains("CVE-2021-41773")
                    .contains("runtimeVersion = 2.4.49")
                    .contains("E-001");
        }

        @Test
        @DisplayName("every request asks for a JSON object at zero temperature")
        void requestsAreDeterministicAndStructured() {
            FakeModelClient client = new FakeModelClient().thenReply("""
                    {"decision":"INVESTIGATE","missingEvidence":["x"],
                     "rationale":"r","capability":"inspect_service"}
                    """);

            policyWith(client, registry()).decide(
                    freshCase(), Scenarios.confirmedVulnerableWorld());

            ModelRequest request = client.lastRequest();
            assertThat(request.jsonResponse()).isTrue();
            assertThat(request.temperature()).isZero();
            assertThat(request.systemPrompt()).contains("scanner finding is not a confirmed");
        }
    }
}
