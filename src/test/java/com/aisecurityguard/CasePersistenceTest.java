package com.aisecurityguard;

import com.aisecurityguard.casefile.CaseRepository;
import com.aisecurityguard.casefile.InMemoryCaseRepository;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.scenario.Scenarios;
import com.aisecurityguard.tool.SimulationWorld;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Case storage.
 *
 * <p>Before this existed, the workflow service kept case state in a private map. That worked only
 * because nothing restarted, and it left the observed environment stranded in the orchestration
 * layer - an environment is not the orchestrator's business, but it <em>is</em> part of what was
 * investigated, so it belongs with the case.
 *
 * <p>What matters here is not that a map works. It is that a case can be <b>loaded and continued</b>
 * rather than only handled inside one method call, and that the recorded environment is retained
 * unchanged as evidence.
 */
class CasePersistenceTest {

    private static SimulationWorld world() {
        return Scenarios.confirmedVulnerableWorld();
    }

    // ==================================================================
    // The repository
    // ==================================================================

    @Nested
    @DisplayName("InMemoryCaseRepository")
    class Repository {

        private final CaseRepository repository = new InMemoryCaseRepository();

        @Test
        @DisplayName("an empty repository is empty, not broken")
        void emptyRepository() {
            assertThat(repository.size()).isZero();
            assertThat(repository.all()).isEmpty();
            assertThat(repository.find("CASE-NONE")).isEmpty();
            assertThat(repository.contains("CASE-NONE")).isFalse();
        }

        @Test
        @DisplayName("a saved case can be found by id")
        void saveThenFind() {
            SecurityCase securityCase = Scenarios.confirmedVulnerableCase();
            repository.save(securityCase, world(), LocalTime.NOON);

            assertThat(repository.contains("CASE-VUL-001")).isTrue();
            assertThat(repository.find("CASE-VUL-001")).isPresent()
                    .get()
                    .satisfies(stored -> {
                        assertThat(stored.securityCase().caseId()).isEqualTo("CASE-VUL-001");
                        assertThat(stored.securityCase().assetId())
                                .isEqualTo("customer-portal-prod-01");
                        assertThat(stored.observedWorld().runtimeVersion()).isEqualTo("2.4.49");
                        assertThat(stored.storedAt()).isEqualTo(LocalTime.NOON);
                    });
        }

        @Test
        @DisplayName("saving the same case again replaces it rather than duplicating it")
        void saveReplaces() {
            SecurityCase securityCase = Scenarios.confirmedVulnerableCase();
            repository.save(securityCase, world(), LocalTime.NOON);
            repository.save(securityCase, world().withRuntimeVersion("2.4.58"), LocalTime.MIDNIGHT);

            assertThat(repository.size()).isEqualTo(1);
            assertThat(repository.find("CASE-VUL-001").orElseThrow().observedWorld().runtimeVersion())
                    .as("the replacement is a new record, not a mutated one")
                    .isEqualTo("2.4.58");
        }

        @Test
        @DisplayName("cases are listed in the order they were first opened")
        void listingIsDeterministic() {
            SecurityCase first = Scenarios.confirmedVulnerableCase();
            SecurityCase second = Scenarios.notAffectedCase();
            SecurityCase third = Scenarios.evidenceConflictCase();

            repository.save(third, world(), LocalTime.NOON);
            repository.save(first, world(), LocalTime.NOON);
            repository.save(second, world(), LocalTime.NOON);

            assertThat(repository.all()).extracting(s -> s.securityCase().caseId())
                    .as("insertion order, not hash order: a report must not depend on String.hashCode")
                    .containsExactly("CASE-VUL-003", "CASE-VUL-001", "CASE-VUL-002");
        }

        @Test
        @DisplayName("a null case id is absent rather than an error")
        void nullCaseIdIsAbsent() {
            assertThat(repository.find(null)).isEmpty();
            assertThat(repository.contains(null)).isFalse();
        }

        @Test
        @DisplayName("saving nothing is rejected")
        void saveRequiresArguments() {
            SecurityCase securityCase = Scenarios.confirmedVulnerableCase();

            assertThatThrownBy(() -> repository.save(null, world(), LocalTime.NOON))
                    .isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> repository.save(securityCase, null, LocalTime.NOON))
                    .isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> repository.save(securityCase, world(), null))
                    .isInstanceOf(NullPointerException.class);
        }
    }

    // ==================================================================
    // The workflow service
    // ==================================================================

    @Nested
    @DisplayName("CaseManagementService persistence")
    class WorkflowService {

        @Test
        @DisplayName("an investigated case is stored and can be loaded afterwards")
        void investigatedCaseIsStored() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();

            assertThat(run.caseManagement().load("CASE-VUL-001"))
                    .as("a case must survive the call that created it")
                    .isPresent();
            assertThat(run.caseManagement().allCases()).hasSize(1);
        }

        @Test
        @DisplayName("a loaded case carries its evidence, assessment and lifecycle")
        void loadedCaseIsComplete() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();

            SecurityCase loaded = run.caseManagement().load("CASE-VUL-001").orElseThrow();

            assertThat(loaded.lifecycle()).isEqualTo(CaseLifecycle.ASSESSED);
            assertThat(loaded.evidenceIds()).containsExactly("E-001", "E-002", "E-003", "E-004");
            assertThat(loaded.assessment().findingStatus())
                    .isEqualTo(com.aisecurityguard.domain.FindingStatus.CONFIRMED_VULNERABLE);
            assertThat(loaded.selectedToolSequence())
                    .containsExactly("inspect_service", "lookup_kev", "get_asset_context");
        }

        @Test
        @DisplayName("an unknown case id loads as absent, not as an error")
        void unknownCaseIsAbsent() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();

            assertThat(run.caseManagement().load("CASE-DOES-NOT-EXIST")).isEmpty();
        }

        @Test
        @DisplayName("the environment a case was investigated against is retained")
        void observedWorldIsRetained() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();

            assertThat(run.caseManagement().observedWorldFor(run.securityCase()))
                    .isPresent()
                    .get()
                    .satisfies(world -> assertThat(world.runtimeVersion()).isEqualTo("2.4.49"));
        }

        @Test
        @DisplayName("remediating a case that was never investigated fails with a clear reason")
        void remediatingUnknownCaseFailsClearly() {
            ScenarioHarness.LifecycleRun run = ScenarioHarness.positiveAwaitingApproval();
            run.caseManagement().decide(run.securityCase(),
                    com.aisecurityguard.domain.ApprovalRequest.approvedBy(
                            "CASE-VUL-001", "analyst.chris", run.clock().tick()));
            var token = run.caseManagement().tokenFor(run.securityCase()).orElseThrow();

            // A different case object with the same shape but no stored environment: the service
            // must refuse rather than guess what it was supposed to change.
            SecurityCase stranger = new SecurityCase("CASE-STRANGER", "asset-x", "CVE-2021-41773");

            assertThatThrownBy(() ->
                    run.caseManagement().remediateAndVerify(stranger, token))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("cannot authorise execution on case");
        }

        @Test
        @DisplayName("all three canonical cases are stored under their own ids")
        void allCasesAreStored() {
            SimulationClockHolder holder = new SimulationClockHolder();

            holder.investigate(Scenarios.confirmedVulnerableCase(),
                    Scenarios.POSITIVE_SCANNER_CLAIM, Scenarios.confirmedVulnerableWorld());
            holder.investigate(Scenarios.notAffectedCase(),
                    Scenarios.NEGATIVE_SCANNER_CLAIM, Scenarios.notAffectedWorld());
            holder.investigate(Scenarios.evidenceConflictCase(),
                    Scenarios.CONFLICT_SCANNER_CLAIM, Scenarios.evidenceConflictWorld());

            assertThat(holder.service().allCases()).extracting(SecurityCase::caseId)
                    .containsExactly("CASE-VUL-001", "CASE-VUL-002", "CASE-VUL-003");
        }

        /** A service wired to its own repository, so cases accumulate across investigations. */
        private static final class SimulationClockHolder {

            private final com.aisecurityguard.casefile.CaseManagementService service;
            private final com.aisecurityguard.audit.SimulationClock clock =
                    new com.aisecurityguard.audit.SimulationClock();

            SimulationClockHolder() {
                var auditLog = new com.aisecurityguard.audit.InMemoryAuditLog(clock);
                var registry = com.aisecurityguard.tool.ToolRegistry.of(
                        new com.aisecurityguard.tool.InspectServiceTool(),
                        new com.aisecurityguard.tool.LookupKevTool(),
                        new com.aisecurityguard.tool.GetAssetContextTool(),
                        new com.aisecurityguard.tool.ValidateVulnerabilityTool(),
                        new com.aisecurityguard.tool.CheckServiceHealthTool());
                var conflictResolver = new com.aisecurityguard.agent.ConflictResolver();
                var loop = new com.aisecurityguard.agent.InvestigationLoop(
                        new com.aisecurityguard.agent.ReferenceDecisionPolicy(
                                registry, new com.aisecurityguard.agent.PriorityPolicy(),
                                conflictResolver),
                        registry, auditLog, clock,
                        new com.aisecurityguard.agent.AssessmentService(
                                new com.aisecurityguard.agent.ConfidencePolicy()),
                        conflictResolver);

                service = new com.aisecurityguard.casefile.CaseManagementService(
                        loop,
                        new com.aisecurityguard.approval.DefaultApprovalGate(auditLog),
                        new com.aisecurityguard.remediation.ControlledRemediationExecutor(
                                new com.aisecurityguard.remediation.RemediationActionCatalog(),
                                auditLog, clock),
                        new com.aisecurityguard.verification.ToolBasedRemediationVerifier(
                                registry, auditLog, clock),
                        conflictResolver,
                        new InMemoryCaseRepository(),
                        auditLog,
                        clock);
            }

            com.aisecurityguard.casefile.CaseManagementService service() {
                return service;
            }

            void investigate(SecurityCase securityCase, String claim, SimulationWorld world) {
                service.investigate(securityCase, claim, world);
            }
        }
    }
}
