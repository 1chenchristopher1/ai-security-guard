package com.aisecurityguard;

import com.aisecurityguard.audit.AuditIntegrityReport;
import com.aisecurityguard.audit.InMemoryAuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.domain.AuditActors;
import com.aisecurityguard.domain.AuditEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The audit trail must be evidence, not just a log.
 *
 * <p>"Append-only" describes an intention. These tests establish the stronger property: that an
 * entry cannot be altered, dropped, reordered or moved between cases without the chain noticing.
 * A trail whose integrity cannot be checked does not support the claim that every decision is
 * traceable - it only supports the claim that every decision was written down.
 */
class AuditIntegrityTest {

    private static InMemoryAuditLog logWithThreeEvents() {
        InMemoryAuditLog log = new InMemoryAuditLog(new SimulationClock());
        log.append("CASE-A", AuditActors.SYSTEM, "CASE_OPENED", "opened");
        log.append("CASE-A", AuditActors.AI_AGENT, "AGENT_DECISION", "investigate");
        log.append("CASE-A", AuditActors.SECURITY_TOOL, "EVIDENCE_CREATED", "E-002");
        return log;
    }

    // ==================================================================
    // The intact case
    // ==================================================================

    @Nested
    @DisplayName("An untouched trail")
    class Intact {

        @Test
        @DisplayName("a freshly written trail verifies")
        void freshTrailVerifies() {
            AuditIntegrityReport report = logWithThreeEvents().verifyIntegrity();

            assertThat(report.isValid()).isTrue();
            assertThat(report.eventsChecked()).isEqualTo(3);
            assertThat(report.firstBrokenSequence()).isNull();
            assertThat(report.describe()).contains("intact");
        }

        @Test
        @DisplayName("an empty trail is trivially valid")
        void emptyTrailIsValid() {
            InMemoryAuditLog log = new InMemoryAuditLog(new SimulationClock());

            assertThat(log.verifyIntegrity().isValid()).isTrue();
            assertThat(log.verifyIntegrity().eventsChecked()).isZero();
        }

        @Test
        @DisplayName("the first entry links to the genesis hash")
        void firstEntryLinksToGenesis() {
            AuditEvent first = logWithThreeEvents().all().get(0);

            assertThat(first.previousHash()).isEqualTo(AuditEvent.GENESIS_HASH);
            assertThat(first.sequence()).isEqualTo(1);
            assertThat(first.linksTo(null)).isTrue();
        }

        @Test
        @DisplayName("every entry carries a 64-character SHA-256 hash")
        void hashesAreWellFormed() {
            for (AuditEvent event : logWithThreeEvents().all()) {
                assertThat(event.hash()).hasSize(64).matches("[0-9a-f]{64}");
                assertThat(event.isSelfConsistent()).isTrue();
            }
        }

        @Test
        @DisplayName("each entry links to its predecessor")
        void chainIsLinked() {
            List<AuditEvent> events = logWithThreeEvents().all();

            for (int i = 1; i < events.size(); i++) {
                assertThat(events.get(i).previousHash()).isEqualTo(events.get(i - 1).hash());
                assertThat(events.get(i).linksTo(events.get(i - 1))).isTrue();
            }
        }
    }

    // ==================================================================
    // Tampering
    // ==================================================================

    @Nested
    @DisplayName("A tampered trail")
    class Tampered {

        /** Replaces one entry, simulating an in-place edit by someone with write access. */
        private void replace(InMemoryAuditLog log, int index, AuditEvent replacement) {
            List<AuditEvent> events = new ArrayList<>(log.all());
            events.set(index, replacement);
            log.replaceEntriesForTest(events);
        }

        @Test
        @DisplayName("altering an entry's result is detected")
        void alteringAResultIsDetected() {
            InMemoryAuditLog log = logWithThreeEvents();
            AuditEvent original = log.all().get(1);

            // Rewrite history so the agent looks like it escalated when it actually investigated.
            // The forger keeps the stored hash, so only the entry's own content check can catch it.
            AuditEvent forged = new AuditEvent(
                    original.sequence(), original.timestamp(), original.actor(),
                    "AGENT_DECISION", "ESCALATE", original.caseId(),
                    original.previousHash(), original.hash());
            replace(log, 1, forged);

            AuditIntegrityReport report = log.verifyIntegrity();

            assertThat(report.isValid())
                    .as("an edited entry must not verify against its own hash")
                    .isFalse();
            assertThat(report.brokenSelfHashes())
                    .as("the edited entry's content no longer matches its recorded hash")
                    .containsExactly(2L);
            assertThat(report.firstBrokenSequence()).isEqualTo(2L);
            assertThat(report.describe()).contains("BROKEN");
        }

        @Test
        @DisplayName("altering an entry and recomputing its hash still leaves the chain broken")
        void recomputingOneHashDoesNotRepairTheChain() {
            InMemoryAuditLog log = logWithThreeEvents();
            AuditEvent original = log.all().get(1);

            // A more careful forger also fixes the entry's own hash. The entry is then internally
            // consistent, but its predecessor link and its successor's link to it both break,
            // because the hash it produced is not the one the chain was built on.
            AuditEvent forged = AuditEvent.append(
                    original.sequence(), original.timestamp(), original.actor(),
                    "AGENT_DECISION", "ESCALATE", original.caseId(),
                    log.all().get(0));
            replace(log, 1, forged);

            AuditIntegrityReport report = log.verifyIntegrity();

            assertThat(forged.isSelfConsistent())
                    .as("the forged entry is internally consistent")
                    .isTrue();
            assertThat(report.isValid())
                    .as("but the chain is still broken, because entry 3 links to the old hash")
                    .isFalse();
            assertThat(report.brokenLinks()).contains(3L);
        }

        @Test
        @DisplayName("deleting an entry is detected")
        void deletingAnEntryIsDetected() {
            InMemoryAuditLog log = logWithThreeEvents();
            List<AuditEvent> events = new ArrayList<>(log.all());
            events.remove(1);
            log.replaceEntriesForTest(events);

            AuditIntegrityReport report = log.verifyIntegrity();

            assertThat(report.isValid())
                    .as("a dropped entry leaves a sequence gap and a broken link")
                    .isFalse();
            assertThat(report.brokenLinks())
                    .as("the entry that followed the deleted one now links to a stale hash")
                    .containsExactly(3L);
            assertThat(report.firstBrokenSequence()).isEqualTo(3L);
        }

        @Test
        @DisplayName("reordering entries is detected")
        void reorderingEntriesIsDetected() {
            InMemoryAuditLog log = logWithThreeEvents();
            List<AuditEvent> events = new ArrayList<>(log.all());
            java.util.Collections.swap(events, 1, 2);
            log.replaceEntriesForTest(events);

            assertThat(log.verifyIntegrity().isValid()).isFalse();
        }

        @Test
        @DisplayName("moving an entry to another case is detected")
        void movingAnEntryToAnotherCaseIsDetected() {
            InMemoryAuditLog log = logWithThreeEvents();
            AuditEvent original = log.all().get(0);

            // Re-label the opening event as belonging to a different case, so a finding can be
            // presented as if it were opened elsewhere. The case id is inside the hash.
            AuditEvent forged = new AuditEvent(
                    original.sequence(), original.timestamp(), original.actor(),
                    original.eventType(), original.result(), "CASE-B",
                    original.previousHash(), original.hash());
            replace(log, 0, forged);

            assertThat(log.verifyIntegrity().isValid()).isFalse();
        }

        @Test
        @DisplayName("back-dating an entry is detected")
        void backDatingAnEntryIsDetected() {
            InMemoryAuditLog log = logWithThreeEvents();
            AuditEvent original = log.all().get(2);

            AuditEvent forged = new AuditEvent(
                    original.sequence(), LocalTime.of(3, 0, 0), original.actor(),
                    original.eventType(), original.result(), original.caseId(),
                    original.previousHash(), original.hash());
            replace(log, 2, forged);

            assertThat(log.verifyIntegrity().isValid())
                    .as("the timestamp is inside the hash, so it cannot be changed")
                    .isFalse();
        }

        @Test
        @DisplayName("appending a fabricated entry with a guessed link is detected")
        void fabricatedAppendIsDetected() {
            InMemoryAuditLog log = logWithThreeEvents();
            List<AuditEvent> events = new ArrayList<>(log.all());

            // Append an event that claims to follow the last one but was not produced by the log.
            AuditEvent fabricated = new AuditEvent(
                    4L, LocalTime.of(9, 12, 59), AuditActors.AI_AGENT,
                    "REMEDIATION_EXECUTED", "actually happened, honest",
                    "CASE-A", AuditEvent.GENESIS_HASH, AuditEvent.GENESIS_HASH);
            events.add(fabricated);
            log.replaceEntriesForTest(events);

            assertThat(log.verifyIntegrity().isValid())
                    .as("a hand-written entry cannot fake the link")
                    .isFalse();
        }
    }

    // ==================================================================
    // The guarantees the domain must keep
    // ==================================================================

    @Nested
    @DisplayName("Construction rules")
    class Construction {

        @Test
        @DisplayName("an event cannot be constructed without a hash")
        void hashIsRequired() {
            assertThatThrownBy(() -> new AuditEvent(
                    1L, LocalTime.NOON, AuditActors.SYSTEM, "TYPE", "result", "CASE",
                    AuditEvent.GENESIS_HASH, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("hash must not be blank");
        }

        @Test
        @DisplayName("an event cannot be constructed without a predecessor link")
        void previousHashIsRequired() {
            assertThatThrownBy(() -> new AuditEvent(
                    1L, LocalTime.NOON, AuditActors.SYSTEM, "TYPE", "result", "CASE",
                    "  ", "abc"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("previousHash must not be blank");
        }

        @Test
        @DisplayName("the hash is deterministic for the same content")
        void hashingIsDeterministic() {
            AuditEvent first = AuditEvent.append(1L, LocalTime.NOON, AuditActors.SYSTEM,
                    "TYPE", "result", "CASE", null);
            AuditEvent second = AuditEvent.append(1L, LocalTime.NOON, AuditActors.SYSTEM,
                    "TYPE", "result", "CASE", null);

            assertThat(first.hash()).isEqualTo(second.hash());
            assertThat(first.previousHash()).isEqualTo(AuditEvent.GENESIS_HASH);
        }

        @Test
        @DisplayName("different content produces different hashes")
        void differentContentHashesDiffer() {
            AuditEvent a = AuditEvent.append(1L, LocalTime.NOON, AuditActors.SYSTEM,
                    "TYPE", "result", "CASE", null);
            AuditEvent b = AuditEvent.append(1L, LocalTime.NOON, AuditActors.SYSTEM,
                    "TYPE", "different result", "CASE", null);

            assertThat(a.hash()).isNotEqualTo(b.hash());
        }

        @Test
        @DisplayName("field boundaries are hashed, so text cannot be moved between fields")
        void fieldBoundariesAreHashed() {
            // Without a separator, ("ab", "c") and ("a", "bc") would hash identically, letting an
            // attacker shift text between fields without changing the hash.
            AuditEvent a = AuditEvent.append(1L, LocalTime.NOON, AuditActors.SYSTEM,
                    "ab", "c", "CASE", null);
            AuditEvent b = AuditEvent.append(1L, LocalTime.NOON, AuditActors.SYSTEM,
                    "a", "bc", "CASE", null);

            assertThat(a.hash()).isNotEqualTo(b.hash());
        }

        @Test
        @DisplayName("changing the case id changes the hash")
        void caseIdIsHashed() {
            AuditEvent a = AuditEvent.append(1L, LocalTime.NOON, AuditActors.SYSTEM,
                    "TYPE", "result", "CASE-A", null);
            AuditEvent b = AuditEvent.append(1L, LocalTime.NOON, AuditActors.SYSTEM,
                    "TYPE", "result", "CASE-B", null);

            assertThat(a.hash()).isNotEqualTo(b.hash());
        }
    }

    // ==================================================================
    // The trail produced by a real workflow
    // ==================================================================

    @Test
    @DisplayName("a full workflow run produces a chain that verifies")
    void realWorkflowChainVerifies() {
        // A genuine case, driven through the real loop and tools, must leave a verifiable trail.
        // This is the test that matters: hashing that only works on hand-built events would be
        // worse than useless, because it would give false assurance about the real ones.
        var run = ScenarioHarness.confirmedVulnerable();
        AuditIntegrityReport report = run.auditLog().verifyIntegrity();

        assertThat(report.isValid())
                .as("a real case must produce a verifiable trail: %s", report.describe())
                .isTrue();
        assertThat(report.eventsChecked())
                .as("the positive scenario emits a substantial trail")
                .isGreaterThan(10);
    }

    @Test
    @DisplayName("trails from all three canonical scenarios verify independently")
    void allScenarioTrailsVerify() {
        for (var run : List.of(
                ScenarioHarness.confirmedVulnerable(),
                ScenarioHarness.notAffected(),
                ScenarioHarness.evidenceConflict())) {

            AuditIntegrityReport report = run.auditLog().verifyIntegrity();
            assertThat(report.isValid())
                    .as("%s: %s", run.securityCase().caseId(), report.describe())
                    .isTrue();
        }
    }
}
