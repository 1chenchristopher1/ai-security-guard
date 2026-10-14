package com.aisecurityguard.audit;

import com.aisecurityguard.domain.AuditEvent;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * In-memory, append-only, hash-chained {@link AuditLog}.
 *
 * <p>Storing events in a list is enough for this milestone: the point is to prove the workflow
 * emits the right events in the right order, and that the resulting trail is verifiable. A later
 * milestone can persist the same structure without changing the interface.
 */
public class InMemoryAuditLog implements AuditLog {

    private final SimulationClock clock;
    private final List<AuditEvent> events = new ArrayList<>();

    public InMemoryAuditLog(SimulationClock clock) {
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public AuditEvent append(String caseId, String actor, String eventType, String result) {
        long sequence = events.size() + 1L;
        AuditEvent previous = events.isEmpty() ? null : events.get(events.size() - 1);

        AuditEvent event = AuditEvent.append(
                sequence, clock.tick(), actor, eventType, result, caseId, previous);

        events.add(event);
        return event;
    }

    @Override
    public List<AuditEvent> all() {
        return List.copyOf(events);
    }

    @Override
    public List<AuditEvent> forCase(String caseId) {
        return events.stream()
                .filter(e -> e.caseId().equals(caseId))
                .sorted(Comparator.comparingLong(AuditEvent::sequence))
                .toList();
    }

    @Override
    public int size() {
        return events.size();
    }

    @Override
    public AuditIntegrityReport verifyIntegrity() {
        List<Long> brokenSelfHashes = new ArrayList<>();
        List<Long> brokenLinks = new ArrayList<>();
        Long firstBroken = null;

        for (int i = 0; i < events.size(); i++) {
            AuditEvent event = events.get(i);
            AuditEvent predecessor = i == 0 ? null : events.get(i - 1);

            if (!event.isSelfConsistent()) {
                brokenSelfHashes.add(event.sequence());
                if (firstBroken == null) {
                    firstBroken = event.sequence();
                }
            }
            if (!event.linksTo(predecessor)) {
                brokenLinks.add(event.sequence());
                if (firstBroken == null) {
                    firstBroken = event.sequence();
                }
            }
        }

        return new AuditIntegrityReport(events.size(), brokenSelfHashes, brokenLinks, firstBroken);
    }

    /**
     * Replaces the stored entries wholesale.
     *
     * <p><b>Test seam.</b> The point of hash chaining is to detect an edit made by someone with
     * write access to the storage, so the only honest way to test it is to actually perform such an
     * edit. This method is that capability, and it exists nowhere in the production API surface:
     * there is deliberately no update or delete on {@link AuditLog}.
     *
     * <p>It is named for what it is so that it cannot be mistaken for a supported operation, and it
     * is the only mutator on this class.
     */
    public void replaceEntriesForTest(List<AuditEvent> tampered) {
        Objects.requireNonNull(tampered, "tampered entries must not be null");
        events.clear();
        events.addAll(tampered);
    }
}
