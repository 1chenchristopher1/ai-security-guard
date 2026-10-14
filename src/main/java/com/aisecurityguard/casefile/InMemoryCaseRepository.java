package com.aisecurityguard.casefile;

import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.SimulationWorld;

import java.time.LocalTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * In-memory {@link CaseRepository}.
 *
 * <p>Enough to prove the workflow service no longer owns case state, and to let a case be loaded
 * and continued rather than only handled within one method call. A later milestone can persist the
 * same structure without changing the interface - which is the point of the interface existing.
 */
public class InMemoryCaseRepository implements CaseRepository {

    /**
     * Insertion-ordered, so {@link #all()} lists cases in the order they were first opened rather
     * than in hash order. Determinism matters here: a report or a test that enumerates cases should
     * not depend on the hash of a string.
     */
    private final Map<String, StoredCase> byCaseId = new LinkedHashMap<>();

    @Override
    public void save(SecurityCase securityCase, SimulationWorld observedWorld, LocalTime storedAt) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        Objects.requireNonNull(observedWorld, "observedWorld must not be null");
        Objects.requireNonNull(storedAt, "storedAt must not be null");

        byCaseId.put(securityCase.caseId(), new StoredCase(securityCase, observedWorld, storedAt));
    }

    @Override
    public Optional<StoredCase> find(String caseId) {
        return Optional.ofNullable(caseId == null ? null : byCaseId.get(caseId));
    }

    @Override
    public List<StoredCase> all() {
        return List.copyOf(byCaseId.values());
    }

    @Override
    public int size() {
        return byCaseId.size();
    }

    @Override
    public boolean contains(String caseId) {
        return caseId != null && byCaseId.containsKey(caseId);
    }

    @Override
    public void clear() {
        byCaseId.clear();
    }
}
