package com.aisecurityguard.domain;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Structured, machine-readable facts about a case, merged from tool results.
 *
 * <p>This is the agent's working memory and is deliberately distinct from the evidence chain:
 * evidence is the human-readable justification, facts are what the decision policy reasons over.
 * The prototype keeps the same split ({@code c.evidence} vs {@code c.facts}).
 *
 * <p>Facts are only ever added; a fact is never overwritten with a different value, because that
 * would mean two sources disagreed and the disagreement was silently discarded.
 */
public final class CaseFacts {

    private final Map<String, Object> values;

    public CaseFacts() {
        this.values = new java.util.LinkedHashMap<>();
    }

    private CaseFacts(Map<String, Object> values) {
        this.values = values;
    }

    /** An empty facts set. */
    public static CaseFacts empty() {
        return new CaseFacts();
    }

    /**
     * Merges facts produced by a tool result.
     *
     * @throws IllegalStateException if a key is already present with a different value, which
     *                               means the case contains conflicting facts and must not be
     *                               silently continued
     */
    public void merge(Map<String, Object> incoming) {
        if (incoming == null || incoming.isEmpty()) {
            return;
        }
        incoming.forEach((key, value) -> {
            Object existing = values.get(key);
            if (existing != null && !Objects.equals(existing, value)) {
                throw new IllegalStateException(
                        "conflicting case facts for key '" + key + "': '" + existing
                                + "' vs '" + value + "'. Conflicting facts must be escalated, "
                                + "not overwritten.");
            }
            values.put(key, value);
        });
    }

    public Optional<Object> get(String key) {
        return Optional.ofNullable(values.get(key));
    }

    public Optional<String> getString(String key) {
        return get(key).map(String::valueOf);
    }

    public boolean has(String key) {
        return values.containsKey(key);
    }

    @SuppressWarnings("unchecked")
    public Optional<Map<String, Object>> getMap(String key) {
        return get(key).filter(Map.class::isInstance).map(v -> (Map<String, Object>) v);
    }

    public Set<String> keys() {
        return Set.copyOf(values.keySet());
    }

    /** Immutable snapshot, in insertion order. */
    public Map<String, Object> asMap() {
        return Map.copyOf(values);
    }

    @Override
    public String toString() {
        return "CaseFacts" + values;
    }
}
