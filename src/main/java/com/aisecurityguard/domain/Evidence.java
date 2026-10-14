package com.aisecurityguard.domain;

import java.time.LocalTime;

/**
 * One immutable, append-only item in a case's evidence chain.
 *
 * <p>Scanner findings, tool successes, tool failures and inconclusive validations are all
 * evidence. A failing tool produces evidence too - tool failure is never treated as proof that
 * the finding is false.
 *
 * <p>Evidence IDs are assigned by {@link SecurityCase} and follow the prototype's scheme:
 * {@code E-001}, {@code E-002}, ... derived from chain position, so the chain reads as an ordered
 * narrative and gaps are impossible.
 *
 * @param evidenceId assigned by the case, e.g. {@code E-001}
 * @param metadata   evidence type / source / finding / reliability / evidence-scoped facts
 * @param timestamp  when the evidence was collected (synthetic clock in Milestone 0)
 */
public record Evidence(
        String evidenceId,
        EvidenceMetadata metadata,
        java.time.LocalTime timestamp) {

    public Evidence {
        if (evidenceId == null || evidenceId.isBlank()) {
            throw new IllegalArgumentException("evidenceId must not be blank");
        }
        if (metadata == null) {
            throw new IllegalArgumentException("evidence metadata must not be null");
        }
        if (timestamp == null) {
            throw new IllegalArgumentException("evidence timestamp must not be null");
        }
    }

    /** The human-readable assertion this evidence supports. */
    public String finding() {
        return metadata.finding();
    }

    /** Convenience accessor for the evidence category. */
    public String type() {
        return metadata.type();
    }

    /** Convenience accessor for the evidence source. */
    public String source() {
        return metadata.source();
    }

    /** Convenience accessor for the evidence reliability. */
    public EvidenceReliability reliability() {
        return metadata.reliability();
    }
}
