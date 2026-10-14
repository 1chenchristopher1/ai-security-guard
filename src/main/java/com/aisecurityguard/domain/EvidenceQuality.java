package com.aisecurityguard.domain;

import java.util.List;

/**
 * How well the evidence in a case supports an assessment.
 *
 * <p>This is the input to confidence derivation, computed from the evidence chain rather than
 * declared by the caller. It deliberately summarises <em>quality</em> only: whether the evidence
 * conflicts is a separate question, because a conflict does not make individual items unreliable -
 * it makes the whole conclusion unsupportable.
 *
 * @param itemCount               number of evidence items in the chain
 * @param highestReliability      the strongest reliability present, or {@code null} if empty
 * @param lowestReliability       the weakest reliability present, or {@code null} if empty
 * @param highestReliabilityCount how many items carry the strongest reliability
 * @param allHighReliability      true when every item is {@link EvidenceReliability#HIGH}
 * @param anyInconclusive         true when at least one item is
 *                                {@link EvidenceReliability#INCONCLUSIVE}
 * @param mediumReliabilityCount  how many items are {@link EvidenceReliability#MEDIUM}
 */
public record EvidenceQuality(
        int itemCount,
        EvidenceReliability highestReliability,
        EvidenceReliability lowestReliability,
        int highestReliabilityCount,
        boolean allHighReliability,
        boolean anyInconclusive,
        int mediumReliabilityCount) {

    // Reliabilities from strongest to weakest. Ordinal order is deliberately not relied upon,
    // so that reordering the enum can never silently invert a confidence calculation.
    private static final List<EvidenceReliability> BY_STRENGTH = List.of(
            EvidenceReliability.HIGH,
            EvidenceReliability.MEDIUM,
            EvidenceReliability.INCONCLUSIVE);

    public EvidenceQuality {
        if (itemCount < 0) {
            throw new IllegalArgumentException("evidence count must not be negative");
        }
    }

    /** An empty evidence chain. */
    public static EvidenceQuality ofEmpty() {
        return new EvidenceQuality(0, null, null, 0, false, false, 0);
    }

    /** Summarises the quality of a chain of evidence. */
    public static EvidenceQuality of(List<Evidence> evidence) {
        if (evidence == null || evidence.isEmpty()) {
            return ofEmpty();
        }

        EvidenceReliability highest = BY_STRENGTH.get(0);
        EvidenceReliability lowest = BY_STRENGTH.get(0);
        for (Evidence item : evidence) {
            if (BY_STRENGTH.indexOf(item.reliability()) < BY_STRENGTH.indexOf(highest)) {
                highest = item.reliability();
            }
            if (BY_STRENGTH.indexOf(item.reliability()) > BY_STRENGTH.indexOf(lowest)) {
                lowest = item.reliability();
            }
        }

        int highestCount = 0;
        int mediumCount = 0;
        boolean anyInconclusive = false;
        for (Evidence item : evidence) {
            if (item.reliability() == highest) {
                highestCount++;
            }
            if (item.reliability() == EvidenceReliability.MEDIUM) {
                mediumCount++;
            }
            if (item.reliability() == EvidenceReliability.INCONCLUSIVE) {
                anyInconclusive = true;
            }
        }

        return new EvidenceQuality(
                evidence.size(),
                highest,
                lowest,
                highestCount,
                highest == EvidenceReliability.HIGH && lowest == EvidenceReliability.HIGH,
                anyInconclusive,
                mediumCount);
    }

    /** True when the chain carries at least one item. */
    public boolean hasAnyEvidence() {
        return itemCount > 0;
    }
}
