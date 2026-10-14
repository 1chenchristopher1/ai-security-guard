package com.aisecurityguard.domain;

import java.util.Map;

/**
 * Evidence information produced by a tool: everything needed to turn a tool result into an
 * {@link Evidence} record.
 *
 * <p>Kept separate from the domain facts a tool returns (see {@link ToolResult#facts()}) so that
 * the evidence store never silently absorbs domain state, and so a later milestone can persist
 * evidence metadata - source, reliability, provenance - without persisting domain facts with it.
 *
 * @param type        evidence category, e.g. {@code Runtime Service Evidence}
 * @param source      where the evidence came from, e.g. {@code inspect_service} or {@code CISA KEV}
 * @param finding     the human-readable assertion this evidence supports
 * @param reliability how much this evidence can be trusted
 * @param facts       evidence-scoped detail (e.g. {@code {"runtimeVersion": "2.4.49"}})
 */
public record EvidenceMetadata(
        String type,
        String source,
        String finding,
        EvidenceReliability reliability,
        Map<String, Object> facts) {

    public EvidenceMetadata {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("evidence type must not be blank");
        }
        if (source == null || source.isBlank()) {
            throw new IllegalArgumentException("evidence source must not be blank");
        }
        if (finding == null || finding.isBlank()) {
            throw new IllegalArgumentException("evidence finding must not be blank");
        }
        if (reliability == null) {
            throw new IllegalArgumentException("evidence reliability must not be null");
        }
        facts = facts == null ? Map.of() : Map.copyOf(facts);
    }

    /** Evidence information carrying only evidence-scoped facts. */
    public static EvidenceMetadata of(String type, String source, String finding,
                                      EvidenceReliability reliability) {
        return new EvidenceMetadata(type, source, finding, reliability, Map.of());
    }
}
