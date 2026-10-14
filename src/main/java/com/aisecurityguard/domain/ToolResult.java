package com.aisecurityguard.domain;

import java.util.Map;
import java.util.Optional;

/**
 * The structured result of a single tool execution.
 *
 * <p>This is the interface future real tools (PF4J plugins, in the target architecture) must
 * implement, and it is the seam that lets Milestone 0 be simulated while later milestones are
 * real: simulated tools and real tools differ only in how {@code summary}, {@code evidence} and
 * {@code facts} are produced.
 *
 * <p>A result carries information for two different consumers at once:
 * <ul>
 *   <li>{@link #evidence()} - what the human and the audit trail see. The investigation loop
 *       converts it into an {@link Evidence} record, which is why it must always be present, even
 *       when the tool failed.</li>
 *   <li>{@link #facts()} - the machine-readable domain facts the decision policy reasons over,
 *       merged into {@link SecurityCase#facts()}.</li>
 * </ul>
 *
 * @param status   execution outcome
 * @param toolName name of the tool that produced this result
 * @param summary  one-line result string shown on the tool card
 * @param evidence evidence information to be appended to the case evidence chain
 * @param facts    structured domain facts to be merged into case facts
 * @param error    present only when the status is not {@link ToolStatus#SUCCESS}
 */
public record ToolResult(
        ToolStatus status,
        String toolName,
        String summary,
        EvidenceMetadata evidence,
        Map<String, Object> facts,
        ToolError error) {

    public ToolResult {
        if (status == null) {
            throw new IllegalArgumentException("tool status must not be null");
        }
        if (toolName == null || toolName.isBlank()) {
            throw new IllegalArgumentException("toolName must not be blank");
        }
        if (summary == null || summary.isBlank()) {
            throw new IllegalArgumentException("tool summary must not be blank");
        }
        if (evidence == null) {
            throw new IllegalArgumentException(
                    "a tool result must carry evidence information, even when the tool fails");
        }
        facts = facts == null ? Map.of() : Map.copyOf(facts);
        if (status == ToolStatus.SUCCESS && error != null) {
            throw new IllegalArgumentException("a successful tool result must not carry an error");
        }
        if (status != ToolStatus.SUCCESS && error == null) {
            throw new IllegalArgumentException(
                    "a " + status + " tool result must explain itself with an error");
        }
    }

    public Optional<ToolError> errorDetail() {
        return Optional.ofNullable(error);
    }

    public boolean isSuccess() {
        return status == ToolStatus.SUCCESS;
    }
}
