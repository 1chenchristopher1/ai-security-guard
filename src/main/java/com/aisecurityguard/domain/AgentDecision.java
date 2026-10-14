package com.aisecurityguard.domain;

import java.util.List;
import java.util.Optional;

/**
 * A single agent decision, recorded with everything needed to justify it.
 *
 * <p>Every decision - whether it investigates, assesses or escalates - carries the same four
 * things, which is what makes the workflow auditable:
 * <ol>
 *   <li>{@link #observedEvidenceIds()} - the evidence the agent actually saw</li>
 *   <li>{@link #missingEvidence()} - the evidence it judged to be missing</li>
 *   <li>{@link #rationale()} - a concise explainable summary of why</li>
 *   <li>{@link #selectedTool()} - which capability it chose next, if any</li>
 * </ol>
 *
 * <p>{@link #rationale()} is an explainable summary, not hidden chain of thought.
 *
 * @param decisionType        INVESTIGATE, ASSESS or ESCALATE
 * @param observedEvidenceIds evidence IDs present in the case when this decision was made
 * @param missingEvidence     human-readable description of the evidence gaps identified
 * @param rationale           concise justification
 * @param selectedTool        the tool chosen next, or {@code null} for ASSESS / ESCALATE
 * @param toolArguments       arguments for the selected tool, or {@code null}
 * @param assessment          the assessment, present for ASSESS and for a reasoned ESCALATE
 */
public record AgentDecision(
        AgentDecisionType decisionType,
        List<String> observedEvidenceIds,
        List<String> missingEvidence,
        String rationale,
        String selectedTool,
        ToolArguments toolArguments,
        Assessment assessment) {

    public AgentDecision {
        if (decisionType == null) {
            throw new IllegalArgumentException("decisionType must not be null");
        }
        if (rationale == null || rationale.isBlank()) {
            throw new IllegalArgumentException("decision rationale must not be blank");
        }
        observedEvidenceIds = observedEvidenceIds == null
                ? List.of()
                : List.copyOf(observedEvidenceIds);
        missingEvidence = missingEvidence == null ? List.of() : List.copyOf(missingEvidence);

        if (decisionType == AgentDecisionType.INVESTIGATE) {
            if (selectedTool == null || selectedTool.isBlank()) {
                throw new IllegalArgumentException("an INVESTIGATE decision must select a tool");
            }
            if (toolArguments == null) {
                throw new IllegalArgumentException("an INVESTIGATE decision must supply tool arguments");
            }
            if (missingEvidence.isEmpty()) {
                throw new IllegalArgumentException(
                        "an INVESTIGATE decision must state what evidence is missing");
            }
            if (assessment != null) {
                throw new IllegalArgumentException("an INVESTIGATE decision must not carry an assessment");
            }
        } else {
            if (selectedTool != null || toolArguments != null) {
                throw new IllegalArgumentException(
                        "only an INVESTIGATE decision may select a tool");
            }
            if (assessment == null) {
                throw new IllegalArgumentException(
                        "an " + decisionType + " decision must carry an assessment");
            }
            if (decisionType == AgentDecisionType.ASSESS && !missingEvidence.isEmpty()) {
                throw new IllegalArgumentException(
                        "an ASSESS decision must not list missing evidence: assessing means the "
                                + "agent judged the evidence sufficient");
            }
            // ESCALATE may legitimately carry missing evidence. The conflict scenario escalates
            // precisely because a specific gap - resolving the contradiction - could not be
            // closed, and recording that gap is what makes the escalation explainable.
        }
    }

    public Optional<String> selectedToolIfPresent() {
        return Optional.ofNullable(selectedTool);
    }

    public Optional<ToolArguments> toolArgumentsIfPresent() {
        return Optional.ofNullable(toolArguments);
    }

    public Optional<Assessment> assessmentIfPresent() {
        return Optional.ofNullable(assessment);
    }
}
