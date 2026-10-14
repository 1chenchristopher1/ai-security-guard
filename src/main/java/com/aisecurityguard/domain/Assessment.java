package com.aisecurityguard.domain;

import java.util.List;
import java.util.Optional;

/**
 * One assessment produced by the agent, with the evidence that supports it.
 *
 * <p>Independently variable axes, never merged into a single "severity":
 * <ul>
 *   <li>{@link #findingStatus()} - is the vulnerability real?</li>
 *   <li>{@link #priority()} - how urgent is remediation? May be absent.</li>
 *   <li>{@link #confidence()} - how well is this assessment supported? <b>Derived</b>, not
 *       declared: it is computed from evidence quality and conflict by
 *       {@link com.aisecurityguard.agent.ConfidencePolicy}.</li>
 *   <li>{@link #actionImpact()} - how risky is the proposed action? Drives human approval.</li>
 * </ul>
 *
 * <p>{@link #rationale()} is a concise, explainable summary for the audit trail and the approval
 * screen. It is NOT the model's hidden chain of thought and must never contain one.
 * {@link #reasons()} is the structured form of the same justification - the individual bullets the
 * approval screen shows - each of which states something the evidence actually supports.
 *
 * @param findingStatus         what is true about the asset
 * @param priority              remediation urgency, or {@code null} when unassigned
 *                              (the conflict scenario assigns no priority)
 * @param confidence            how strongly the evidence supports this assessment, derived
 * @param supportingEvidenceIds evidence IDs this assessment rests on; must all exist in the case
 * @param rationale             concise, human-readable justification
 * @param reasons               structured justification bullets, in presentation order
 * @param proposedAction        the proposed defensive action, or {@code null} if none
 * @param actionImpact          operational risk of the proposed action, or {@code null} if none
 */
public record Assessment(
        FindingStatus findingStatus,
        Priority priority,
        Confidence confidence,
        List<String> supportingEvidenceIds,
        String rationale,
        List<String> reasons,
        String proposedAction,
        ActionImpact actionImpact) {

    public Assessment {
        if (findingStatus == null) {
            throw new IllegalArgumentException("findingStatus must not be null");
        }
        if (confidence == null) {
            throw new IllegalArgumentException(
                    "confidence must not be null: it is derived by ConfidencePolicy before the "
                            + "assessment is finalised");
        }
        if (rationale == null || rationale.isBlank()) {
            throw new IllegalArgumentException("assessment rationale must not be blank");
        }
        supportingEvidenceIds = supportingEvidenceIds == null
                ? List.of()
                : List.copyOf(supportingEvidenceIds);
        if (supportingEvidenceIds.isEmpty()) {
            throw new IllegalArgumentException(
                    "an assessment must reference at least one supporting evidence id");
        }
        reasons = reasons == null ? List.of() : List.copyOf(reasons);
        if ((proposedAction == null) != (actionImpact == null)) {
            throw new IllegalArgumentException(
                    "proposedAction and actionImpact must either both be present or both be absent");
        }
        if (proposedAction != null && proposedAction.isBlank()) {
            throw new IllegalArgumentException("proposedAction must not be blank when present");
        }
    }

    public Optional<Priority> priorityIfAssigned() {
        return Optional.ofNullable(priority);
    }

    public Optional<String> proposedActionIfPresent() {
        return Optional.ofNullable(proposedAction);
    }

    public Optional<ActionImpact> actionImpactIfPresent() {
        return Optional.ofNullable(actionImpact);
    }

    /** True when this assessment is a finding that was dismissed; no action, no human decision. */
    public boolean isStopWithoutAction() {
        return findingStatus == FindingStatus.NOT_AFFECTED;
    }

    /** True when the agent refused to force a verdict. */
    public boolean isEscalation() {
        return findingStatus == FindingStatus.UNDETERMINED;
    }

    /**
     * True when the proposed action is consequential and therefore cannot execute without
     * explicit human approval. This is the gate the runtime must enforce - not the prompt.
     */
    public boolean requiresHumanApproval() {
        return actionImpact != null && actionImpact.requiresHumanApproval();
    }
}
