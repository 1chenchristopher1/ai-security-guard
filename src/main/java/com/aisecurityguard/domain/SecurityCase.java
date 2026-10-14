package com.aisecurityguard.domain;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A vulnerability investigation case: the aggregate root and single source of truth for one
 * scanner finding.
 *
 * <p>It owns the four things the workflow needs:
 * <ul>
 *   <li><b>identity</b> - caseId, assetId, cveId (the prototype kept these in a global scenario
 *       table instead; a real case must own them)</li>
 *   <li><b>lifecycle phase</b> - where the process is ({@link CaseLifecycle})</li>
 *   <li><b>evidence</b> - the append-only evidence chain</li>
 *   <li><b>facts</b> - the machine-readable memory the decision policy reads</li>
 * </ul>
 *
 * <p>plus the {@link Assessment} once one exists, and the decisions taken along the way.
 *
 * <p>Invariants enforced here:
 * <ul>
 *   <li>Evidence IDs are assigned by the case ({@code E-001}, {@code E-002}, ...) so the chain can
 *       never have gaps or duplicates.</li>
 *   <li>Evidence is append-only - there is no update or delete operation.</li>
 *   <li>Scanner finding is always the first evidence item.</li>
 *   <li>Finding status lives on the {@link Assessment} and is never mutated by lifecycle
 *       changes.</li>
 * </ul>
 */
public class SecurityCase {

    private static final String EVIDENCE_ID_FORMAT = "E-%03d";

    private final String caseId;
    private final String assetId;
    private final String cveId;

    private CaseLifecycle lifecycle = CaseLifecycle.INVESTIGATING;
    private final List<Evidence> evidence = new ArrayList<>();
    private final CaseFacts facts = new CaseFacts();
    private final List<AgentDecision> decisions = new ArrayList<>();

    private Assessment assessment;
    private boolean automaticRemediationBlocked;
    private String escalationReason;

    public SecurityCase(String caseId, String assetId, String cveId) {
        this.caseId = require(caseId, "caseId");
        this.assetId = require(assetId, "assetId");
        this.cveId = require(cveId, "cveId");
    }

    private static String require(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    // ------------------------------------------------------------------ identity

    public String caseId() {
        return caseId;
    }

    public String assetId() {
        return assetId;
    }

    public String cveId() {
        return cveId;
    }

    // ------------------------------------------------------------------ lifecycle

    public CaseLifecycle lifecycle() {
        return lifecycle;
    }

    public boolean isTerminal() {
        return lifecycle.isTerminal();
    }

    /**
     * True when the agent must stop taking investigative decisions.
     *
     * <p>Broader than {@link #isTerminal()}: an assessed case is still open and awaiting a human,
     * but the agent's investigation of it is over.
     */
    public boolean blocksFurtherInvestigation() {
        return lifecycle.blocksFurtherInvestigation();
    }

    /**
     * Moves the case to a new lifecycle stage.
     *
     * <p>Only a genuinely finished case refuses to move. An {@link CaseLifecycle#ASSESSED} case
     * has to remain movable, because the human decision that follows it is what takes the case
     * into remediation.
     */
    public void moveTo(CaseLifecycle next) {
        Objects.requireNonNull(next, "next lifecycle must not be null");
        if (lifecycle.isTerminal()) {
            throw new IllegalStateException(
                    "case " + caseId + " already reached terminal lifecycle " + lifecycle
                            + " and cannot move to " + next);
        }
        this.lifecycle = next;
    }

    // ------------------------------------------------------------------ evidence

    /** The append-only evidence chain, in collection order. */
    public List<Evidence> evidence() {
        return List.copyOf(evidence);
    }

    /**
     * Appends a new evidence item and assigns its ID from chain position.
     *
     * @return the stored {@link Evidence}, including its assigned ID
     */
    public Evidence appendEvidence(EvidenceMetadata metadata, java.time.LocalTime timestamp) {
        String id = EVIDENCE_ID_FORMAT.formatted(evidence.size() + 1);
        Evidence item = new Evidence(id, metadata, timestamp);
        evidence.add(item);
        return item;
    }

    public Optional<Evidence> findEvidence(String evidenceId) {
        return evidence.stream().filter(e -> e.evidenceId().equals(evidenceId)).findFirst();
    }

    /** IDs of all evidence in the chain, in order. Used for {@code observedEvidenceIds}. */
    public List<String> evidenceIds() {
        return evidence.stream().map(Evidence::evidenceId).toList();
    }

    public int evidenceCount() {
        return evidence.size();
    }

    // ------------------------------------------------------------------ facts

    public CaseFacts facts() {
        return facts;
    }

    // ------------------------------------------------------------------ assessment

    public Optional<Assessment> assessmentIfPresent() {
        return Optional.ofNullable(assessment);
    }

    public Assessment assessment() {
        return assessment;
    }

    /**
     * Stores the assessment exactly once. An assessment is immutable: it is never replaced, so
     * a later lifecycle change can never rewrite what the agent concluded.
     */
    public void recordAssessment(Assessment value) {
        Objects.requireNonNull(value, "assessment must not be null");
        if (this.assessment != null) {
            throw new IllegalStateException(
                    "case " + caseId + " already has an assessment; assessments are immutable");
        }
        this.assessment = value;
    }

    // ------------------------------------------------------------------ decisions

    /** Every agent decision taken on this case, in order. */
    public List<AgentDecision> decisions() {
        return List.copyOf(decisions);
    }

    public void recordDecision(AgentDecision decision) {
        decisions.add(Objects.requireNonNull(decision, "decision must not be null"));
    }

    /** The tool selected by the agent, in the order the agent selected them. */
    public List<String> selectedToolSequence() {
        return decisions.stream()
                .map(AgentDecision::selectedTool)
                .filter(Objects::nonNull)
                .toList();
    }

    // ------------------------------------------------------------------ remediation gate

    /**
     * True when automatic remediation is blocked for this case. Set when the case escalates, so
     * the gate is a property of the case rather than an implicit consequence of a phase check.
     */
    public boolean isAutomaticRemediationBlocked() {
        return automaticRemediationBlocked;
    }

    public Optional<String> escalationReason() {
        return Optional.ofNullable(escalationReason);
    }

    /**
     * Blocks automatic remediation. This is the runtime enforcing the escalation, not the prompt
     * asking the model nicely.
     */
    public void blockAutomaticRemediation(String reason) {
        this.automaticRemediationBlocked = true;
        this.escalationReason = require(reason, "escalation reason");
    }

    @Override
    public String toString() {
        return "SecurityCase[" + caseId + " " + assetId + " " + cveId
                + " lifecycle=" + lifecycle
                + " evidence=" + evidence.size()
                + " assessment=" + (assessment == null ? "none" : assessment.findingStatus())
                + "]";
    }
}
