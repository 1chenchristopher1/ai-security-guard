package com.aisecurityguard.api;

import com.aisecurityguard.agent.ConflictStatus;
import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.ApprovalOutcome;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.EvidenceReliability;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.Priority;

import java.util.List;

/**
 * The wire format for the UI.
 *
 * <p>Deliberately separate from the domain types rather than serialising them directly. The domain
 * is free to change shape without breaking the page, the page is free to show a summary without
 * the server exposing everything, and - most usefully - it is obvious at a glance what the UI is
 * actually permitted to see.
 *
 * <p>Everything here is a plain record with no behaviour, so serialisation is unambiguous.
 */
public final class CaseView {

    private CaseView() {
    }

    /** A case as the overview list needs it. */
    public record Summary(
            String caseId,
            String assetId,
            String cveId,
            CaseLifecycle lifecycle,
            FindingStatus findingStatus,
            Priority priority,
            Confidence confidence,
            String statusLabel,
            int evidenceCount,
            boolean approvalRequired,
            ApprovalOutcome approvalOutcome,
            boolean automaticRemediationBlocked,
            int auditEventCount) {
    }

    /** Everything the investigation and approval screens need. */
    public record Detail(
            String caseId,
            String assetId,
            String cveId,
            CaseLifecycle lifecycle,
            String statusLabel,
            String statusTone,
            FindingStatus findingStatus,
            Priority priority,
            Confidence confidence,
            ActionImpact actionImpact,
            List<String> reasons,
            String rationale,
            String proposedAction,
            boolean requiresHumanApproval,
            boolean approvalRequired,
            ApprovalOutcome approvalOutcome,
            String approverId,
            boolean automaticRemediationBlocked,
            String escalationReason,
            ConflictStatus conflictStatus,
            List<EvidenceView> evidence,
            List<DecisionView> decisions,
            List<AuditEventView> audit,
            List<CheckView> verificationChecks,
            List<String> remediationSteps,
            String backupReference,
            boolean chainIntact,
            String chainReport) {
    }

    /** One evidence record. */
    public record EvidenceView(
            String evidenceId,
            String type,
            String source,
            String finding,
            EvidenceReliability reliability,
            String time) {
    }

    /** One agent decision, including the reasoning the audit trail shows. */
    public record DecisionView(
            int number,
            String decisionType,
            String selectedTool,
            String toolArguments,
            List<String> observedEvidenceIds,
            List<String> missingEvidence,
            String rationale) {
    }

    /** One audit entry. */
    public record AuditEventView(
            long sequence,
            String time,
            String actor,
            String eventType,
            String result,
            String hashPrefix) {
    }

    /** One post-remediation verification check. */
    public record CheckView(String name, String observation, boolean passed) {
    }

    /** What the page needs to render the scenario chooser. */
    public record ScenarioView(String key, String label, String caseId, String assetId,
                               String scannerClaim, String expectedOutcome) {
    }

    /** A message for the user, successful or not. */
    public record Message(String message, String detail) {
        public static Message of(String message) {
            return new Message(message, null);
        }
    }
}
