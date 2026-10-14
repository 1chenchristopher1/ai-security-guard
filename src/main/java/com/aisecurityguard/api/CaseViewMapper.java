package com.aisecurityguard.api;

import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.Priority;

/**
 * Turns domain objects into the shapes the UI reads.
 *
 * <p>Presentation decisions that are genuinely presentational - the wording of a status, which
 * colour family it belongs to - live here rather than in the page, so the page stays a renderer and
 * the vocabulary stays in one place. The page decides how things look; this decides what they are
 * called.
 */
public final class CaseViewMapper {

    private CaseViewMapper() {
    }

    /** The headline for a case, in the language the prototype used. */
    public static String statusLabel(CaseLifecycle lifecycle) {
        return switch (lifecycle) {
            case INVESTIGATING -> "Finding Under Investigation";
            case ASSESSED -> "Assessment Ready - Awaiting Approval";
            case CLEARED -> "Finding Closed - Not Affected";
            case ESCALATED -> "Escalated to a Human";
            case REMEDIATING -> "Remediation Running";
            case VERIFYING -> "Verifying Remediation";
            case RESOLVED -> "Case Resolved";
        };
    }

    /**
     * Which colour family a lifecycle belongs to.
     *
     * <p>Returned as a name rather than a hex value so the page owns its palette: "danger" means
     * whatever the design says it means.
     */
    public static String statusTone(CaseLifecycle lifecycle) {
        return switch (lifecycle) {
            case INVESTIGATING, REMEDIATING, VERIFYING -> "warn";
            case ASSESSED -> "danger";
            case CLEARED, RESOLVED -> "ok";
            case ESCALATED -> "warn";
        };
    }

    /** The label for a finding status. */
    public static String findingLabel(FindingStatus status) {
        return switch (status) {
            case CONFIRMED_VULNERABLE -> "CONFIRMED VULNERABLE";
            case NOT_AFFECTED -> "NOT AFFECTED";
            case UNDETERMINED -> "UNDETERMINED";
        };
    }

    /** The label for a priority, including the case where none was assigned. */
    public static String priorityLabel(Priority priority) {
        if (priority == null) {
            return "Unassigned - a human must decide";
        }
        return switch (priority) {
            case P0 -> "P0 - Immediate Remediation";
            case P1 -> "P1 - Urgent Remediation";
            case P2 -> "P2 - Scheduled Remediation";
            case P3 -> "P3 - Low Urgency";
            case P4 -> "P4 - Routine";
            case P5 -> "P5 - Lowest Urgency";
        };
    }

    /** The label for a confidence level. */
    public static String confidenceLabel(Confidence confidence) {
        return switch (confidence) {
            case C0 -> "C0 - Very High Confidence";
            case C1 -> "C1 - High Confidence";
            case C2 -> "C2 - Moderate Confidence";
            case C3 -> "C3 - Low Confidence";
            case C4 -> "C4 - Very Low Confidence";
        };
    }

    /** The label for an action impact, including the case where no action was proposed. */
    public static String actionImpactLabel(com.aisecurityguard.domain.ActionImpact impact) {
        if (impact == null) {
            return "No action proposed";
        }
        return switch (impact) {
            case A0 -> "A0 - Informational";
            case A1 -> "A1 - Low Impact";
            case A2 -> "A2 - Consequential Action";
        };
    }
}
