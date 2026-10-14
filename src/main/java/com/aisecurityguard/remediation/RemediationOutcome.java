package com.aisecurityguard.remediation;

import com.aisecurityguard.tool.SimulationWorld;

import java.util.List;

/**
 * The outcome of executing an approved remediation.
 *
 * @param caseId           the case that was remediated
 * @param actionId         the catalogue action that was applied
 * @param steps            the steps that ran, in order, for the audit trail
 * @param postFixWorld     the state of the world after the fix, for verification to observe
 * @param backupReference  reference to the pre-remediation backup
 * @param executedBy       the human whose approval authorised this
 */
public record RemediationOutcome(
        String caseId,
        String actionId,
        List<String> steps,
        SimulationWorld postFixWorld,
        String backupReference,
        String executedBy) {
}
