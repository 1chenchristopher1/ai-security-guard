package com.aisecurityguard.verification;

import java.util.List;

/**
 * The outcome of independently verifying an applied remediation.
 *
 * <p>Verification is a separate concern from remediation on purpose: the component that changed
 * the system is not the component that decides whether the change worked.
 *
 * @param caseId          the case that was verified
 * @param checks          the individual checks and their observations, in order
 * @param evidenceIds     the evidence records the checks produced
 * @param passed          true only when every check passed
 * @param observedVersion the runtime version observed after the fix
 */
public record RemediationVerification(
        String caseId,
        List<Check> checks,
        List<String> evidenceIds,
        boolean passed,
        String observedVersion) {

    /**
     * One verification check.
     *
     * @param name        what was checked
     * @param observation what was observed
     * @param passed      whether the observation is acceptable
     */
    public record Check(String name, String observation, boolean passed) {
    }

    public RemediationVerification {
        checks = List.copyOf(checks);
        evidenceIds = List.copyOf(evidenceIds);
    }
}
