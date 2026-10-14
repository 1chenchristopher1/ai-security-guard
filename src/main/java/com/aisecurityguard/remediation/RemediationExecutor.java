package com.aisecurityguard.remediation;

import com.aisecurityguard.approval.ApprovedExecution;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.SimulationWorld;

/**
 * Executes an approved remediation.
 *
 * <p>The signature is the security control: this method demands an {@link ApprovedExecution},
 * which can only be obtained from the approval gate in exchange for a token, which can only be
 * minted by a human decision. There is no overload without it, no boolean to skip it, and no
 * default. That is the difference between an approval gate and an approval prompt.
 */
public interface RemediationExecutor {

    /**
     * Applies the predefined remediation action for a case.
     *
     * @param securityCase the case being remediated
     * @param execution    the validated authorisation to execute
     * @param world        the world as the investigation observed it; the executor derives the
     *                     post-fix world from it rather than mutating it
     * @return what happened, including the post-fix world for verification
     * @throws IllegalStateException when no catalogued action addresses the vulnerability
     */
    RemediationOutcome execute(SecurityCase securityCase, ApprovedExecution execution,
                               SimulationWorld world);
}
