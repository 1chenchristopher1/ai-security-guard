package com.aisecurityguard.verification;

import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.SimulationWorld;

/**
 * Independently establishes whether an applied remediation actually worked.
 *
 * <p>The verifier produces <em>evidence</em>, not just a verdict: a fix that is asserted but not
 * evidenced is indistinguishable from a fix that did not happen.
 */
public interface RemediationVerifier {

    /**
     * Verifies the current state of a remediated case.
     *
     * @param securityCase the case that was remediated
     * @param postFixWorld the world as it stands after the fix
     * @return the checks performed, the evidence they produced, and whether all passed
     */
    RemediationVerification verify(SecurityCase securityCase, SimulationWorld postFixWorld);
}
