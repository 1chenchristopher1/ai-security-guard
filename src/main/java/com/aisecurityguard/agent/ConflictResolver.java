package com.aisecurityguard.agent;

import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.ValidateVulnerabilityTool;
import org.springframework.stereotype.Component;

/**
 * Works out whether the case contains a contradiction between sources, from the evidence alone.
 *
 * <p>This exists because "the conflict is resolved" is not something a decision policy should get
 * to assert. If a policy were allowed to declare its own conflict status, it could resolve any
 * contradiction simply by ceasing to look at it - which is exactly the failure mode the escalation
 * path is meant to prevent.
 *
 * <p>All inputs are read from the case facts and the evidence chain, so the resolver is a pure
 * function of state that could be replayed or audited:
 * <ul>
 *   <li>{@code scannerClaimedVersion} - the specific version the scanner claimed, if any. A vague
 *       "something may be vulnerable" is not a checkable claim and cannot conflict.</li>
 *   <li>{@code runtimeVersion} - the version actually observed at runtime.</li>
 *   <li>{@code validationResult} - the outcome of an independent check, if one was attempted.</li>
 * </ul>
 *
 * <p>The resulting status is a three-way distinction, and the middle state matters: a conflict
 * that is merely {@link ConflictStatus#PENDING} is not a failure, it is unfinished work with a
 * tool still available to finish it. Only {@link ConflictStatus#UNRESOLVED} - a contradiction that
 * survived every available check - caps confidence and forces escalation.
 */
@Component
public class ConflictResolver {

    /**
     * Establishes the conflict status for a case.
     *
     * @param securityCase the case to inspect
     * @return the conflict status, never {@code null}
     */
    public ConflictStatus resolve(SecurityCase securityCase) {
        String claimed = securityCase.facts()
                .getString(FactKeys.SCANNER_CLAIMED_VERSION)
                .orElse(null);
        String runtime = securityCase.facts()
                .getString(FactKeys.RUNTIME_VERSION)
                .orElse(null);

        // No specific claim, or nothing observed yet: nothing can contradict anything.
        if (claimed == null || runtime == null || claimed.equals(runtime)) {
            return ConflictStatus.NONE;
        }

        // A specific claim and a directly contradictory observation. This is a real conflict,
        // and the agent now owes the case an attempt to settle it independently.
        String validation = securityCase.facts()
                .getString(FactKeys.VALIDATION_RESULT)
                .orElse(null);

        if (validation == null) {
            return ConflictStatus.PENDING;
        }
        if (!ValidateVulnerabilityTool.isConclusive(validation)) {
            // Validation ran but could not settle the question, so the contradiction stands.
            return ConflictStatus.UNRESOLVED;
        }

        // An independent check ran and settled the question, so the contradiction is explained.
        return ConflictStatus.NONE;
    }

    /**
     * Whether the evidence can currently support a confident verdict, as far as contradiction is
     * concerned. Passed to assessment finalisation, where it caps confidence.
     */
    public boolean isConflictSettled(SecurityCase securityCase) {
        return resolve(securityCase).isSettled();
    }
}
