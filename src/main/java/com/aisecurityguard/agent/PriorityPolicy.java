package com.aisecurityguard.agent;

import com.aisecurityguard.domain.CaseFacts;
import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.Priority;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;

/**
 * Derives remediation {@link Priority} from case facts.
 *
 * <p>Priority answers "how urgently must this be fixed". It is deliberately separate from finding
 * status ("is it real") and from confidence ("how sure are we"): a confirmed vulnerability can be
 * urgent or routine depending entirely on exposure and business context, and no amount of evidence
 * quality changes that.
 *
 * <p>The score starts at a baseline and adds weight for each risk factor, then maps to a band.
 * This is a transparent, auditable rule set rather than a black box, so a human can always answer
 * "why is this P0?" from the facts alone.
 *
 * <table>
 *   <caption>Risk weights</caption>
 *   <tr><td>Known exploited in the wild</td><td>+4</td></tr>
 *   <tr><td>Internet-facing</td><td>+3</td></tr>
 *   <tr><td>Production environment</td><td>+2</td></tr>
 *   <tr><td>High business criticality</td><td>+1</td></tr>
 *   <tr><td>Baseline</td><td>1</td></tr>
 * </table>
 *
 * <p>Score 10 must mean P0, which is why the weight for known exploitation is high enough that
 * P0 requires <em>all</em> of exploitation, internet exposure and production: 4+3+2+1 = 10.
 * Without exploitation the score caps at 6, which is P2. That matches the prototype, where only
 * the combination of known exploitation, internet exposure and a production asset yields P0.
 *
 * <p>Weights are not simply 1/2/3/4 because that would put a merely internet-facing staging asset
 * at P2 alongside a confirmed production vulnerability. Exploitation evidence is what makes a
 * finding immediate, so it dominates the scale.
 */
@Component
public class PriorityPolicy {

    // Risk weights, ordered by how much each factor changes the urgency.
    private static final int WEIGHT_KNOWN_EXPLOITED = 4;
    private static final int WEIGHT_INTERNET_FACING = 3;
    private static final int WEIGHT_PRODUCTION = 2;
    private static final int WEIGHT_HIGH_CRITICALITY = 1;

    private static final int BASELINE = 1;

    /** The environment value that counts as production. */
    private static final String ENVIRONMENT_PRODUCTION = "PRODUCTION";

    /** The criticality value that counts as high. */
    private static final String CRITICALITY_HIGH = "HIGH";

    /** Priority that saturates for anything scoring zero risk, and for a dismissed finding. */
    private static final Priority LOWEST_PRIORITY = Priority.P5;

    /**
     * Derives priority for a confirmed vulnerability from the case facts.
     *
     * @param facts the case facts; must contain the exploitation and asset-context facts
     * @return the derived priority, never {@code null}
     */
    public Priority derive(CaseFacts facts) {
        int score = BASELINE;

        boolean knownExploited = booleanFact(facts, FactKeys.KNOWN_EXPLOITED).orElse(false);
        Map<String, Object> asset = facts.getMap(FactKeys.ASSET_CONTEXT).orElse(Map.of());
        boolean internetFacing = Boolean.TRUE.equals(asset.get(FactKeys.ASSET_INTERNET_FACING));
        boolean production = ENVIRONMENT_PRODUCTION.equals(asset.get(FactKeys.ASSET_ENVIRONMENT));
        boolean highCriticality = CRITICALITY_HIGH.equals(
                asset.get(FactKeys.ASSET_BUSINESS_CRITICALITY));

        if (knownExploited) {
            score += WEIGHT_KNOWN_EXPLOITED;
        }
        if (internetFacing) {
            score += WEIGHT_INTERNET_FACING;
        }
        if (production) {
            score += WEIGHT_PRODUCTION;
        }
        if (highCriticality) {
            score += WEIGHT_HIGH_CRITICALITY;
        }

        return band(score);
    }

    /**
     * Maps a risk score onto a priority band. Higher score means more urgent, so the bands run
     * from P0 at the top down to P5.
     *
     * <p>The boundaries are chosen so that reaching P0 requires <em>all</em> of known
     * exploitation, internet exposure and production (4+3+2+1 = 10), while any one of those
     * missing drops the finding out of the immediate band. P1 (score 8) requires two of the
     * three: exploited and exposed, or exploited and in production.
     */
    private Priority band(int score) {
        if (score >= 10) {
            return Priority.P0;
        }
        if (score >= 8) {
            return Priority.P1;
        }
        if (score >= 6) {
            return Priority.P2;
        }
        if (score >= 4) {
            return Priority.P3;
        }
        if (score >= 2) {
            return Priority.P4;
        }
        return LOWEST_PRIORITY;
    }

    /**
     * The priority for a finding that is not affected. No action is required, so urgency is
     * minimal by definition rather than by scoring.
     */
    public Priority deriveForNonAffected() {
        return LOWEST_PRIORITY;
    }

    private Optional<Boolean> booleanFact(CaseFacts facts, String key) {
        return facts.get(key).filter(Boolean.class::isInstance).map(Boolean.class::cast);
    }
}
