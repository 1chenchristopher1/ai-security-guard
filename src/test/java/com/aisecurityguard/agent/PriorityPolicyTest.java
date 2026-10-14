package com.aisecurityguard.agent;

import com.aisecurityguard.domain.CaseFacts;
import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.Priority;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Priority must follow from the risk factors, not from a single hard-coded condition.
 *
 * <p>The ladder matters because "how urgent is this" is the question a small IT team actually
 * needs answered, and because collapsing it to urgent/not-urgent was the prototype's weakest
 * prioritisation behaviour. The prototype only ever produced P0 or P2; this covers the whole
 * P0..P5 band.
 */
class PriorityPolicyTest {

    private final PriorityPolicy policy = new PriorityPolicy();

    private static CaseFacts facts(boolean knownExploited, Boolean internetFacing,
                                   String environment, String criticality) {
        CaseFacts caseFacts = new CaseFacts();
        if (knownExploited) {
            caseFacts.merge(Map.of(FactKeys.KNOWN_EXPLOITED, true));
        } else {
            caseFacts.merge(Map.of(FactKeys.KNOWN_EXPLOITED, false));
        }
        if (internetFacing != null) {
            Map<String, Object> asset = new HashMap<>();
            asset.put(FactKeys.ASSET_INTERNET_FACING, internetFacing);
            asset.put(FactKeys.ASSET_ENVIRONMENT, environment);
            asset.put(FactKeys.ASSET_BUSINESS_CRITICALITY, criticality);
            caseFacts.merge(Map.of(FactKeys.ASSET_CONTEXT, asset));
        }
        return caseFacts;
    }

    @Test
    @DisplayName("known exploitation on an internet-facing production asset is P0")
    void exploitedExposedProductionIsP0() {
        // This is the prototype's positive scenario and the headline demo case: 4+3+2+1 = 10.
        assertThat(policy.derive(facts(true, true, "PRODUCTION", "HIGH")))
                .isEqualTo(Priority.P0);
    }

    @Test
    @DisplayName("known exploitation on an exposed pre-production asset is P1")
    void exploitedExposedPreProductionIsP1() {
        // 4+3+0+1 = 8. Actively exploited on an internet-facing system, but not production.
        assertThat(policy.derive(facts(true, true, "STAGING", "HIGH")))
                .isEqualTo(Priority.P1);
    }

    @Test
    @DisplayName("known exploitation on a production asset, even without internet exposure, is P1")
    void exploitedProductionNotExposedIsP1() {
        // 4+0+2+1 = 8. Two of the three top risk factors. Known exploitation in production is
        // too serious to be merely scheduled, even if the service is not internet-facing.
        assertThat(policy.derive(facts(true, false, "PRODUCTION", "HIGH")))
                .isEqualTo(Priority.P1);
    }

    @Test
    @DisplayName("no exploitation but fully exposed production is P2")
    void exposedProductionWithoutExploitationIsP2() {
        // 0+3+2+1 = 6. Exploitation evidence is what makes a finding immediate; without it, even
        // a fully exposed high-criticality production system is scheduled rather than immediate.
        assertThat(policy.derive(facts(false, true, "PRODUCTION", "HIGH")))
                .isEqualTo(Priority.P2);
    }

    @Test
    @DisplayName("no exploitation on an exposed pre-production asset is P3")
    void exposedPreProductionIsP3() {
        // 0+3+0+1 = 4.
        assertThat(policy.derive(facts(false, true, "STAGING", "HIGH")))
                .isEqualTo(Priority.P3);
    }

    @Test
    @DisplayName("an internal development host with low criticality scores the baseline only")
    void lowExposureLowCriticalityIsP5() {
        // 0+0+0+0 baseline = 1, which is below the P4 threshold.
        assertThat(policy.derive(facts(false, false, "STAGING", "MEDIUM")))
                .isEqualTo(Priority.P5);
    }

    @Test
    @DisplayName("a fully contained asset scores the baseline and bottoms out at P5")
    void containedAssetIsP5() {
        assertThat(policy.derive(facts(false, false, "DEVELOPMENT", "LOW")))
                .isEqualTo(Priority.P5);
    }

    @Test
    @DisplayName("the ladder is monotonic: adding a risk factor never lowers urgency")
    void ladderIsMonotonic() {
        Priority none = policy.derive(facts(false, false, "DEVELOPMENT", "LOW"));
        Priority exposed = policy.derive(facts(false, true, "DEVELOPMENT", "LOW"));
        Priority exposedProd = policy.derive(facts(false, true, "PRODUCTION", "LOW"));
        Priority exploited = policy.derive(facts(true, true, "PRODUCTION", "LOW"));

        // Lower ordinal means more urgent, so each step must be <= the previous.
        assertThat(exposed.ordinal()).isLessThanOrEqualTo(none.ordinal());
        assertThat(exposedProd.ordinal()).isLessThanOrEqualTo(exposed.ordinal());
        assertThat(exploited.ordinal()).isLessThanOrEqualTo(exposedProd.ordinal());
    }

    @Test
    @DisplayName("every band P0..P5 is reachable, so the ladder is not decorative")
    void allBandsAreReachable() {
        // baseline 1 + knownExploited 4 + internetFacing 3 + production 2 + highCriticality 1
        assertThat(policy.derive(facts(true, true, "PRODUCTION", "HIGH")))
                .as("4+3+2+1 +1 = 11")
                .isEqualTo(Priority.P0);
        assertThat(policy.derive(facts(true, true, "STAGING", "HIGH")))
                .as("4+3+0+1 +1 = 9")
                .isEqualTo(Priority.P1);
        assertThat(policy.derive(facts(false, true, "PRODUCTION", "HIGH")))
                .as("0+3+2+1 +1 = 7")
                .isEqualTo(Priority.P2);
        assertThat(policy.derive(facts(false, false, "PRODUCTION", "HIGH")))
                .as("0+0+2+1 +1 = 4")
                .isEqualTo(Priority.P3);
        assertThat(policy.derive(facts(false, false, "DEVELOPMENT", "HIGH")))
                .as("0+0+0+1 +1 = 2")
                .isEqualTo(Priority.P4);
        assertThat(policy.derive(facts(false, false, "DEVELOPMENT", "LOW")))
                .as("baseline only = 1")
                .isEqualTo(Priority.P5);
    }

    @Test
    @DisplayName("missing asset context still yields a priority rather than failing")
    void missingAssetContextIsTolerated() {
        CaseFacts sparse = new CaseFacts();
        sparse.merge(Map.of(FactKeys.KNOWN_EXPLOITED, true));

        // Only the exploitation weight applies: 4+1 = 5, which is P3.
        assertThat(policy.derive(sparse)).isEqualTo(Priority.P3);
    }

    @Test
    @DisplayName("an empty fact set still yields the lowest priority rather than throwing")
    void emptyFactsAreTolerated() {
        assertThat(policy.derive(new CaseFacts())).isEqualTo(Priority.P5);
    }

    @Test
    @DisplayName("a dismissed finding is P5 by definition, not by scoring")
    void nonAffectedIsP5() {
        assertThat(policy.deriveForNonAffected()).isEqualTo(Priority.P5);
    }
}
