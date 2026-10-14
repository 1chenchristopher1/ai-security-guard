package com.aisecurityguard.agent;

import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.ValidateVulnerabilityTool;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Conflict status is a property of the evidence, inferred by the framework.
 *
 * <p>The three-way distinction is the point of this test. A conflict that is merely
 * {@link ConflictStatus#PENDING} is unfinished work with a tool still available; only
 * {@link ConflictStatus#UNRESOLVED} is the honest end state that caps confidence. Collapsing the
 * two would let the system either give up too early or keep investigating forever.
 */
class ConflictResolverTest {

    private final ConflictResolver resolver = new ConflictResolver();

    private static SecurityCase caseWith(String claimed, String runtime, String validation) {
        SecurityCase securityCase = new SecurityCase("CASE-C-001", "asset-01", "CVE-2021-41773");
        if (claimed != null) {
            securityCase.facts().merge(Map.of(FactKeys.SCANNER_CLAIMED_VERSION, claimed));
        }
        if (runtime != null) {
            securityCase.facts().merge(Map.of(FactKeys.RUNTIME_VERSION, runtime));
        }
        if (validation != null) {
            securityCase.facts().merge(Map.of(FactKeys.VALIDATION_RESULT, validation));
        }
        return securityCase;
    }

    @Test
    @DisplayName("no claim means nothing to conflict with")
    void noClaimIsNoConflict() {
        assertThat(resolver.resolve(caseWith(null, "2.4.58", null)))
                .isEqualTo(ConflictStatus.NONE);
    }

    @Test
    @DisplayName("nothing observed yet is not a conflict")
    void noObservationIsNoConflict() {
        assertThat(resolver.resolve(caseWith("2.4.49", null, null)))
                .isEqualTo(ConflictStatus.NONE);
    }

    @Test
    @DisplayName("a claim matching the observation is not a conflict")
    void matchingClaimIsNoConflict() {
        assertThat(resolver.resolve(caseWith("2.4.49", "2.4.49", null)))
                .isEqualTo(ConflictStatus.NONE);
    }

    @Test
    @DisplayName("a specific claim contradicted by observation, not yet checked, is PENDING")
    void contradictedClaimIsPending() {
        // The agent still has validate_vulnerability available, so this is unfinished work
        // rather than a failure.
        assertThat(resolver.resolve(caseWith("2.4.49", "2.4.58", null)))
                .isEqualTo(ConflictStatus.PENDING);
    }

    @Test
    @DisplayName("a contradiction that survived the independent check is UNRESOLVED")
    void inconclusiveValidationLeavesItUnresolved() {
        assertThat(resolver.resolve(caseWith("2.4.49", "2.4.58", "INCONCLUSIVE")))
                .isEqualTo(ConflictStatus.UNRESOLVED);
    }

    @Test
    @DisplayName("a contradiction settled by the independent check is no longer a conflict")
    void successfulValidationSettlesIt() {
        // A conclusive validation settles the question in either direction: here it ruled the
        // vulnerability out, which explains the scanner's contradictory claim.
        assertThat(resolver.resolve(caseWith("2.4.49", "2.4.58",
                ValidateVulnerabilityTool.RESULT_RULED_OUT)))
                .isEqualTo(ConflictStatus.NONE);
        assertThat(resolver.resolve(caseWith("2.4.49", "2.4.49",
                ValidateVulnerabilityTool.RESULT_CONFIRMED_VULNERABLE)))
                .isEqualTo(ConflictStatus.NONE);
    }

    @Test
    @DisplayName("an inconclusive validation leaves the contradiction standing")
    void inconclusiveResultIsUnresolved() {
        assertThat(resolver.resolve(caseWith("2.4.49", "2.4.58",
                ValidateVulnerabilityTool.RESULT_INCONCLUSIVE)))
                .isEqualTo(ConflictStatus.UNRESOLVED);
    }

    @Test
    @DisplayName("a vague scanner warning cannot conflict with anything")
    void vagueWarningCannotConflict() {
        // This is the NOT_AFFECTED scenario: the scanner raised a finding but named no version,
        // so there is nothing specific to contradict and no independent check is warranted.
        assertThat(resolver.resolve(caseWith(null, "2.4.58", null)))
                .isEqualTo(ConflictStatus.NONE);
    }

    @Test
    @DisplayName("only NONE counts as settled; PENDING does not")
    void onlyNoneIsSettled() {
        assertThat(resolver.isConflictSettled(caseWith("2.4.49", "2.4.49", null))).isTrue();
        assertThat(resolver.isConflictSettled(caseWith("2.4.49", "2.4.58", null)))
                .as("an unchallenged contradiction is not settled evidence")
                .isFalse();
        assertThat(resolver.isConflictSettled(caseWith("2.4.49", "2.4.58", "INCONCLUSIVE")))
                .isFalse();
    }

    @Test
    @DisplayName("status semantics are explicit")
    void statusSemantics() {
        assertThat(ConflictStatus.UNRESOLVED.isUnresolvedConflict()).isTrue();
        assertThat(ConflictStatus.PENDING.isUnresolvedConflict()).isFalse();
        assertThat(ConflictStatus.NONE.isSettled()).isTrue();
        assertThat(ConflictStatus.PENDING.isSettled()).isFalse();
        assertThat(ConflictStatus.UNRESOLVED.isSettled()).isFalse();
    }
}
