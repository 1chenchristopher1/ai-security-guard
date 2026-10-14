package com.aisecurityguard.agent;

import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.Evidence;
import com.aisecurityguard.domain.EvidenceMetadata;
import com.aisecurityguard.domain.EvidenceQuality;
import com.aisecurityguard.domain.EvidenceReliability;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Confidence must be derived from the evidence, never declared.
 *
 * <p>These tests pin the derivation rules directly. The scenario tests then confirm that the
 * derivation produces the classifications the prototype demonstrates (C0 / C0 / C3), which is the
 * real proof that the rule matches the intended behaviour rather than merely being self-consistent.
 */
class ConfidencePolicyTest {

    private final ConfidencePolicy policy = new ConfidencePolicy();

    private static Evidence evidence(String id, EvidenceReliability reliability) {
        return new Evidence(id,
                EvidenceMetadata.of("Type", "source", "finding", reliability),
                LocalTime.of(9, 12, 1));
    }

    private static List<Evidence> chain(EvidenceReliability... reliabilities) {
        List<Evidence> items = new ArrayList<>();
        for (int i = 0; i < reliabilities.length; i++) {
            items.add(evidence("E-%03d".formatted(i + 1), reliabilities[i]));
        }
        return items;
    }

    @Test
    @DisplayName("several high-reliability sources that agree give C0")
    void highReliabilityConsensusIsC0() {
        EvidenceQuality quality = EvidenceQuality.of(chain(
                EvidenceReliability.HIGH, EvidenceReliability.HIGH, EvidenceReliability.HIGH));

        assertThat(policy.derive(quality, true)).isEqualTo(Confidence.C0);
    }

    @Test
    @DisplayName("an unresolved conflict caps confidence at C3 regardless of how good the evidence is")
    void unresolvedConflictCapsAtC3() {
        EvidenceQuality quality = EvidenceQuality.of(chain(
                EvidenceReliability.HIGH, EvidenceReliability.HIGH, EvidenceReliability.HIGH));

        assertThat(policy.derive(quality, false))
                .as("conflicting evidence is unusable evidence, not merely weaker evidence")
                .isEqualTo(Confidence.C3);
    }

    @Test
    @DisplayName("inconclusive evidence costs more than merely being weaker than high")
    void inconclusiveEvidenceDowngrades() {
        EvidenceQuality quality = EvidenceQuality.of(chain(
                EvidenceReliability.HIGH, EvidenceReliability.HIGH,
                EvidenceReliability.INCONCLUSIVE));

        // not all high (-1) and inconclusive (-1)
        assertThat(policy.derive(quality, true)).isEqualTo(Confidence.C2);
    }

    @Test
    @DisplayName("a lone high-reliability observation is decisive and can be C0")
    void singleHighObservationIsC0() {
        // Reading the actual running version is decisive about that version; there is nothing
        // further to corroborate. C0 must remain reachable for this legitimate case.
        EvidenceQuality quality = EvidenceQuality.of(chain(EvidenceReliability.HIGH));

        assertThat(policy.derive(quality, true)).isEqualTo(Confidence.C0);
    }

    @Test
    @DisplayName("a lone medium-reliability item is an unverified assertion, not decisive")
    void singleMediumItemDowngrades() {
        EvidenceQuality quality = EvidenceQuality.of(chain(EvidenceReliability.MEDIUM));

        assertThat(policy.derive(quality, true)).isEqualTo(Confidence.C1);
    }

    @Test
    @DisplayName("no evidence at all is C4")
    void emptyEvidenceIsC4() {
        assertThat(policy.derive(EvidenceQuality.ofEmpty(), true)).isEqualTo(Confidence.C4);

        // An unresolved conflict short-circuits before the evidence-volume rules, so even an
        // empty chain is reported as a conflict rather than as "no evidence".
        assertThat(policy.derive(EvidenceQuality.of(List.of()), false)).isEqualTo(Confidence.C3);
    }

    @Test
    @DisplayName("weaknesses compose: a lone inconclusive item scores worse than a lone high item")
    void weaknessesCompose() {
        EvidenceQuality loneHigh = EvidenceQuality.of(chain(EvidenceReliability.HIGH));
        EvidenceQuality loneInconclusive = EvidenceQuality.of(chain(EvidenceReliability.INCONCLUSIVE));

        // one item, not high (-1)                  -> C1
        // one item, not high (-1), inconclusive (-1) -> C2
        assertThat(policy.derive(loneHigh, true)).isEqualTo(Confidence.C0);
        assertThat(policy.derive(loneInconclusive, true)).isEqualTo(Confidence.C2);
    }

    @Test
    @DisplayName("adding weaker evidence never raises confidence")
    void confidenceIsMonotonicInEvidence() {
        // This is the property that makes the score trustworthy: more evidence, or weaker
        // evidence, can only ever push confidence down, never up.
        Confidence strongOnly = policy.derive(
                EvidenceQuality.of(chain(EvidenceReliability.HIGH, EvidenceReliability.HIGH)), true);
        Confidence strongPlusWeak = policy.derive(
                EvidenceQuality.of(chain(EvidenceReliability.HIGH, EvidenceReliability.HIGH,
                        EvidenceReliability.INCONCLUSIVE)), true);
        Confidence weakOnly = policy.derive(
                EvidenceQuality.of(chain(EvidenceReliability.INCONCLUSIVE)), true);

        assertThat(strongOnly).isEqualTo(Confidence.C0);
        assertThat(strongPlusWeak.ordinal())
                .as("adding inconclusive evidence must not improve the score")
                .isGreaterThanOrEqualTo(strongOnly.ordinal());
        assertThat(weakOnly.ordinal())
                .as("a lone inconclusive item must not outrank corroborated high evidence")
                .isGreaterThanOrEqualTo(strongPlusWeak.ordinal());
    }

    @Test
    @DisplayName("a medium-reliability claim contradicted by high evidence still downgrades one level")
    void mediumClaimIsWeakerThanHigh() {
        // A scanner claim is weaker than direct observation, so the chain is not "all high".
        EvidenceQuality quality = EvidenceQuality.of(chain(
                EvidenceReliability.MEDIUM, EvidenceReliability.HIGH, EvidenceReliability.HIGH));

        assertThat(policy.derive(quality, true))
                .as("medium is weaker than high, but is not evidence of unreliability")
                .isEqualTo(Confidence.C1);
    }

    @Test
    @DisplayName("downgrades saturate at C4 and never run off the end")
    void downgradesSaturate() {
        EvidenceQuality quality = EvidenceQuality.of(chain(
                EvidenceReliability.INCONCLUSIVE));

        Confidence result = policy.derive(quality, true);

        assertThat(result.ordinal()).isLessThanOrEqualTo(Confidence.C4.ordinal());
    }

    @Test
    @DisplayName("null evidence quality is rejected rather than guessed at")
    void nullQualityRejected() {
        assertThatThrownBy(() -> policy.derive(null, true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ------------------------------------------------------------------
    // EvidenceQuality itself
    // ------------------------------------------------------------------

    @Test
    @DisplayName("EvidenceQuality summarises strongest, weakest and composition")
    void qualitySummarisesTheChain() {
        EvidenceQuality quality = EvidenceQuality.of(chain(
                EvidenceReliability.MEDIUM, EvidenceReliability.HIGH,
                EvidenceReliability.INCONCLUSIVE, EvidenceReliability.HIGH));

        assertThat(quality.itemCount()).isEqualTo(4);
        assertThat(quality.highestReliability()).isEqualTo(EvidenceReliability.HIGH);
        assertThat(quality.lowestReliability()).isEqualTo(EvidenceReliability.INCONCLUSIVE);
        assertThat(quality.highestReliabilityCount()).isEqualTo(2);
        assertThat(quality.mediumReliabilityCount()).isEqualTo(1);
        assertThat(quality.allHighReliability()).isFalse();
        assertThat(quality.anyInconclusive()).isTrue();
    }

    @Test
    @DisplayName("an all-high chain reports allHighReliability")
    void allHighChain() {
        EvidenceQuality quality = EvidenceQuality.of(chain(
                EvidenceReliability.HIGH, EvidenceReliability.HIGH));

        assertThat(quality.allHighReliability()).isTrue();
        assertThat(quality.anyInconclusive()).isFalse();
        assertThat(quality.highestReliabilityCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("reliability strength ordering is explicit, not enum ordinal")
    void strengthOrderingIsExplicit() {
        // HIGH must be strongest and INCONCLUSIVE weakest, whatever the enum declaration order.
        EvidenceQuality mixed = EvidenceQuality.of(chain(
                EvidenceReliability.INCONCLUSIVE, EvidenceReliability.HIGH));

        assertThat(mixed.highestReliability()).isEqualTo(EvidenceReliability.HIGH);
        assertThat(mixed.lowestReliability()).isEqualTo(EvidenceReliability.INCONCLUSIVE);
        assertThat(mixed.allHighReliability()).isFalse();
    }
}
