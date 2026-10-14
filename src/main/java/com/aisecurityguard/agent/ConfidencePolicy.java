package com.aisecurityguard.agent;

import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.EvidenceQuality;
import com.aisecurityguard.domain.EvidenceReliability;
import org.springframework.stereotype.Component;

/**
 * Derives {@link Confidence} from the quality of the evidence and from whether the evidence
 * conflicts.
 *
 * <p>Confidence is the system's honesty valve: it is the axis that lets the agent say
 * "undetermined, and I know why". It therefore must not be declared by whoever forms the
 * assessment - it is computed, so that it cannot be talked up.
 *
 * <p>The rules:
 * <ol>
 *   <li><b>An unresolved conflict caps confidence at C3.</b> Conflicting evidence is not weak
 *       evidence, it is unusable evidence: no reliable automated verdict is possible.</li>
 *   <li><b>Otherwise, confidence starts at C0 and each weakness costs one level.</b> C0 means the
 *       evidence is decisive and high-reliability. The weaknesses are:
 *       <ul>
 *         <li>the chain rests on a single item that is not high-reliability, i.e. an unverified
 *             assertion rather than an observation;</li>
 *         <li>not every item is high-reliability;</li>
 *         <li>at least one item is inconclusive, which is worse than merely not-high.</li>
 *       </ul>
 *       The deductions compose, so adding weaker evidence can never <em>raise</em> confidence -
 *       which is the property that makes the score trustworthy.</li>
 * </ol>
 *
 * <p>Note what does <em>not</em> cause a downgrade: a medium-reliability scanner claim that
 * runtime evidence has already explained away. In that situation the claim is not a gap in the
 * evidence, it is a question that has been answered. The rule that keeps this correct is that only
 * {@code INCONCLUSIVE} evidence counts as an unreliability penalty on top of the non-high
 * penalty; {@code MEDIUM} evidence is weaker than {@code HIGH} but is not evidence of
 * unreliability.
 */
@Component
public final class ConfidencePolicy {

    /**
     * Derives confidence for an assessment.
     *
     * @param quality          summary of the evidence chain backing the assessment
     * @param conflictResolved false when the case contains contradictory claims that the evidence
     *                         has not settled. An unresolved conflict caps confidence at C3.
     * @return the derived confidence, never {@code null}
     */
    public Confidence derive(EvidenceQuality quality, boolean conflictResolved) {
        if (quality == null) {
            throw new IllegalArgumentException("evidence quality must not be null");
        }

        // Rule 1: an unresolved conflict is disqualifying, not merely a deduction.
        if (!conflictResolved) {
            return Confidence.C3;
        }

        // Rule 2: start optimistic, downgrade once per weakness.
        Confidence confidence = Confidence.C0;

        if (quality.itemCount() == 0) {
            return Confidence.C4;
        }

        // A lone medium-reliability item is an unverified assertion, not an observation, so it
        // cannot be decisive on its own. A lone HIGH item can be: reading the actual running
        // version is decisive evidence about that version, and there is nothing further to
        // corroborate. Requiring two items unconditionally would make C0 unreachable for the
        // legitimate single-observation case.
        if (quality.itemCount() == 1 && quality.highestReliability() != EvidenceReliability.HIGH) {
            confidence = downgrade(confidence);
        }

        // The chain is weaker than "several independent high-reliability sources agree".
        if (!quality.allHighReliability()) {
            confidence = downgrade(confidence);
        }

        // Inconclusive evidence is worse than merely not-high: it is evidence that something
        // could not be established.
        if (quality.anyInconclusive()) {
            confidence = downgrade(confidence);
        }

        return confidence;
    }

    /** One step weaker, saturating at {@link Confidence#C4}. */
    private Confidence downgrade(Confidence current) {
        int next = Math.min(current.ordinal() + 1, Confidence.C4.ordinal());
        return Confidence.values()[next];
    }
}
