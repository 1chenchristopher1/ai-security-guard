package com.aisecurityguard.agent;

import com.aisecurityguard.domain.Assessment;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.Evidence;
import com.aisecurityguard.domain.EvidenceQuality;
import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.SecurityCase;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Finalises an assessment: validates that it is justified, then derives its confidence.
 *
 * <p>An assessment produced by a decision policy is a <em>draft</em>. It states the finding, the
 * priority and the proposed action, and it claims which evidence supports it. This service is the
 * only place that can turn a draft into a stored assessment, and it is where the following are
 * enforced:
 * <ol>
 *   <li><b>Supporting evidence exists.</b> Every cited evidence ID must be present in the case, so
 *       an assessment can never cite evidence that was never collected.</li>
 *   <li><b>Confidence is derived, never declared.</b> It is computed from evidence quality and
 *       from whether a contradiction remains, by {@link ConfidencePolicy}. A policy therefore
 *       cannot talk up its own certainty.</li>
 *   <li><b>Reasoning is structured.</b> {@link Assessment#reasons()} is trimmed and de-blanked so
 *       the approval screen renders clean bullets.</li>
 * </ol>
 *
 * <p>Separating this from the investigation loop matters: the loop orchestrates, this decides
 * whether a verdict is admissible. When an LLM becomes the decision policy, this is the component
 * that stands between the model and the case - the place where the runtime refuses to record a
 * conclusion the evidence cannot carry.
 */
@Component
public class AssessmentService {

    /** Source name of the opening scanner finding, which is the hypothesis rather than support. */
    private static final String SCANNER_FINDING_SOURCE = "Vulnerability Scanner";

    private final ConfidencePolicy confidencePolicy;
    private final PriorityPolicy priorityPolicy;

    /**
     * Constructs the service.
     *
     * <p>{@code @Autowired} is required because the class has a second constructor: without it
     * Spring cannot tell which to use and falls back to looking for a no-argument constructor.
     * The two-argument form is the real one; the single-argument form is a convenience for callers
     * that only need the default policies.
     */
    @org.springframework.beans.factory.annotation.Autowired
    public AssessmentService(ConfidencePolicy confidencePolicy, PriorityPolicy priorityPolicy) {
        this.confidencePolicy = Objects.requireNonNull(confidencePolicy);
        this.priorityPolicy = Objects.requireNonNull(priorityPolicy);
    }

    /** Convenience constructor using the default policies. */
    public AssessmentService(ConfidencePolicy confidencePolicy) {
        this(confidencePolicy, new PriorityPolicy());
    }

    /**
     * Validates a draft assessment against the case and derives its confidence.
     *
     * @param securityCase     the case the assessment belongs to
     * @param draft            the assessment proposed by the decision policy
     * @param conflictResolved false when the case contains contradictory claims the evidence has
     *                         not settled, which caps confidence at C3
     * @return a finalised, immutable assessment
     * @throws VerdictRefusedException if the assessment cites evidence that does not exist, or
     *                                 confirms a vulnerability without the facts needed to
     *                                 prioritise it
     */
    public Assessment finalise(SecurityCase securityCase, Assessment draft, boolean conflictResolved) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        Objects.requireNonNull(draft, "draft assessment must not be null");

        validateSupportingEvidenceExists(securityCase, draft);
        validateConfirmedFindingIsPrioritisable(securityCase, draft);

        Confidence confidence = confidencePolicy.derive(
                investigationEvidenceQuality(securityCase), conflictResolved);

        return new Assessment(
                draft.findingStatus(),
                resolvePriority(securityCase, draft),
                confidence,
                draft.supportingEvidenceIds(),
                draft.rationale(),
                cleanReasons(draft.reasons()),
                draft.proposedAction(),
                draft.actionImpact());
    }

    /**
     * Enforces that a confirmed vulnerability is actually prioritisable, and refuses the verdict if
     * it is not.
     *
     * <p>Priority is remediation urgency. A stored assessment reading "CONFIRMED_VULNERABLE" with no
     * priority tells a reviewer nothing about how urgently to act, so it is not an acceptable
     * outcome - and the urgency genuinely cannot be derived without knowing whether the flaw is
     * being exploited and how exposed the asset is.
     *
     * <p>This matters more with a language model as the decider than it does with the reference
     * policy. The reference policy structurally cannot confirm a vulnerability before gathering
     * those facts, because its own rules require them first. A model can simply decide it has seen
     * enough, which is how this check came to be needed: nothing else in the runtime noticed that a
     * confirmed finding had arrived without the evidence its priority depends on.
     *
     * <p>The refusal escalates the case rather than guessing a priority, because an unprioritised
     * confirmed vulnerability is precisely the thing a human should look at.
     */
    private void validateConfirmedFindingIsPrioritisable(SecurityCase securityCase, Assessment draft) {
        if (draft.findingStatus() != FindingStatus.CONFIRMED_VULNERABLE) {
            return;
        }

        List<String> missing = new ArrayList<>();
        if (!securityCase.facts().has(FactKeys.KNOWN_EXPLOITED)) {
            missing.add("whether the vulnerability is known to be exploited (lookup_kev)");
        }
        if (securityCase.facts().getMap(FactKeys.ASSET_CONTEXT).isEmpty()) {
            missing.add("asset exposure and business criticality (get_asset_context)");
        }

        if (!missing.isEmpty()) {
            throw new VerdictRefusedException(
                    "assessment for case " + securityCase.caseId() + " confirms a vulnerability "
                            + "without the evidence its priority depends on. Missing: " + missing
                            + ". A confirmed vulnerability that cannot be prioritised must be "
                            + "escalated, not stored with no urgency.");
        }
    }

    /**
     * The priority for a finalised assessment.
     *
     * <p>The three finding statuses are treated differently, because they mean different things:
     * <ul>
     *   <li><b>CONFIRMED_VULNERABLE</b> - real and remediation is proposed, so urgency is derived
     *       from the risk factors. This is the only case where priority carries information.</li>
     *   <li><b>NOT_AFFECTED</b> - nothing to fix, so urgency is the minimum. A priority exists
     *       because there is a finding, it just needs no action.</li>
     *   <li><b>UNDETERMINED</b> - the runtime has deliberately refused to judge the asset, so it
     *       must not judge its urgency either. Assigning P5 here would silently assert "not
     *       urgent", which is a verdict the agent declined to reach. No priority is the honest
     *       answer, and it is what tells a reviewer that a human still has to decide.</li>
     * </ul>
     *
     * <p>Like confidence, this is decided by the runtime rather than by the assessment that
     * arrived, so neither a reference policy nor a language model can declare its own urgency.
     */
    private com.aisecurityguard.domain.Priority resolvePriority(SecurityCase securityCase,
                                                                Assessment draft) {
        return switch (draft.findingStatus()) {
            case CONFIRMED_VULNERABLE -> priorityPolicy.derive(securityCase.facts());
            case NOT_AFFECTED -> priorityPolicy.deriveForNonAffected();
            case UNDETERMINED -> null;
        };
    }

    /**
     * Enforces that an assessment can be justified: every supporting evidence ID must exist in the
     * case. Without this an assessment could cite evidence it never collected.
     */
    private void validateSupportingEvidenceExists(SecurityCase securityCase, Assessment draft) {
        List<String> unknown = draft.supportingEvidenceIds().stream()
                .filter(id -> securityCase.findEvidence(id).isEmpty())
                .toList();
        if (!unknown.isEmpty()) {
            throw new VerdictRefusedException(
                    "assessment for case " + securityCase.caseId()
                            + " references evidence that does not exist: " + unknown
                            + ". An assessment must be supported by real evidence.");
        }
    }

    /**
     * Normalises the structured justification bullets. Blank entries are dropped rather than
     * rendered, and order is preserved because it is presentation order.
     */
    private List<String> cleanReasons(List<String> reasons) {
        if (reasons == null || reasons.isEmpty()) {
            return List.of();
        }
        List<String> cleaned = reasons.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(reason -> !reason.isEmpty())
                .toList();
        return cleaned.isEmpty() ? List.of() : cleaned;
    }

    /**
     * The evidence a confidence rating is derived from: the <em>investigation</em> evidence, not
     * the initial scanner finding.
     *
     * <p>This distinction is load-bearing. The scanner finding is the hypothesis under test - it
     * is present in every case by construction, including the case where it turns out to be wrong.
     * Counting it as supporting evidence would mean no assessment could ever reach C0, and would
     * treat "the scanner said so" as if it corroborated itself.
     *
     * <p>It is not ignored, though: if the scanner's specific claim contradicts what the
     * investigation found, that contradiction is what {@code conflictResolved} reports, and it
     * caps confidence at C3. So the claim still carries weight - as a challenge to the verdict
     * rather than as support for it.
     */
    private EvidenceQuality investigationEvidenceQuality(SecurityCase securityCase) {
        List<Evidence> gathered = securityCase.evidence().stream()
                .filter(evidence -> !isInitialScannerFinding(evidence))
                .toList();
        return EvidenceQuality.of(gathered);
    }

    /** True for the opening scanner finding, evidence {@code E-001}. */
    private boolean isInitialScannerFinding(Evidence evidence) {
        return SCANNER_FINDING_SOURCE.equals(evidence.source());
    }
}
