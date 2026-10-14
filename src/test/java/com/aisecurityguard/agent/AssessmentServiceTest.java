package com.aisecurityguard.agent;

import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.Assessment;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.EvidenceMetadata;
import com.aisecurityguard.domain.EvidenceReliability;
import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.Priority;
import com.aisecurityguard.domain.SecurityCase;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The runtime must be able to refuse a verdict the evidence cannot carry.
 *
 * <p>This is the component that stands between a decision policy - and, in a later milestone, an
 * LLM - and the stored case. These tests exist to prove three properties that the whole
 * human-in-the-loop argument rests on: an assessment cannot cite evidence it never collected, a
 * policy cannot choose its own confidence, and an open contradiction cannot be assessed away.
 */
class AssessmentServiceTest {

    private final AssessmentService service = new AssessmentService(new ConfidencePolicy());

    private static SecurityCase caseWith(EvidenceReliability... reliabilities) {
        SecurityCase securityCase = new SecurityCase("CASE-T-001", "asset-01", "CVE-2021-41773");
        securityCase.appendEvidence(
                new EvidenceMetadata("Scanner Finding", "Vulnerability Scanner",
                        "Scanner claims the asset is affected.", EvidenceReliability.MEDIUM,
                        java.util.Map.of()),
                LocalTime.of(9, 12, 1));
        for (int i = 0; i < reliabilities.length; i++) {
            securityCase.appendEvidence(
                    new EvidenceMetadata("Investigation Evidence", "inspect_service",
                            "Observation " + (i + 1), reliabilities[i], java.util.Map.of()),
                    LocalTime.of(9, 12, 2 + i));
        }
        // A confirmed vulnerability must be prioritisable, so the facts that priority derives from
        // are part of the baseline fixture. Tests that want the refusal path remove them.
        securityCase.facts().merge(java.util.Map.of(FactKeys.KNOWN_EXPLOITED, true));
        securityCase.facts().merge(java.util.Map.of(FactKeys.ASSET_CONTEXT, java.util.Map.of(
                FactKeys.ASSET_INTERNET_FACING, true,
                FactKeys.ASSET_ENVIRONMENT, "PRODUCTION",
                FactKeys.ASSET_BUSINESS_CRITICALITY, "HIGH")));
        return securityCase;
    }

    private static Assessment draft(List<String> evidenceIds, Confidence declared) {
        return new Assessment(
                FindingStatus.CONFIRMED_VULNERABLE,
                Priority.P0,
                declared,
                evidenceIds,
                "Draft assessment under test.",
                List.of("  Vulnerable runtime confirmed  ", "", "   "),
                "Upgrade the service.",
                ActionImpact.A2);
    }

    @Test
    @DisplayName("a policy cannot choose its own confidence: the declared value is discarded")
    void declaredConfidenceIsDiscarded() {
        SecurityCase securityCase = caseWith(
                EvidenceReliability.HIGH, EvidenceReliability.HIGH, EvidenceReliability.HIGH);

        // The policy claims C0. The evidence is three high items plus a scanner claim, so the
        // derivation also lands on C0 - but if the policy had claimed C1 or C3, that would be
        // overwritten too. The point is that the input does not survive.
        Assessment finalised = service.finalise(securityCase, draft(securityCase.evidenceIds(), Confidence.C0), true);

        assertThat(finalised.confidence()).isEqualTo(Confidence.C0);
        assertThat(finalised.findingStatus()).isEqualTo(FindingStatus.CONFIRMED_VULNERABLE);
        assertThat(finalised.priority()).isEqualTo(Priority.P0);
    }

    @Test
    @DisplayName("a policy cannot choose its own priority either: it is re-derived from the facts")
    void declaredPriorityIsRecomputed() {
        // The draft asks for P0 while the facts describe a contained development host: known
        // exploitation absent, no exposure, low criticality. Priority is urgency, and a policy
        // does not get to decide how urgent its own finding is.
        SecurityCase contained = new SecurityCase("CASE-T-002", "asset-02", "CVE-2021-41773");
        contained.appendEvidence(
                new EvidenceMetadata("Scanner Finding", "Vulnerability Scanner",
                        "Scanner claim.", EvidenceReliability.MEDIUM, java.util.Map.of()),
                LocalTime.of(9, 12, 1));
        contained.appendEvidence(
                new EvidenceMetadata("Investigation Evidence", "inspect_service",
                        "Observation.", EvidenceReliability.HIGH, java.util.Map.of()),
                LocalTime.of(9, 12, 2));
        contained.facts().merge(java.util.Map.of(FactKeys.KNOWN_EXPLOITED, false));
        contained.facts().merge(java.util.Map.of(FactKeys.ASSET_CONTEXT, java.util.Map.of(
                FactKeys.ASSET_INTERNET_FACING, false,
                FactKeys.ASSET_ENVIRONMENT, "DEVELOPMENT",
                FactKeys.ASSET_BUSINESS_CRITICALITY, "LOW")));

        Assessment finalised = service.finalise(
                contained, draft(contained.evidenceIds(), Confidence.C0), true);

        assertThat(finalised.priority())
                .as("a policy asking for P0 on a contained dev host does not get P0")
                .isEqualTo(Priority.P5);
    }

    @Test
    @DisplayName("a confirmed vulnerability without the facts its priority needs is refused")
    void confirmedVulnerabilityMustBePrioritisable() {
        // Priority cannot be computed without knowing whether the flaw is exploited and how
        // exposed the asset is. Storing "CONFIRMED_VULNERABLE" with no urgency would tell a
        // reviewer nothing, so the runtime refuses the verdict instead.
        SecurityCase bare = new SecurityCase("CASE-T-003", "asset-03", "CVE-2021-41773");
        bare.appendEvidence(
                new EvidenceMetadata("Scanner Finding", "Vulnerability Scanner",
                        "Scanner claim.", EvidenceReliability.MEDIUM, java.util.Map.of()),
                LocalTime.of(9, 12, 1));
        bare.appendEvidence(
                new EvidenceMetadata("Investigation Evidence", "inspect_service",
                        "Version observed.", EvidenceReliability.HIGH, java.util.Map.of()),
                LocalTime.of(9, 12, 2));

        assertThatThrownBy(() -> service.finalise(
                bare, draft(bare.evidenceIds(), Confidence.C0), true))
                .isInstanceOf(VerdictRefusedException.class)
                .hasMessageContaining("without the evidence its priority depends on")
                .hasMessageContaining("lookup_kev")
                .hasMessageContaining("get_asset_context");
    }

    @Test
    @DisplayName("an undetermined finding is given no priority at all")
    void undeterminedFindingHasNoPriority() {
        // Priority was withheld because the agent refused to reach a verdict. Assigning P5 here
        // would silently assert "not urgent", which is a judgement the agent declined to make.
        SecurityCase securityCase = caseWith(EvidenceReliability.INCONCLUSIVE);
        Assessment undetermined = new Assessment(
                FindingStatus.UNDETERMINED,
                Priority.P5,
                Confidence.C0,
                securityCase.evidenceIds(),
                "No reliable verdict is possible.",
                List.of(),
                null,
                null);

        Assessment finalised = service.finalise(securityCase, undetermined, false);

        assertThat(finalised.priority())
                .as("no urgency may be asserted for a finding the agent would not judge")
                .isNull();
    }

    @Test
    @DisplayName("an unresolved conflict denies the policy the high confidence it asked for")
    void unresolvedConflictDowngradesADeclaredC0() {
        SecurityCase securityCase = caseWith(
                EvidenceReliability.HIGH, EvidenceReliability.HIGH, EvidenceReliability.HIGH);

        Assessment finalised = service.finalise(
                securityCase, draft(securityCase.evidenceIds(), Confidence.C0), false);

        assertThat(finalised.confidence())
                .as("the policy asked for C0 while a contradiction stands; the runtime refuses")
                .isEqualTo(Confidence.C3);
    }

    @Test
    @DisplayName("a non-high investigation chain cannot be presented as C0")
    void weakInvestigationChainCannotClaimC0() {
        SecurityCase securityCase = caseWith(EvidenceReliability.INCONCLUSIVE);

        Assessment finalised = service.finalise(
                securityCase, draft(securityCase.evidenceIds(), Confidence.C0), true);

        assertThat(finalised.confidence().ordinal())
                .as("inconclusive investigation evidence must weaken the rating")
                .isGreaterThan(Confidence.C0.ordinal());
    }

    @Test
    @DisplayName("an assessment citing evidence that does not exist is refused")
    void unknownSupportingEvidenceIsRefused() {
        SecurityCase securityCase = caseWith(EvidenceReliability.HIGH);

        assertThatThrownBy(() -> service.finalise(
                securityCase,
                draft(List.of("E-001", "E-999"), Confidence.C0),
                true))
                .isInstanceOf(VerdictRefusedException.class)
                .hasMessageContaining("references evidence that does not exist")
                .hasMessageContaining("E-999");
    }

    @Test
    @DisplayName("justification bullets are trimmed and blank entries dropped")
    void reasonsAreNormalised() {
        SecurityCase securityCase = caseWith(EvidenceReliability.HIGH, EvidenceReliability.HIGH);

        Assessment finalised = service.finalise(
                securityCase, draft(securityCase.evidenceIds(), Confidence.C0), true);

        assertThat(finalised.reasons())
                .as("the approval screen must not render blank bullets")
                .containsExactly("Vulnerable runtime confirmed");
    }

    @Test
    @DisplayName("the scanner finding is the hypothesis under test, not supporting evidence")
    void scannerFindingDoesNotDiluteConfidence() {
        // Two high investigation observations plus the medium scanner claim.
        SecurityCase securityCase = caseWith(EvidenceReliability.HIGH, EvidenceReliability.HIGH);

        Assessment finalised = service.finalise(
                securityCase, draft(securityCase.evidenceIds(), Confidence.C0), true);

        assertThat(finalised.confidence())
                .as("counting the scanner claim as evidence would make C0 unreachable")
                .isEqualTo(Confidence.C0);
    }
}
