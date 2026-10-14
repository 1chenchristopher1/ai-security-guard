package com.aisecurityguard.agent;

import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.AgentDecisionType;
import com.aisecurityguard.domain.Assessment;
import com.aisecurityguard.domain.CaseFacts;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.Priority;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.domain.ToolArguments;
import com.aisecurityguard.tool.SimulationWorld;
import com.aisecurityguard.tool.ToolRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Deterministic, evidence-driven reference decision policy.
 *
 * <p>This is a direct port of the prototype's {@code decide()} function. It is <b>not</b> the
 * final agent. It exists for three reasons:
 * <ol>
 *   <li>to prove the Java architecture can express the workflow;</li>
 *   <li>to reproduce the prototype's behaviour exactly;</li>
 *   <li>to become the regression oracle a real LLM agent is compared against.</li>
 * </ol>
 *
 * <p>It is the <b>default</b> policy, so the project builds, runs and tests with no network access
 * and no API key. The LLM agent
 * ({@link com.aisecurityguard.agent.llm.LlmDecisionPolicy}) is enabled instead by setting
 * {@code aisecurityguard.agent.policy=llm}. Only one of the two is ever registered.
 *
 * <p>Two properties are load-bearing and must survive into the LLM version:
 * <ul>
 *   <li><b>It decides from current case state only.</b> There is no precomputed tool sequence
 *       anywhere - no scenario switch, no playbook. The next tool is a function of the current
 *       facts and evidence.</li>
 *   <li><b>It is a pure function.</b> {@link #decide} reads the case and returns a decision; it
 *       does not mutate anything, invoke tools or advance state. The loop does that.</li>
 * </ul>
 *
 * <p>Every decision reports the evidence it observed, the evidence it judged to be missing, and a
 * concise rationale. The rationale is an explainable summary, never hidden chain of thought.
 */
@Component
@ConditionalOnProperty(name = "aisecurityguard.agent.policy", havingValue = "reference",
        matchIfMissing = true)
public class ReferenceDecisionPolicy implements DecisionPolicy {

    // ------------------------------------------------------------------
    // Rationale text. Short, factual, explainable - one line each.
    // ------------------------------------------------------------------

    private static final String RATIONALE_NEED_RUNTIME =
            "Scanner severity alone is insufficient to confirm that the running service is actually vulnerable.";

    private static final String RATIONALE_NEED_INDEPENDENT_CONFIRMATION =
            "The scanner version claim and the observed runtime version disagree. "
                    + "The agent needs an independent source before it can decide.";

    private static final String RATIONALE_CONFLICT_UNRESOLVED =
            "Independent validation could not resolve the conflict between the scanner claim "
                    + "and the observed runtime version. Conflicting evidence prevents a reliable "
                    + "automated assessment.";

    private static final String RATIONALE_NOT_AFFECTED =
            "Runtime evidence shows a version outside the affected range, so the scanner finding "
                    + "is not supported.";

    private static final String RATIONALE_NEED_EXPLOITATION =
            "Known exploitation evidence materially affects remediation priority.";

    private static final String RATIONALE_NEED_ASSET_CONTEXT =
            "Exposure and business criticality decide how urgent a confirmed vulnerability is.";

    private static final String RATIONALE_CONFIRMED =
            "Evidence is sufficient and consistent across independent sources.";

    private static final String NOTE_CONFIRMED =
            "Multiple independent evidence sources consistently support this assessment.";

    private static final String NOTE_NOT_AFFECTED =
            "The observed runtime version is outside the affected range, which contradicts the scanner finding.";

    private static final String NOTE_CONFLICT =
            "Conflicting evidence prevents a reliable automated assessment.";

    private static final String ACTION_UPGRADE_APACHE =
            "Upgrade Apache HTTP Server to a patched version.";

    /**
     * Placeholder confidence for a draft assessment.
     *
     * <p>A decision policy is not allowed to choose its own confidence: the real value is derived
     * from evidence quality and conflict by {@link ConfidencePolicy}, via
     * {@link AssessmentService}. This constant exists only because {@link Assessment} is
     * structurally complete at construction. C4 is used as the placeholder deliberately - if a
     * draft ever escaped without being finalised, an unearned assertion of certainty would be far
     * worse than an unearned assertion of doubt.
     */
    private static final Confidence DRAFT_CONFIDENCE = Confidence.C4;

    /**
     * Placeholder priority for a draft assessment, for the same reason as
     * {@link #DRAFT_CONFIDENCE}: the real value is derived by {@link AssessmentService}. The
     * lowest urgency is used so that an unfinalised draft can never overstate how soon something
     * must be fixed.
     */
    private static final Priority DRAFT_PRIORITY = Priority.P5;

    private final ToolRegistry toolRegistry;
    private final PriorityPolicy priorityPolicy;
    private final ConflictResolver conflictResolver;

    public ReferenceDecisionPolicy(ToolRegistry toolRegistry,
                                   PriorityPolicy priorityPolicy,
                                   ConflictResolver conflictResolver) {
        this.toolRegistry = toolRegistry;
        this.priorityPolicy = priorityPolicy;
        this.conflictResolver = conflictResolver;
    }

    /**
     * Decides the next step for a case, from the case's current evidence and facts.
     *
     * @param securityCase the case as it currently stands
     * @param world        the environment the tools will observe; used only for the CVE
     *                     applicability rule, never to select a tool sequence
     * @return an {@link AgentDecision} of type INVESTIGATE, ASSESS or ESCALATE
     */
    @Override
    public AgentDecision decide(SecurityCase securityCase, SimulationWorld world) {
        CaseFacts facts = securityCase.facts();
        List<String> observed = securityCase.evidenceIds();

        // --- Rule 1: we do not know what is actually running. -------------------
        String runtime = facts.getString(FactKeys.RUNTIME_VERSION).orElse(null);
        if (runtime == null) {
            return investigate(observed, "inspect_service",
                    List.of("Actual runtime version", "Vulnerability applicability"),
                    RATIONALE_NEED_RUNTIME, securityCase);
        }

        // --- The runtime is running a version the CVE does not affect. ----------
        if (!world.vulnerableRuntimeVersions().contains(runtime)) {

            // Whether a specific scanner claim contradicts what the runtime shows is decided by
            // the framework from the evidence, not asserted by this policy. That is what stops a
            // policy from resolving a conflict merely by no longer looking at it.
            ConflictStatus conflict = conflictResolver.resolve(securityCase);

            // Rule 2: a contradiction exists and has not been challenged yet. Seek an
            // independent source before concluding anything.
            if (conflict == ConflictStatus.PENDING) {
                return investigate(observed, "validate_vulnerability",
                        List.of("Independent confirmation of the runtime version"),
                        RATIONALE_NEED_INDEPENDENT_CONFIRMATION, securityCase);
            }

            // Rule 3: the contradiction survived every available check -> escalate.
            // A failed or inconclusive tool must never be read as "not affected".
            if (conflict == ConflictStatus.UNRESOLVED) {
                return escalate(observed,
                        List.of("Reliable resolution of the version conflict"),
                        RATIONALE_CONFLICT_UNRESOLVED,
                        new Assessment(
                                FindingStatus.UNDETERMINED,
                                null,
                                DRAFT_CONFIDENCE,   // replaced by AssessmentService
                                observed,
                                NOTE_CONFLICT,
                                List.of(),          // nothing is well enough established to assert
                                null,
                                null));
            }

            // Rule 4: no contradiction remains. The finding is a false positive.
            // The scanner claim is not a gap here: runtime evidence has answered it.
            return assess(List.copyOf(observed),
                    new Assessment(
                            FindingStatus.NOT_AFFECTED,
                            Priority.P5,
                            DRAFT_CONFIDENCE,
                            observed,
                            NOTE_NOT_AFFECTED,
                            List.of(),
                            null,
                            null));
        }

        // --- The runtime is affected. Now decide how urgent it is. --------------

        // Rule 5: exploitation status is unknown.
        if (!facts.has(FactKeys.KNOWN_EXPLOITED)) {
            return investigate(observed, "lookup_kev",
                    List.of("Real-world exploitation status", "Internet exposure",
                            "Asset criticality"),
                    RATIONALE_NEED_EXPLOITATION, securityCase);
        }

        // Rule 6: asset exposure and criticality are unknown.
        if (facts.getMap(FactKeys.ASSET_CONTEXT).isEmpty()) {
            return investigate(observed, "get_asset_context",
                    List.of("Asset exposure", "Business criticality"),
                    RATIONALE_NEED_ASSET_CONTEXT, securityCase);
        }

        // Rule 7: evidence is sufficient and consistent.
        // The assessment now rests on the evidence actually present, which includes the
        // asset-context evidence. `observed` is the snapshot taken when this decision was made:
        // it must be the same list that is recorded on the decision, or the audit trail would
        // claim the agent assessed evidence it had not yet seen.
        return assess(List.copyOf(observed),
                confirmedVulnerableAssessment(securityCase, facts, observed));
    }

    // ------------------------------------------------------------------
    // Assessment construction
    // ------------------------------------------------------------------

    private Assessment confirmedVulnerableAssessment(
            SecurityCase securityCase, CaseFacts facts, List<String> observed) {

        boolean knownExploited = facts.get(FactKeys.KNOWN_EXPLOITED)
                .filter(Boolean.class::isInstance)
                .map(Boolean.class::cast)
                .orElse(false);

        Map<String, Object> asset = facts.getMap(FactKeys.ASSET_CONTEXT).orElse(Map.of());
        boolean internetFacing = Boolean.TRUE.equals(asset.get(FactKeys.ASSET_INTERNET_FACING));
        boolean production = "PRODUCTION".equals(asset.get(FactKeys.ASSET_ENVIRONMENT));

        // Priority is NOT decided here. Like confidence, it is derived by AssessmentService when
        // the assessment is finalised, so there is exactly one source of truth for it and so a
        // policy - reference or model - cannot declare its own urgency.

        List<String> reasons = new ArrayList<>();
        reasons.add("Vulnerable runtime confirmed");
        if (internetFacing) {
            reasons.add("Internet-facing service");
        }
        if (production) {
            reasons.add("Production asset");
        }
        if (knownExploited) {
            reasons.add("Known exploitation in the wild");
        }

        return new Assessment(
                FindingStatus.CONFIRMED_VULNERABLE,
                DRAFT_PRIORITY,         // replaced by AssessmentService
                DRAFT_CONFIDENCE,       // replaced by AssessmentService
                observed,
                NOTE_CONFIRMED,
                reasons,
                ACTION_UPGRADE_APACHE,
                // A consequential action: it may modify a running production service,
                // so the runtime must require explicit human approval.
                ActionImpact.A2);
    }

    // ------------------------------------------------------------------
    // Decision construction helpers
    // ------------------------------------------------------------------

    private AgentDecision investigate(
            List<String> observed,
            String toolName,
            List<String> missingEvidence,
            String rationale,
            SecurityCase securityCase) {

        if (!toolRegistry.contains(toolName)) {
            throw new IllegalStateException(
                    "reference policy selected tool '" + toolName
                            + "' which is not registered. Available: " + toolRegistry.toolNames());
        }
        ToolArguments arguments = toolRegistry.argumentsFor(toolName, securityCase);

        return new AgentDecision(
                AgentDecisionType.INVESTIGATE,
                observed,
                missingEvidence,
                rationale,
                toolName,
                arguments,
                null);
    }

    private AgentDecision assess(List<String> observed, Assessment assessment) {
        // An ASSESS decision has no evidence gaps left to close, by definition:
        // reaching ASSESS means the policy judged the evidence sufficient.
        return new AgentDecision(
                AgentDecisionType.ASSESS,
                observed,
                List.of(),
                assessment.rationale(),
                null,
                null,
                assessment);
    }

    /**
     * Escalation hands the case to a human and selects no tool. The unresolved gap is carried on
     * the decision itself, because that gap is the reason a human is now required.
     *
     * @param unresolvedGaps what could not be established
     */
    private AgentDecision escalate(
            List<String> observed,
            List<String> unresolvedGaps,
            String rationale,
            Assessment assessment) {

        return new AgentDecision(
                AgentDecisionType.ESCALATE,
                observed,
                unresolvedGaps,
                rationale,
                null,
                null,
                assessment);
    }
}