package com.aisecurityguard.agent.llm;

import com.aisecurityguard.domain.Evidence;
import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.ToolRegistry;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Builds the prompts that turn a case into a model request.
 *
 * <p>This class is the whole of the agent's "instructions". It is deliberately explicit and
 * inspectable: the workflow rules the model is told to follow are the same rules the runtime
 * enforces, so a divergence between the two is a visible bug rather than a silent one.
 *
 * <p>Two properties matter:
 * <ul>
 *   <li><b>The capability list is generated from the registry</b>, so the model can never be told
 *       about a tool that does not exist, and can never be told about a capability that was not
 *       granted.</li>
 *   <li><b>The model is asked only for judgements, never for facts.</b> It reports what evidence
 *       it has seen and what it thinks is missing; it does not report versions or exploitation
 *       status, because those come from tools. This is what keeps the assessment grounded.</li>
 * </ul>
 */
@Component
public class CasePromptBuilder {

    private final ToolRegistry toolRegistry;

    public CasePromptBuilder(ToolRegistry toolRegistry) {
        this.toolRegistry = Objects.requireNonNull(toolRegistry);
    }

    /**
     * The standing instructions. Static apart from the capability list.
     */
    public String systemPrompt() {
        return """
                You are the investigation agent of an agentic cyber defence system. You investigate
                a vulnerability scanner finding against one asset and decide what to do next.

                CORE PRINCIPLE
                A scanner finding is not a confirmed vulnerability. A scanner result is evidence,
                and often a false positive. You must not accept it as fact.

                AVAILABLE CAPABILITIES
                %s

                You may select ONLY these, by their exact name. You have no shell, no file access,
                no network access and no ability to change anything. You cannot execute
                remediation; you may only propose it.

                YOUR DECISION - choose exactly one
                  INVESTIGATE - evidence is insufficient. Select ONE capability for the next piece
                                of evidence, and say what is missing and why that capability.
                  ASSESS      - evidence is sufficient and consistent. State your finding.
                  ESCALATE    - a contradiction remains, a capability failed or returned
                                INCONCLUSIVE, or no reliable verdict is possible. Say what could
                                not be established.

                ORDER OF INVESTIGATION
                Establish the observed runtime version first (inspect_service). Do not gather asset
                context before you know whether the asset is even affected: exposure and
                criticality only matter once a vulnerability is real.

                For a runtime version INSIDE the affected set you must also obtain:
                  - lookup_kev         : whether it is being exploited in the wild
                  - get_asset_context  : whether it is exposed, and how critical it is
                Both feed the priority. Do not assess without them.

                HOW TO READ CAPABILITY RESULTS
                A capability that FAILED or returned INCONCLUSIVE has NOT answered its question.
                It is never evidence that the finding is false.

                A SPECIFIC scanner claim that the observed runtime contradicts is a CONFLICT, and a
                conflict is never resolved by your own reasoning.

                This is the most important rule here:
                  - When the scanner claims a specific version and the runtime shows a different
                    one, you MUST call validate_vulnerability before concluding anything. Do not
                    dismiss the finding on the strength of the observed version alone: that is
                    exactly the reasoning the conflict rule exists to forbid, and it is how a real
                    contradiction gets silently discarded.
                  - "The scanner said 2.4.49 but the runtime is 2.4.58, so the scanner is simply
                    wrong" is NOT a conclusion you are permitted to reach. The scanner naming a
                    specific affected version is a claim about this asset that you cannot settle
                    yourself.
                  - Only after validate_vulnerability has run may you conclude. If it returns
                    INCONCLUSIVE, the conflict is UNRESOLVED and you must ESCALATE.
                  - Only a CONCLUSIVE validation, or the absence of any specific conflicting
                    claim, allows you to dismiss the finding.

                OTHER RULES
                1. Decide only from the CURRENT FACTS and EVIDENCE given to you. Never invent
                   values, versions, or evidence that is not listed.
                2. Do not select a capability whose answer you already have.
                3. If evidence is sufficient and consistent, assess - do not keep investigating.
                4. You must never claim an action was taken. You propose; a human decides.

                OUTPUT
                Reply with a single JSON object and nothing else. No markdown fences.

                "proposedAction" is for REMEDIATION of a confirmed vulnerability only. If your
                finding is NOT_AFFECTED or UNDETERMINED, omit proposedAction and actionImpact
                entirely: recording a closure is not an action, and the runtime handles it.

                You do not decide priority or confidence. The runtime derives those, and any values
                you supply for them will be ignored.
                """.formatted(capabilityList());
    }

    /** The user turn: the case as it currently stands. */
    public String casePrompt(SecurityCase securityCase) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("CASE\n");
        prompt.append("  case id      : ").append(securityCase.caseId()).append('\n');
        prompt.append("  asset        : ").append(securityCase.assetId()).append('\n');
        prompt.append("  cve          : ").append(securityCase.cveId()).append('\n');
        prompt.append("  finding status so far : ")
                .append(securityCase.assessmentIfPresent()
                        .map(a -> a.findingStatus().name())
                        .orElse("none yet"))
                .append('\n');

        prompt.append("\nCURRENT FACTS (authoritative, produced by executed capabilities)\n");
        Map<String, Object> facts = securityCase.facts().asMap();
        if (facts.isEmpty()) {
            prompt.append("  (none yet)\n");
        } else {
            facts.forEach((key, value) -> prompt.append("  ").append(key).append(" = ")
                    .append(String.valueOf(value)).append('\n'));
        }

        prompt.append("\nEVIDENCE\n");
        if (securityCase.evidence().isEmpty()) {
            prompt.append("  (none yet)\n");
        } else {
            for (Evidence evidence : securityCase.evidence()) {
                prompt.append("  ").append(evidence.evidenceId())
                        .append(" [").append(evidence.reliability()).append("] ")
                        .append(evidence.source()).append(" - ")
                        .append(evidence.finding())
                        .append('\n');
            }
        }

        // A contradiction is the case's most important feature, so it is stated as a fact about
        // the case rather than left for the model to notice in the evidence list. An earlier
        // version buried it, and the model duly dismissed the finding on the observed version
        // alone - precisely the error this warning exists to prevent.
        String conflictWarning = conflictWarning(securityCase);
        if (!conflictWarning.isEmpty()) {
            prompt.append(conflictWarning);
        }

        prompt.append(readinessChecklist(securityCase));

        prompt.append("""

                RESPONSE SCHEMA
                {
                  "decision": "INVESTIGATE" | "ASSESS" | "ESCALATE",
                  "missingEvidence": ["what is missing; required for INVESTIGATE, may be used for ESCALATE"],
                  "rationale": "one or two sentences, a concise explainable summary",
                  "capability": "capability name; required for INVESTIGATE, omit otherwise",
                  "findingStatus": "CONFIRMED_VULNERABLE" | "NOT_AFFECTED" | "UNDETERMINED",
                  "proposedAction": "what you propose, or omit if none",
                  "actionImpact": "A0" | "A1" | "A2" if you propose an action, omit otherwise
                }

                Note on actionImpact: use A2 when the action could change or interrupt a running
                service, because that requires explicit human approval.
                """);

        return prompt.toString();
    }

    /**
     * Lists the facts the case still lacks, and says whether they block an assessment.
     *
     * <p>Exists because a model that stops gathering evidence too early produces a confirmed
     * vulnerability whose priority cannot be computed - it simply has not seen whether the flaw is
     * exploited or how exposed the asset is. The runtime refuses such an assessment, so telling the
     * model the gaps up front is both kinder and more reliable than letting it discover the refusal.
     */
    private String readinessChecklist(SecurityCase securityCase) {
        boolean runtimeKnown = securityCase.facts().has(FactKeys.RUNTIME_VERSION);
        boolean exploitationKnown = securityCase.facts().has(FactKeys.KNOWN_EXPLOITED);
        boolean assetContextKnown = !securityCase.facts().getMap(FactKeys.ASSET_CONTEXT).isEmpty();

        StringBuilder checklist = new StringBuilder();
        checklist.append("\nDECISION READINESS (what the runtime requires before a verdict)\n");
        checklist.append("  observed runtime version : ")
                .append(runtimeKnown ? "KNOWN" : "MISSING - inspect_service")
                .append('\n');
        checklist.append("  known exploitation       : ")
                .append(exploitationKnown ? "KNOWN" : "MISSING - lookup_kev")
                .append('\n');
        checklist.append("  asset exposure/criticality: ")
                .append(assetContextKnown ? "KNOWN" : "MISSING - get_asset_context")
                .append('\n');

        if (!runtimeKnown) {
            checklist.append("  -> The runtime version is the first thing to establish. Do not\n")
                    .append("     gather asset context before you know whether the asset is affected.\n");
        } else if (!exploitationKnown || !assetContextKnown) {
            checklist.append("  -> If the observed version is AFFECTED, a CONFIRMED_VULNERABLE\n")
                    .append("     verdict requires BOTH missing items above, because priority is\n")
                    .append("     derived from them. The runtime will refuse such a verdict and\n")
                    .append("     escalate the case, so gather them before assessing.\n");
            checklist.append("  -> If the observed version is NOT affected, neither is needed:\n")
                    .append("     there is nothing to prioritise.\n");
        } else {
            checklist.append("  -> Everything a verdict needs is present. Assess.\n");
        }
        return checklist.toString();
    }

    /** Renders the registered capabilities for the system prompt. */
    private String capabilityList() {
        return toolRegistry.toolNames().stream()
                .sorted()
                .map(name -> "  - " + name)
                .collect(Collectors.joining("\n"));
    }

    /**
     * States the scanner-vs-runtime contradiction explicitly, when one exists and has not been
     * settled.
     *
     * <p>Returns an empty string when there is nothing to warn about, so the common case stays
     * uncluttered.
     */
    private String conflictWarning(SecurityCase securityCase) {
        String claimed = securityCase.facts()
                .getString(FactKeys.SCANNER_CLAIMED_VERSION).orElse(null);
        String runtime = securityCase.facts()
                .getString(FactKeys.RUNTIME_VERSION).orElse(null);

        if (claimed == null || runtime == null || claimed.equals(runtime)) {
            return "";
        }

        boolean validationAttempted = securityCase.facts().has(FactKeys.VALIDATION_RESULT);

        StringBuilder warning = new StringBuilder();
        warning.append("\n*** EVIDENCE CONFLICT - READ CAREFULLY ***\n");
        warning.append("  The scanner made a SPECIFIC version claim of ").append(claimed)
                .append(",\n  but the observed runtime version is ").append(runtime)
                .append(".\n");
        warning.append("  These cannot both be true, and you cannot settle this yourself.\n");

        if (validationAttempted) {
            warning.append("  An independent validation has already been attempted. If its result\n")
                    .append("  was INCONCLUSIVE, the conflict remains UNRESOLVED and you must\n")
                    .append("  ESCALATE. Do not dismiss the finding on the observed version alone.\n");
        } else {
            warning.append("  You MUST call validate_vulnerability now. Concluding NOT_AFFECTED\n")
                    .append("  from the observed version alone is forbidden: the scanner naming a\n")
                    .append("  specific affected version is a claim about this asset that you have\n")
                    .append("  not yet tested.\n");
        }
        warning.append("*******************************************\n");
        return warning.toString();
    }

    /** Exposed so tests can assert the model is never told about an unavailable capability. */
    public java.util.Set<String> advertisedCapabilities() {
        return toolRegistry.toolNames();
    }
}
