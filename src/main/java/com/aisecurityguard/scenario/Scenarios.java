package com.aisecurityguard.scenario;

import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.SimulationWorld;

import java.util.Set;

/**
 * The three canonical demo scenarios, transcribed from the prototype's {@code SC} table.
 *
 * <p>These are <b>test and demo fixtures</b>, not production code. The only reason they exist is
 * to give the tools something to observe deterministically. Note carefully what they do
 * <em>not</em> do: they do not tell the agent which tools to call, and nothing in
 * {@link com.aisecurityguard.agent.InvestigationLoop} or
 * {@link com.aisecurityguard.agent.ReferenceDecisionPolicy} refers to them. The tool call sequence
 * falls out of the evidence, which is the property the negative case exists to prove.
 */
public final class Scenarios {

    /**
     * The applicability rule for the demo CVE, CVE-2021-41773: Apache HTTP Server 2.4.49 is
     * affected. Expressed as data rather than a hard-coded string comparison, because in the
     * target architecture this comes from the vulnerability database.
     */
    public static final Set<String> CVE_2021_41773_AFFECTED_VERSIONS = Set.of("2.4.49");

    // ------------------------------------------------------------------
    // Scenario 1: CONFIRMED_VULNERABLE
    // ------------------------------------------------------------------

    /** The affected runtime really is running, on an exposed production asset with known exploitation. */
    public static final String POSITIVE_SCANNER_CLAIM =
            "Scanner reports a potential vulnerability in Apache HTTP Server.";

    public static SimulationWorld confirmedVulnerableWorld() {
        return new SimulationWorld(
                "2.4.49",
                true,
                true,
                "PRODUCTION",
                "HIGH",
                CVE_2021_41773_AFFECTED_VERSIONS,
                null);
    }

    public static SecurityCase confirmedVulnerableCase() {
        return new SecurityCase("CASE-VUL-001", "customer-portal-prod-01", "CVE-2021-41773");
    }

    // ------------------------------------------------------------------
    // Scenario 2: NOT_AFFECTED
    // ------------------------------------------------------------------

    /**
     * The scanner raised a finding but made no specific version claim, and the runtime is a
     * version the CVE does not affect. There is nothing to resolve, so the finding is dismissed.
     */
    public static final String NEGATIVE_SCANNER_CLAIM =
            "Scanner reports a potential vulnerable Apache HTTP Server version.";

    public static SimulationWorld notAffectedWorld() {
        return new SimulationWorld(
                "2.4.58",
                true,
                false,
                "STAGING",
                "LOW",
                CVE_2021_41773_AFFECTED_VERSIONS,
                null);
    }

    public static SecurityCase notAffectedCase() {
        return new SecurityCase("CASE-VUL-002", "internal-wiki-staging-02", "CVE-2021-41773");
    }

    // ------------------------------------------------------------------
    // Scenario 3: EVIDENCE_CONFLICT -> ESCALATE
    // ------------------------------------------------------------------

    /**
     * The scanner makes a specific version claim that runtime inspection contradicts, and the
     * independent validation cannot resolve the disagreement.
     */
    public static final String CONFLICT_SCANNER_CLAIM =
            "Scanner reports Apache HTTP Server 2.4.49.";

    public static SimulationWorld evidenceConflictWorld() {
        return new SimulationWorld(
                "2.4.58",
                true,
                true,
                "PRODUCTION",
                "HIGH",
                CVE_2021_41773_AFFECTED_VERSIONS,
                "2.4.49");
    }

    public static SecurityCase evidenceConflictCase() {
        return new SecurityCase("CASE-VUL-003", "partner-api-prod-03", "CVE-2021-41773");
    }

    private Scenarios() {
    }
}
