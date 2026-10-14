package com.aisecurityguard.scenario;

import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.SimulationWorld;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A wider, parameterised library of worlds for grading the agent.
 *
 * <p>The three canonical scenarios prove the workflow works. They are not a grading set: three
 * hand-written cases cannot show whether a decision policy generalises, and they cannot distinguish
 * "the agent reasoned correctly" from "the agent happened to match the three cases it was written
 * for".
 *
 * <p>This library builds worlds from their risk factors instead, so coverage can be enumerated
 * rather than invented. Its purpose is to be the grading set a language model is measured against,
 * and the property-checking harness the reference policy is held to.
 *
 * <p>Worlds are pure data; nothing here encodes a decision or an expected outcome. What the agent
 * <em>should</em> do is asserted by the tests, not baked into the fixtures.
 */
public final class ScenarioLibrary {

    /** The affected range for the demo CVE. */
    public static final Set<String> AFFECTED_2021_41773 = Set.of("2.4.49");

    /** A version outside the affected range. */
    public static final String UNAFFECTED_VERSION = "2.4.58";

    /** The affected version. */
    public static final String AFFECTED_VERSION = "2.4.49";

    /** A named world together with the case it belongs to. */
    public record Scenario(String name, SecurityCase securityCase, SimulationWorld world,
                           String scannerClaim) {
    }

    // ------------------------------------------------------------------
    // Building blocks
    // ------------------------------------------------------------------

    public static SimulationWorld world(String runtimeVersion, boolean knownExploited,
                                        boolean internetFacing, String environment,
                                        String criticality, String claimedVersion) {
        return new SimulationWorld(runtimeVersion, knownExploited, internetFacing, environment,
                criticality, AFFECTED_2021_41773, claimedVersion);
    }

    private static SecurityCase caseFor(String name) {
        return new SecurityCase("CASE-" + name, "asset-" + name.toLowerCase(java.util.Locale.ROOT),
                "CVE-2021-41773");
    }

    private static Scenario scenario(String name, SimulationWorld world, String claim) {
        return new Scenario(name, caseFor(name), world, claim);
    }

    public static final String VAGUE_CLAIM =
            "Scanner reports a potential vulnerability in Apache HTTP Server.";
    public static final String SPECIFIC_CLAIM_AFFECTED =
            "Scanner reports Apache HTTP Server 2.4.49.";
    public static final String SPECIFIC_CLAIM_UNAFFECTED =
            "Scanner reports Apache HTTP Server 2.4.58.";

    // ------------------------------------------------------------------
    // The risk-factor matrix
    // ------------------------------------------------------------------

    /**
     * Every combination of the risk factors that drive priority, against an affected runtime.
     *
     * <p>This is the full 2x2x2x2 grid: exploitation, exposure, production and criticality. It is
     * exhaustive rather than sampled, because the priority ladder is a rule set and a rule set
     * should be checked at every input, not at a few.
     */
    public static List<Scenario> fullRiskMatrix() {
        List<Scenario> scenarios = new ArrayList<>();
        for (boolean exploited : List.of(false, true)) {
            for (boolean internet : List.of(false, true)) {
                for (String environment : List.of("PRODUCTION", "STAGING")) {
                    for (String criticality : List.of("LOW", "HIGH")) {
                        String name = "MATRIX-" + flag(exploited) + "-" + flag(internet)
                                + "-" + environment + "-" + criticality;
                        scenarios.add(scenario(name,
                                world(AFFECTED_VERSION, exploited, internet, environment,
                                        criticality, null),
                                VAGUE_CLAIM));
                    }
                }
            }
        }
        return scenarios;
    }

    private static String flag(boolean value) {
        return value ? "Y" : "N";
    }

    // ------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------

    /**
     * Situations that are plausible but absent from the three demo scenarios.
     *
     * <p>These are chosen to probe the boundaries of the decision rules rather than to be
     * representative: what happens when a fact is missing, when a finding is contained, when the
     * scanner is confidently wrong in the other direction, and when nothing at all is vulnerable.
     */
    public static Map<String, Scenario> edgeCases() {
        Map<String, Scenario> cases = new LinkedHashMap<>();

        cases.put("AFFECTED-CONTAINED", scenario("AFFECTED-CONTAINED",
                world(AFFECTED_VERSION, false, false, "DEVELOPMENT", "LOW", null),
                VAGUE_CLAIM));

        cases.put("AFFECTED-INTERNAL-PRODUCTION", scenario("AFFECTED-INTERNAL-PRODUCTION",
                world(AFFECTED_VERSION, true, false, "PRODUCTION", "HIGH", null),
                VAGUE_CLAIM));

        cases.put("AFFECTED-EXPOSED-STAGING", scenario("AFFECTED-EXPOSED-STAGING",
                world(AFFECTED_VERSION, true, true, "STAGING", "HIGH", null),
                VAGUE_CLAIM));

        cases.put("UNAFFECTED-EXPOSED-PRODUCTION", scenario("UNAFFECTED-EXPOSED-PRODUCTION",
                world(UNAFFECTED_VERSION, true, true, "PRODUCTION", "HIGH", null),
                VAGUE_CLAIM));

        // The scanner is confidently wrong: it claims an unaffected version. The claim is
        // specific, so it must be checked against reality rather than assumed.
        cases.put("CLAIM-UNAFFECTED-RUNTIME-UNAFFECTED", scenario("CLAIM-UNAFFECTED-RUNTIME-UNAFFECTED",
                world(UNAFFECTED_VERSION, false, true, "PRODUCTION", "HIGH",
                        UNAFFECTED_VERSION),
                SPECIFIC_CLAIM_UNAFFECTED));

        // The scanner claims the affected version and the runtime agrees: no conflict.
        cases.put("CLAIM-AFFECTED-RUNTIME-AFFECTED", scenario("CLAIM-AFFECTED-RUNTIME-AFFECTED",
                world(AFFECTED_VERSION, true, true, "PRODUCTION", "HIGH",
                        AFFECTED_VERSION),
                SPECIFIC_CLAIM_AFFECTED));

        // The canonical conflict, kept here so the grading set contains it.
        cases.put("CLAIM-AFFECTED-RUNTIME-UNAFFECTED", scenario("CLAIM-AFFECTED-RUNTIME-UNAFFECTED",
                world(UNAFFECTED_VERSION, true, true, "PRODUCTION", "HIGH",
                        AFFECTED_VERSION),
                SPECIFIC_CLAIM_AFFECTED));

        cases.put("UNAFFECTED-INTERNAL-DEV", scenario("UNAFFECTED-INTERNAL-DEV",
                world(UNAFFECTED_VERSION, false, false, "DEVELOPMENT", "LOW", null),
                VAGUE_CLAIM));

        return cases;
    }

    /** Edge cases by name, for parameterised tests. */
    public static List<Scenario> edgeCaseList() {
        return List.copyOf(edgeCases().values());
    }

    /** The risk matrix plus the edge cases: the whole grading set. */
    public static List<Scenario> gradingSet() {
        List<Scenario> all = new ArrayList<>(fullRiskMatrix());
        all.addAll(edgeCaseList());
        return List.copyOf(all);
    }

    /** The three canonical demo scenarios, as library entries. */
    public static List<Scenario> canonical() {
        return List.of(
                new Scenario("CONFIRMED_VULNERABLE", Scenarios.confirmedVulnerableCase(),
                        Scenarios.confirmedVulnerableWorld(), Scenarios.POSITIVE_SCANNER_CLAIM),
                new Scenario("NOT_AFFECTED", Scenarios.notAffectedCase(),
                        Scenarios.notAffectedWorld(), Scenarios.NEGATIVE_SCANNER_CLAIM),
                new Scenario("EVIDENCE_CONFLICT", Scenarios.evidenceConflictCase(),
                        Scenarios.evidenceConflictWorld(), Scenarios.CONFLICT_SCANNER_CLAIM));
    }

    private ScenarioLibrary() {
    }
}
