package com.aisecurityguard.api;

import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.scenario.Scenarios;
import com.aisecurityguard.tool.SimulationWorld;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The demo scenarios the page can open, with what each one is meant to show.
 *
 * <p>Kept server-side rather than in the page so the UI cannot invent a scenario the backend does
 * not have, and so the set of demonstrable behaviours is defined in one auditable place.
 */
public final class ScenarioCatalog {

    /** A scenario: its identity, the world it runs against, and what it demonstrates. */
    public record Entry(
            String key,
            String label,
            String assetId,
            String scannerClaim,
            String expectedOutcome,
            SimulationWorld world) {

        /** A fresh case for this scenario. A new one every time, so runs never share state. */
        public SecurityCase newCase() {
            String caseId = switch (key) {
                case "confirmed-vulnerable" -> "CASE-VUL-001";
                case "not-affected" -> "CASE-VUL-002";
                case "evidence-conflict" -> "CASE-VUL-003";
                default -> "CASE-" + key.toUpperCase(java.util.Locale.ROOT);
            };
            return new SecurityCase(caseId, assetId, "CVE-2021-41773");
        }
    }

    private static final Map<String, Entry> ENTRIES = new LinkedHashMap<>();

    static {
        register(new Entry(
                "confirmed-vulnerable",
                "Confirmed vulnerable",
                "customer-portal-prod-01",
                Scenarios.POSITIVE_SCANNER_CLAIM,
                "The affected version really is running on an exposed production asset with known "
                        + "exploitation. Expect CONFIRMED_VULNERABLE at P0, and a remediation "
                        + "proposal that needs your approval.",
                Scenarios.confirmedVulnerableWorld()));

        register(new Entry(
                "not-affected",
                "Not affected",
                "internal-wiki-staging-02",
                Scenarios.NEGATIVE_SCANNER_CLAIM,
                "The scanner raised a finding but named no version, and the runtime is unaffected. "
                        + "Expect the agent to stop early and dismiss the finding, with no action "
                        + "proposed and no approval requested.",
                Scenarios.notAffectedWorld()));

        register(new Entry(
                "evidence-conflict",
                "Evidence conflict",
                "partner-api-prod-03",
                Scenarios.CONFLICT_SCANNER_CLAIM,
                "The scanner claims a specific affected version, the runtime shows a different one, "
                        + "and independent validation cannot settle it. Expect UNDETERMINED at C3, "
                        + "an escalation, and automatic remediation blocked.",
                Scenarios.evidenceConflictWorld()));
    }

    private static void register(Entry entry) {
        ENTRIES.put(entry.key(), entry);
    }

    /**
     * Looks up a scenario.
     *
     * @throws IllegalArgumentException if there is no such scenario. The page can only offer what
     *                                  this catalogue contains, so an unknown key means a bug.
     */
    public static Entry require(String key) {
        Entry entry = key == null ? null : ENTRIES.get(key);
        if (entry == null) {
            throw new IllegalArgumentException("unknown scenario '" + key
                    + "'. Available: " + ENTRIES.keySet());
        }
        return entry;
    }

    /** All scenarios, in presentation order. */
    public static List<Entry> all() {
        return List.copyOf(ENTRIES.values());
    }

    /** The default scenario the page opens with. */
    public static Entry defaultScenario() {
        return require("confirmed-vulnerable");
    }

    private ScenarioCatalog() {
    }
}
