package com.aisecurityguard.tool;

import java.util.Map;
import java.util.Set;

/**
 * The simulated environment the tools observe - effectively the lab.
 *
 * <p>This is where all scenario-specific state lives. The investigation loop and the decision
 * policy never branch on which scenario is running: they only see tool results created from
 * whatever world they were handed. Swapping this record for a Docker Compose lab is the whole of
 * the Milestone 1 environment change.
 *
 * <p>Fields are grouped by which simulated tool reads them:
 * <ul>
 *   <li>{@link #runtimeVersion} - observed at runtime by {@code inspect_service}</li>
 *   <li>{@link #knownExploited} - external intelligence read by {@code lookup_kev}</li>
 *   <li>{@link #internetFacing}, {@link #environment}, {@link #businessCriticality} - read by
 *       {@code get_asset_context}</li>
 *   <li>{@link #vulnerableRuntimeVersions} - the applicability rule used by
 *       {@code validate_vulnerability}</li>
 *   <li>{@link #scannerClaimedVersion} - what the scanner explicitly claimed, if anything. This is
 *       an input to the <em>workflow</em>, not to any tool: it is what makes a claim checkable
 *       against runtime reality.</li>
 * </ul>
 *
 * @param runtimeVersion           the version actually running on the asset
 * @param knownExploited           whether the CVE is a known exploited vulnerability
 * @param internetFacing           whether the service is reachable from the internet
 * @param environment              deployment environment, e.g. {@code PRODUCTION}
 * @param businessCriticality      business criticality, e.g. {@code HIGH}
 * @param vulnerableRuntimeVersions runtime versions affected by this CVE
 * @param scannerClaimedVersion    the exact version the scanner claimed, or {@code null}
 */
public record SimulationWorld(
        String runtimeVersion,
        boolean knownExploited,
        boolean internetFacing,
        String environment,
        String businessCriticality,
        Set<String> vulnerableRuntimeVersions,
        String scannerClaimedVersion) {

    public SimulationWorld {
        if (runtimeVersion == null || runtimeVersion.isBlank()) {
            throw new IllegalArgumentException("runtimeVersion must not be blank");
        }
        if (environment == null || environment.isBlank()) {
            throw new IllegalArgumentException("environment must not be blank");
        }
        if (businessCriticality == null || businessCriticality.isBlank()) {
            throw new IllegalArgumentException("businessCriticality must not be blank");
        }
        vulnerableRuntimeVersions = vulnerableRuntimeVersions == null
                ? Set.of()
                : Set.copyOf(vulnerableRuntimeVersions);
    }

    /** True when the running version is affected by the CVE. The applicability rule. */
    public boolean isRuntimeAffected() {
        return vulnerableRuntimeVersions.contains(runtimeVersion);
    }

    /**
     * The state of the world after a remediation was applied.
     *
     * <p>Returns a new instance rather than mutating: the world the investigation observed has to
     * stay exactly as it was when the assessment was formed, or the audit trail would describe a
     * machine that never existed. Verification is then able to observe the <em>changed</em> world,
     * which is what makes it a real check rather than a formality.
     *
     * @param patchedRuntimeVersion the version now running
     * @return a world representing the patched host
     */
    public SimulationWorld withRuntimeVersion(String patchedRuntimeVersion) {
        return new SimulationWorld(
                patchedRuntimeVersion,
                knownExploited,
                internetFacing,
                environment,
                businessCriticality,
                vulnerableRuntimeVersions,
                scannerClaimedVersion);
    }

    /**
     * True when the scanner made a specific version claim that runtime inspection contradicts.
     * This is the trigger for seeking independent verification.
     */
    public boolean hasVersionConflict() {
        return scannerClaimedVersion != null
                && !scannerClaimedVersion.isBlank()
                && !scannerClaimedVersion.equals(runtimeVersion);
    }

    /** The nested asset-context fact map produced by {@code get_asset_context}. */
    public Map<String, Object> assetContextFacts() {
        return Map.of(
                "internetFacing", internetFacing,
                "environment", environment,
                "businessCriticality", businessCriticality);
    }
}
