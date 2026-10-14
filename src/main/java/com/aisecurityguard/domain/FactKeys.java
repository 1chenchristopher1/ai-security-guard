package com.aisecurityguard.domain;

/**
 * Canonical keys for values stored in {@link CaseFacts}.
 *
 * <p>Centralised so the simulated tools (which write facts) and the decision policy (which reads
 * them) cannot drift apart over a typo. In the target architecture these become the typed fact
 * keys of the case projection.
 */
public final class FactKeys {

    /** Observed runtime version of the target service, e.g. {@code "2.4.49"}. */
    public static final String RUNTIME_VERSION = "runtimeVersion";

    /** Whether the CVE is listed as a known exploited vulnerability. Boolean. */
    public static final String KNOWN_EXPLOITED = "knownExploited";

    /** Result of a safe vulnerability validation attempt. String, e.g. {@code "INCONCLUSIVE"}. */
    public static final String VALIDATION_RESULT = "validationResult";

    /** Nested map describing the asset: internetFacing, environment, businessCriticality. */
    public static final String ASSET_CONTEXT = "asset";

    // ---- keys inside the nested ASSET_CONTEXT map ----

    public static final String ASSET_INTERNET_FACING = "internetFacing";
    public static final String ASSET_ENVIRONMENT = "environment";
    public static final String ASSET_BUSINESS_CRITICALITY = "businessCriticality";

    /** The version the scanner explicitly claimed, when it made a specific claim. */
    public static final String SCANNER_CLAIMED_VERSION = "scannerClaimedVersion";

    private FactKeys() {
    }
}
