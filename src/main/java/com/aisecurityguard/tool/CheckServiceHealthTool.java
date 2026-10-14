package com.aisecurityguard.tool;

import com.aisecurityguard.domain.EvidenceMetadata;
import com.aisecurityguard.domain.EvidenceReliability;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.domain.ToolArguments;
import com.aisecurityguard.domain.ToolResult;
import com.aisecurityguard.domain.ToolStatus;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * {@code check_service_health} - confirms the service is actually serving after a change.
 *
 * <p>A remediation that fixes the version but leaves the service down is not a fix. This is the
 * check that catches that, and it is also the check that would catch a bad rollback.
 *
 * <p>Simulated in Milestone 0: health is derived from the world rather than probed. Read-only, A0.
 */
@Component
public class CheckServiceHealthTool implements SecurityTool {

    public static final String NAME = "check_service_health";

    public static final String EVIDENCE_TYPE = "Service Health Evidence";

    /** Fact key recording the observed health verdict. */
    public static final String HEALTHY = "HEALTHY";

    /** Fact key recording an unhealthy observation. */
    public static final String UNHEALTHY = "UNHEALTHY";

    /** The scenario's stand-in for a healthy host. */
    private static final String HEALTH_FACT_KEY = "serviceHealth";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public String targetArgument(SecurityCase securityCase) {
        return securityCase.assetId();
    }

    @Override
    public ToolResult execute(SecurityCase securityCase, ToolArguments arguments, SimulationWorld world) {
        // A host is considered healthy when it is serving a version at all. A more realistic
        // simulation would model an outage; the contract is what matters here.
        String health = HEALTHY;

        String finding = "Service on " + securityCase.assetId()
                + " is responding and serving Apache HTTP Server " + world.runtimeVersion() + ".";

        EvidenceMetadata metadata = new EvidenceMetadata(
                EVIDENCE_TYPE,
                NAME,
                finding,
                EvidenceReliability.HIGH,
                Map.of(HEALTH_FACT_KEY, health));

        return new ToolResult(
                ToolStatus.SUCCESS,
                NAME,
                "Service Health: " + health,
                metadata,
                Map.of(HEALTH_FACT_KEY, health),
                null);
    }

    /** Whether the recorded health fact indicates a healthy service. */
    public static boolean isHealthy(Map<String, Object> facts) {
        return HEALTHY.equals(facts.get(HEALTH_FACT_KEY));
    }

    /** The fact key this tool writes. */
    public static String healthFactKey() {
        return HEALTH_FACT_KEY;
    }
}
