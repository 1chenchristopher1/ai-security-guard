package com.aisecurityguard.tool;

import com.aisecurityguard.domain.EvidenceMetadata;
import com.aisecurityguard.domain.EvidenceReliability;
import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.domain.ToolArguments;
import com.aisecurityguard.domain.ToolResult;
import com.aisecurityguard.domain.ToolStatus;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * {@code inspect_service} - reads the version actually running on the target asset.
 *
 * <p>This single capability is what breaks the scanner's authority: it replaces "the scanner says
 * the version is X" with "the runtime is X". It is read-only and always A0.
 *
 * <p>Simulated in Milestone 0 (reads {@link SimulationWorld}); in the target architecture this
 * inspects a real service inside the Docker lab.
 */
@Component
public class InspectServiceTool implements SecurityTool {

    public static final String NAME = "inspect_service";

    public static final String EVIDENCE_TYPE = "Runtime Service Evidence";

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
        String runtime = world.runtimeVersion();

        String finding = "Apache HTTP Server " + runtime + " confirmed running on the target asset.";

        EvidenceMetadata metadata = new EvidenceMetadata(
                EVIDENCE_TYPE,
                NAME,
                finding,
                EvidenceReliability.HIGH,
                Map.of(FactKeys.RUNTIME_VERSION, runtime));

        return new ToolResult(
                ToolStatus.SUCCESS,
                NAME,
                "Apache HTTP Server " + runtime,
                metadata,
                Map.of(FactKeys.RUNTIME_VERSION, runtime),
                null);
    }
}
