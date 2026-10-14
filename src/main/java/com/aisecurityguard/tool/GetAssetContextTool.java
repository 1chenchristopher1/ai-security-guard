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
 * {@code get_asset_context} - how exposed and how important the asset is.
 *
 * <p>Exposure and business criticality are what separate "fix it eventually" from "fix it now".
 * Read-only, A0. In the target architecture this reads the CMDB.
 */
@Component
public class GetAssetContextTool implements SecurityTool {

    public static final String NAME = "get_asset_context";

    public static final String EVIDENCE_TYPE = "Asset Context Evidence";

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
        Map<String, Object> assetFacts = world.assetContextFacts();

        String summary = "Internet Facing: " + (world.internetFacing() ? "YES" : "NO")
                + " | " + world.environment()
                + " | Criticality " + world.businessCriticality();

        String finding = "Internet-facing: " + (world.internetFacing() ? "YES" : "NO")
                + ". Environment: " + world.environment()
                + ". Business criticality: " + world.businessCriticality() + ".";

        EvidenceMetadata metadata = new EvidenceMetadata(
                EVIDENCE_TYPE,
                NAME,
                finding,
                EvidenceReliability.HIGH,
                Map.of(FactKeys.ASSET_CONTEXT, assetFacts));

        return new ToolResult(
                ToolStatus.SUCCESS,
                NAME,
                summary,
                metadata,
                Map.of(FactKeys.ASSET_CONTEXT, assetFacts),
                null);
    }
}
