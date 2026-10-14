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
 * {@code lookup_kev} - external exploitation intelligence (CISA Known Exploited Vulnerabilities).
 *
 * <p>Answers "is this being exploited in the wild", which is what turns a confirmed vulnerable
 * version into an urgent one. Read-only, A0. In the target architecture this calls the real KEV
 * feed; here it reads the world.
 */
@Component
public class LookupKevTool implements SecurityTool {

    public static final String NAME = "lookup_kev";

    public static final String EVIDENCE_TYPE = "Threat Intelligence Evidence";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public String targetArgument(SecurityCase securityCase) {
        // threat intelligence is keyed by the vulnerability, not the asset
        return securityCase.cveId();
    }

    @Override
    public ToolResult execute(SecurityCase securityCase, ToolArguments arguments, SimulationWorld world) {
        boolean knownExploited = world.knownExploited();

        String summary = knownExploited
                ? "MATCH FOUND | CISA Known Exploited Vulnerabilities"
                : "NO MATCH";
        String finding = knownExploited
                ? securityCase.cveId() + " is listed as a known exploited vulnerability."
                : securityCase.cveId() + " is not listed as exploited.";

        EvidenceMetadata metadata = new EvidenceMetadata(
                EVIDENCE_TYPE,
                "CISA KEV",
                finding,
                EvidenceReliability.HIGH,
                Map.of(FactKeys.KNOWN_EXPLOITED, knownExploited));

        return new ToolResult(
                ToolStatus.SUCCESS,
                NAME,
                summary,
                metadata,
                Map.of(FactKeys.KNOWN_EXPLOITED, knownExploited),
                null);
    }
}
