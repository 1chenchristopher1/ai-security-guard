package com.aisecurityguard.tool;

import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.domain.ToolArguments;
import com.aisecurityguard.domain.ToolResult;

/**
 * A capability the agent may invoke.
 *
 * <p>This is the seam along which simulation is replaced by reality. In Milestone 0 every
 * implementation is deterministic and reads from {@link SimulationWorld}; in the target
 * architecture these become PF4J extension plugins that talk to a Docker lab, CISA KEV and vendor
 * advisories. The interface - and therefore the investigation loop - does not change.
 *
 * <p>There is deliberately no shell, file-write or arbitrary command capability anywhere in this
 * interface, and none may be added: the agent gets named, typed capabilities or nothing.
 */
public interface SecurityTool {

    /** Stable identifier used by the decision policy, e.g. {@code inspect_service}. */
    String name();

    /**
     * The tool's own primary argument for this case.
     *
     * <p>Lets the registry stay generic: a threat-intelligence tool wants the CVE, an
     * asset-inspection tool wants the asset. The prototype encoded this as an inline special case
     * ({@code d.tool==='lookup_kev' ? 'CVE-...' : s.asset}).
     */
    String targetArgument(SecurityCase securityCase);

    /**
     * Executes the capability.
     *
     * <p>Implementations must return a {@link ToolResult} even on failure - never throw - because
     * a failed tool has to produce evidence and be visible in the audit trail.
     */
    ToolResult execute(SecurityCase securityCase, ToolArguments arguments, SimulationWorld world);
}
