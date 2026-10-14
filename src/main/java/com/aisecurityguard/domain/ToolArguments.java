package com.aisecurityguard.domain;

import java.util.Map;

/**
 * Arguments passed to a tool call, split into a primary target and structured extras.
 *
 * <p>The primary target is overloaded by design and mirrors the prototype (which passes the CVE
 * for {@code lookup_kev} and the asset for everything else): each tool decides what its own target
 * argument means via {@link com.aisecurityguard.tool.SecurityTool#targetArgument}.
 *
 * @param target the tool's primary argument, e.g. an asset ID or a CVE ID
 * @param extras additional structured arguments
 */
public record ToolArguments(String target, Map<String, Object> extras) {

    public ToolArguments {
        if (target == null || target.isBlank()) {
            throw new IllegalArgumentException("tool argument target must not be blank");
        }
        extras = extras == null ? Map.of() : Map.copyOf(extras);
    }

    /** Arguments carrying only a primary target. */
    public static ToolArguments of(String target) {
        return new ToolArguments(target, Map.of());
    }

    /** Renders the argument for audit output, e.g. {@code inspect_service(customer-portal-prod-01)}. */
    public String describe(String toolName) {
        return toolName + "(" + target + ")";
    }
}
