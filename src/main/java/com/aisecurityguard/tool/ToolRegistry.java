package com.aisecurityguard.tool;

import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.domain.ToolArguments;
import com.aisecurityguard.domain.ToolResult;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The tools available to the agent.
 *
 * <p>Discovery is by tool name, because the decision policy selects capabilities by name. A
 * misconfigured policy fails loudly here rather than silently doing nothing.
 *
 * <p>This is the Milestone 0 stand-in for the proposal's capability registry: in the target
 * architecture PF4J discovers plugins, and availability is further restricted by allowlist, scope
 * and case context. Requesting a tool that is not registered is a hard error, which is the
 * behaviour the policy-layer allowlist will later generalise.
 */
@Component
public class ToolRegistry {

    private final Map<String, SecurityTool> toolsByName;

    public ToolRegistry(List<SecurityTool> tools) {
        Map<String, SecurityTool> byName = new LinkedHashMap<>();
        for (SecurityTool tool : tools) {
            SecurityTool previous = byName.put(tool.name(), tool);
            if (previous != null) {
                throw new IllegalStateException(
                        "duplicate security tool registration for name '" + tool.name() + "'");
            }
        }
        this.toolsByName = Map.copyOf(byName);
    }

    /** Convenience factory for tests and programmatic wiring. */
    public static ToolRegistry of(SecurityTool... tools) {
        return new ToolRegistry(List.of(tools));
    }

    public boolean contains(String toolName) {
        return toolName != null && toolsByName.containsKey(toolName);
    }

    /**
     * Looks up a tool.
     *
     * @throws IllegalArgumentException if no such tool is registered
     */
    public SecurityTool require(String toolName) {
        SecurityTool tool = toolName == null ? null : toolsByName.get(toolName);
        if (tool == null) {
            throw new IllegalArgumentException(
                    "no security tool registered under name '" + toolName + "'. Available: "
                            + toolsByName.keySet());
        }
        return tool;
    }

    public Optional<SecurityTool> find(String toolName) {
        return toolName == null ? Optional.empty() : Optional.ofNullable(toolsByName.get(toolName));
    }

    /** Builds the argument set for a tool invocation, using the tool's own target choice. */
    public ToolArguments argumentsFor(String toolName, SecurityCase securityCase) {
        return ToolArguments.of(require(toolName).targetArgument(securityCase));
    }

    /** Registered tool names. */
    public Set<String> toolNames() {
        return toolsByName.keySet();
    }

    public int size() {
        return toolsByName.size();
    }
}
