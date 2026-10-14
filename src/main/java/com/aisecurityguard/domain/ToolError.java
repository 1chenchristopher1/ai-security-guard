package com.aisecurityguard.domain;

/**
 * Error detail for a tool call that did not return {@link ToolStatus#SUCCESS}.
 *
 * @param code    short machine-readable code, e.g. {@code VALIDATION_INCONCLUSIVE}
 * @param message human-readable explanation
 */
public record ToolError(String code, String message) {

    public ToolError {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("tool error code must not be blank");
        }
        if (message == null || message.isBlank()) {
            throw new IllegalArgumentException("tool error message must not be blank");
        }
    }
}
