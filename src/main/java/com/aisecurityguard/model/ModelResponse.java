package com.aisecurityguard.model;

/**
 * A language model reply.
 *
 * @param content      the assistant's text, expected to be a JSON object for decision requests
 * @param model        the model identifier that actually served the request
 * @param totalTokens  tokens consumed, for cost visibility
 * @param finishReason why generation stopped; {@code length} means the reply was truncated and
 *                     therefore cannot be trusted as a complete decision
 */
public record ModelResponse(
        String content,
        String model,
        int totalTokens,
        String finishReason) {

    public ModelResponse {
        if (content == null) {
            throw new IllegalArgumentException("model response content must not be null");
        }
    }

    /** True when the reply was cut off, so any JSON in it is incomplete. */
    public boolean isTruncated() {
        return "length".equalsIgnoreCase(finishReason);
    }
}
