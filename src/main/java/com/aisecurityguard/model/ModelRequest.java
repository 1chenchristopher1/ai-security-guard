package com.aisecurityguard.model;

import java.util.List;

/**
 * A request to a language model.
 *
 * <p>{@code temperature} is fixed low and {@code jsonResponse} is on for every decision request:
 * the agent needs reproducible, machine-parseable verdicts, not creative prose. A model that
 * cannot be parsed is not making a decision, it is producing text.
 *
 * @param systemPrompt   the standing instructions
 * @param messages       the conversation so far, oldest first
 * @param temperature    sampling temperature; low for determinism
 * @param jsonResponse   whether to request a JSON-object response
 * @param maxTokens      upper bound on the reply length
 */
public record ModelRequest(
        String systemPrompt,
        List<ModelMessage> messages,
        double temperature,
        boolean jsonResponse,
        int maxTokens) {

    /** Temperature used for all decision requests. */
    public static final double DECISION_TEMPERATURE = 0.0;

    public ModelRequest {
        if (systemPrompt == null || systemPrompt.isBlank()) {
            throw new IllegalArgumentException("a model request needs a system prompt");
        }
        messages = messages == null ? List.of() : List.copyOf(messages);
        if (messages.isEmpty()) {
            throw new IllegalArgumentException("a model request needs at least one message");
        }
        if (temperature < 0.0 || temperature > 2.0) {
            throw new IllegalArgumentException("temperature must be between 0 and 2");
        }
        if (maxTokens < 1) {
            throw new IllegalArgumentException("maxTokens must be positive");
        }
    }
}
