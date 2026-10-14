package com.aisecurityguard.model;

/**
 * A language model, as far as the agent is concerned.
 *
 * <p>This is the seam between the investigation workflow and whichever model is configured. It is
 * one method wide on purpose: everything interesting - prompt construction, output parsing,
 * grounding validation - lives on the agent side where it can be tested without a network call.
 */
public interface ModelClient {

    /**
     * Sends a request and returns the reply.
     *
     * @throws ModelUnavailableException when the model cannot be reached, is not configured, or
     *                                   returns something unusable. Callers must degrade safely:
     *                                   an unreachable model must never be read as "no
     *                                   vulnerability".
     */
    ModelResponse complete(ModelRequest request);
}
