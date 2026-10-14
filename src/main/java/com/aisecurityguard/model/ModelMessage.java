package com.aisecurityguard.model;

import java.util.List;

/**
 * A single message in a model conversation.
 *
 * <p>Deliberately provider-neutral: the investigation logic must not know whether it is talking to
 * an OpenAI-compatible endpoint or something else, because the choice of model is a deployment
 * decision rather than a design one.
 *
 * @param role    who produced the message
 * @param content the message body
 */
public record ModelMessage(Role role, String content) {

    /** Conversation roles. */
    public enum Role {
        SYSTEM,
        USER,
        ASSISTANT
    }

    public ModelMessage {
        if (role == null) {
            throw new IllegalArgumentException("message role must not be null");
        }
        if (content == null) {
            throw new IllegalArgumentException("message content must not be null");
        }
    }

    public static ModelMessage system(String content) {
        return new ModelMessage(Role.SYSTEM, content);
    }

    public static ModelMessage user(String content) {
        return new ModelMessage(Role.USER, content);
    }

    public static ModelMessage assistant(String content) {
        return new ModelMessage(Role.ASSISTANT, content);
    }
}
