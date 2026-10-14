package com.aisecurityguard.model;

/**
 * Raised when the model layer cannot produce a usable reply.
 *
 * <p>This is a distinct failure mode from "the model said something we did not like". It means no
 * reply was obtained at all - no API key, no connectivity, a timeout, a server error, a truncated
 * response. The agent runtime treats it as a reason to stop and hand the case to a human, never as
 * evidence about the vulnerability.
 */
public class ModelUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ModelUnavailableException(String message) {
        super(message);
    }

    public ModelUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
