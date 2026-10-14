package com.aisecurityguard.model;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the model provider.
 *
 * <p>The API key is read from the {@code DEEPSEEK_API_KEY} environment variable and is never
 * written to a file, logged, or included in an error message. A missing key is a normal,
 * recoverable condition: the harness starts, and any attempt to use the model fails with a clear
 * message rather than a stack trace about a null pointer.
 *
 * @param baseUrl        provider base URL
 * @param model          model identifier to request
 * @param apiKey         secret; must never be logged
 * @param timeoutSeconds per-request timeout
 */
@ConfigurationProperties(prefix = "aisecurityguard.model")
public record ModelProperties(
        String baseUrl,
        String model,
        String apiKey,
        int timeoutSeconds) {

    /** Default provider endpoint. */
    public static final String DEFAULT_BASE_URL = "https://api.deepseek.com";

    /** Default model identifier. */
    public static final String DEFAULT_MODEL = "deepseek-chat";

    /** Default request timeout, generous enough for reasoning models. */
    public static final int DEFAULT_TIMEOUT_SECONDS = 120;

    /** Environment variable the API key is read from. */
    public static final String API_KEY_ENV_VAR = "DEEPSEEK_API_KEY";

    public ModelProperties {
        baseUrl = baseUrl == null || baseUrl.isBlank() ? DEFAULT_BASE_URL : baseUrl;
        model = model == null || model.isBlank() ? DEFAULT_MODEL : model;
        if (timeoutSeconds <= 0) {
            timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
        }
    }

    /**
     * Loads configuration from the environment.
     *
     * <p>The key is read here and nowhere else, so there is a single place to audit.
     */
    public static ModelProperties fromEnvironment() {
        return new ModelProperties(
                System.getenv().getOrDefault("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL),
                System.getenv().getOrDefault("DEEPSEEK_MODEL", DEFAULT_MODEL),
                System.getenv(API_KEY_ENV_VAR),
                DEFAULT_TIMEOUT_SECONDS);
    }

    /** True when an API key is configured. */
    public boolean hasApiKey() {
        return apiKey != null && !apiKey.isBlank();
    }

    /** A description safe to log: everything except the secret. */
    @Override
    public String toString() {
        return "ModelProperties[baseUrl=" + baseUrl
                + ", model=" + model
                + ", apiKey=" + (hasApiKey() ? "***set***" : "***missing***")
                + ", timeoutSeconds=" + timeoutSeconds + "]";
    }
}
