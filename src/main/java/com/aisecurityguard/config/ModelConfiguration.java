package com.aisecurityguard.config;

import com.aisecurityguard.model.DeepSeekModelClient;
import com.aisecurityguard.model.ModelClient;
import com.aisecurityguard.model.ModelProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the language model provider.
 *
 * <p>The API key is read once, from the environment, inside {@link ModelProperties#fromEnvironment}.
 * It is never written to a file and never logged: {@link ModelProperties#toString} redacts it, so
 * even an accidental log statement cannot leak it.
 *
 * <p>No API key is not an error condition. The application starts, the reference policy works, and
 * any attempt to use the model fails with an actionable message rather than a null pointer.
 */
@Configuration
public class ModelConfiguration {

    private static final Logger log = LoggerFactory.getLogger(ModelConfiguration.class);

    @Bean
    public ModelProperties modelProperties() {
        ModelProperties properties = ModelProperties.fromEnvironment();
        log.info("model provider configured: {}", properties);
        if (!properties.hasApiKey()) {
            log.warn("{} is not set. The LLM agent cannot run; the reference policy remains "
                            + "available and any LLM decision will escalate to human review.",
                    ModelProperties.API_KEY_ENV_VAR);
        }
        return properties;
    }

    @Bean
    public ModelClient modelClient(ModelProperties properties, ObjectMapper objectMapper) {
        return new DeepSeekModelClient(properties, objectMapper);
    }
}
