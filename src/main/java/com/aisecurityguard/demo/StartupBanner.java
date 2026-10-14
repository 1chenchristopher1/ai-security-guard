package com.aisecurityguard.demo;

import com.aisecurityguard.agent.DecisionPolicy;
import com.aisecurityguard.agent.llm.LlmDecisionPolicy;
import com.aisecurityguard.model.ModelProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Prints where the application is and what it is configured to do, once it is listening.
 *
 * <p>Small, but the difference between a demo that works and one that looks broken: the URL is
 * printed in a form that can be clicked, and the configuration that matters (which decision maker
 * is active) is stated rather than left to be discovered.
 */
@Component
public class StartupBanner {

    private static final Logger log = LoggerFactory.getLogger(StartupBanner.class);

    private final DecisionPolicy decisionPolicy;
    private final Environment environment;

    public StartupBanner(DecisionPolicy decisionPolicy, Environment environment) {
        this.decisionPolicy = decisionPolicy;
        this.environment = environment;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void announce() {
        String port = environment.getProperty("server.port", "8080");
        String address = environment.getProperty("server.address", "localhost");

        String decisionMaker = decisionPolicy instanceof LlmDecisionPolicy
                ? "live language model"
                : "reference policy (deterministic)";

        ModelProperties model = ModelProperties.fromEnvironment();

        log.info("");
        log.info("  AI Security Guard is running");
        log.info("  ------------------------------------------------");
        log.info("  Open:        http://{}:{}", address, port);
        log.info("  Decision:    {}", decisionMaker);
        if (decisionPolicy instanceof LlmDecisionPolicy) {
            log.info("  Model:       {} at {}", model.model(), model.baseUrl());
        } else {
            log.info("  Starting with the live model instead:");
            log.info("    mvnw.cmd spring-boot:run -Dspring-boot.run.arguments=--aisecurityguard.agent.policy=llm");
        }
        log.info("  Note:        bound to {} only, no authentication - demo use", address);
        log.info("");
    }
}
