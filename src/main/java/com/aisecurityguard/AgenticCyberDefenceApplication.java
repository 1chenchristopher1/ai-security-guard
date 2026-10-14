package com.aisecurityguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * AI Security Guard - Agentic Cyber Defence.
 *
 * <p>Milestone 0: a deterministic, headless reference implementation of the investigation
 * workflow defined by {@code prototype/agentic-cyber-defence-prototype.html}.
 *
 * <p>There is deliberately no web layer, no LLM, no database and no external integration yet.
 * The purpose of this module is to fix the <em>behavioural contract</em> - the agent decision
 * loop, the evidence model, the tool system and the audit trail - so that later milestones can
 * replace {@link com.aisecurityguard.agent.ReferenceDecisionPolicy} with a real LLM agent and be
 * compared against it, decision for decision.
 */
@SpringBootApplication
public class AgenticCyberDefenceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AgenticCyberDefenceApplication.class, args);
    }
}
