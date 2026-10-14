package com.aisecurityguard.config;

import com.aisecurityguard.audit.AuditLog;
import com.aisecurityguard.audit.InMemoryAuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.casefile.CaseRepository;
import com.aisecurityguard.casefile.InMemoryCaseRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the pieces that are plain objects rather than components.
 *
 * <p>Deliberately tiny. The tools, the decision policy, the registry, the loop and the workflow
 * service are {@code @Component}s; only the clock, the audit log and case storage are constructed
 * here, because they carry mutable session state and a later milestone will replace their
 * implementations.
 */
@Configuration
public class HarnessConfiguration {

    @Bean
    public SimulationClock simulationClock() {
        return new SimulationClock();
    }

    @Bean
    public AuditLog auditLog(SimulationClock clock) {
        return new InMemoryAuditLog(clock);
    }

    /**
     * Case storage. In memory for now, but behind an interface so the workflow service no longer
     * owns case state - which is what allows a case to be loaded and continued rather than only
     * handled inside one method call.
     */
    @Bean
    public CaseRepository caseRepository() {
        return new InMemoryCaseRepository();
    }
}
