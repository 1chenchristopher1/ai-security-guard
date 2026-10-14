package com.aisecurityguard.remediation;

import com.aisecurityguard.approval.ApprovedExecution;
import com.aisecurityguard.audit.AuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.domain.AuditActors;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.SimulationWorld;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Executes an approved remediation as a controlled, narrated sequence of steps.
 *
 * <p>Mirrors the prototype's remediation flow - create a backup, apply the predefined action,
 * restart the service, check availability - but unlike the prototype it cannot run without an
 * {@link ApprovedExecution}.
 *
 * <p>Two properties are worth noting:
 * <ul>
 *   <li><b>Backup before change.</b> The plan promises a backup, so a backup happens and its
 *       reference is recorded. A promised safety measure that is not taken is worse than none,
 *       because the approver relied on it.</li>
 *   <li><b>The observed world is not mutated.</b> The post-fix state is a new world, so the world
 *       the assessment was formed against remains intact for the audit trail.</li>
 * </ul>
 */
@Component
public class ControlledRemediationExecutor implements RemediationExecutor {

    private final RemediationActionCatalog catalog;
    private final AuditLog auditLog;
    private final SimulationClock clock;

    public ControlledRemediationExecutor(RemediationActionCatalog catalog,
                                         AuditLog auditLog,
                                         SimulationClock clock) {
        this.catalog = Objects.requireNonNull(catalog);
        this.auditLog = Objects.requireNonNull(auditLog);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public RemediationOutcome execute(SecurityCase securityCase, ApprovedExecution execution,
                                      SimulationWorld world) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        Objects.requireNonNull(execution, "an approved execution is required to remediate");
        Objects.requireNonNull(world, "world must not be null");

        checkNothingAlreadyExecuted(securityCase);

        // Only a catalogued action may run. This throws if the vulnerability has no predefined
        // remediation, which is the intended behaviour: no action is safer than an improvised one.
        RemediationActionCatalog.RemediationAction action = catalog.resolveFor(securityCase);

        securityCase.moveTo(CaseLifecycle.REMEDIATING);
        // The approval itself was recorded by the gate when the human decided; here we record
        // that an approved action is now actually being applied.
        auditLog.append(securityCase.caseId(), AuditActors.SYSTEM, "REMEDIATION_STARTED",
                action.actionId() + " | " + action.description()
                        + " | authorised by " + execution.approverId());

        List<String> steps = new ArrayList<>();

        // 1. Backup. The approval screen promised this, so it is not optional.
        String backupReference = "backup-" + securityCase.caseId() + "-" + clock.tick();
        steps.add("Creating backup...");
        auditLog.append(securityCase.caseId(), AuditActors.SYSTEM, "REMEDIATION_STEP",
                "Creating backup... | " + backupReference);

        // 2. Apply the predefined action.
        steps.add("Executing predefined remediation...");
        auditLog.append(securityCase.caseId(), AuditActors.SYSTEM, "REMEDIATION_STEP",
                "Executing predefined remediation... | " + action.actionId());

        SimulationWorld postFixWorld = catalog.apply(action, world);

        // 3. Restart.
        steps.add("Restarting service...");
        auditLog.append(securityCase.caseId(), AuditActors.SYSTEM, "REMEDIATION_STEP",
                "Restarting service... | " + securityCase.assetId());

        // 4. Availability check.
        steps.add("Checking service availability...");
        auditLog.append(securityCase.caseId(), AuditActors.SYSTEM, "REMEDIATION_STEP",
                "Checking service availability... | " + securityCase.assetId());

        auditLog.append(securityCase.caseId(), AuditActors.SYSTEM, "REMEDIATION_EXECUTED",
                action.actionId() + " | SUCCESS");

        return new RemediationOutcome(
                securityCase.caseId(),
                action.actionId(),
                List.copyOf(steps),
                postFixWorld,
                backupReference,
                execution.approverId());
    }

    /**
     * Refuses to remediate a case that is already past remediation.
     *
     * <p>Combined with single-use approval tokens, this means one approval cannot drive two
     * executions even if a caller reuses the outcome.
     */
    private void checkNothingAlreadyExecuted(SecurityCase securityCase) {
        if (securityCase.lifecycle().isRemediationStage()) {
            throw new IllegalStateException(
                    "case " + securityCase.caseId() + " is already in lifecycle "
                            + securityCase.lifecycle() + " and cannot be remediated again");
        }
    }
}
