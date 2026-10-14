package com.aisecurityguard.verification;

import com.aisecurityguard.audit.AuditLog;
import com.aisecurityguard.audit.SimulationClock;
import com.aisecurityguard.domain.AuditActors;
import com.aisecurityguard.domain.CaseLifecycle;
import com.aisecurityguard.domain.Evidence;
import com.aisecurityguard.domain.EvidenceMetadata;
import com.aisecurityguard.domain.EvidenceReliability;
import com.aisecurityguard.domain.FactKeys;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.domain.ToolResult;
import com.aisecurityguard.tool.CheckServiceHealthTool;
import com.aisecurityguard.tool.InspectServiceTool;
import com.aisecurityguard.tool.SecurityTool;
import com.aisecurityguard.tool.SimulationWorld;
import com.aisecurityguard.tool.ToolRegistry;
import com.aisecurityguard.tool.ValidateVulnerabilityTool;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Verifies a remediation by re-running real checks against the post-fix world.
 *
 * <p>The verification re-uses the same capabilities the investigation used - {@code
 * inspect_service}, {@code validate_vulnerability}, {@code check_service_health} - but against the
 * changed world. That is deliberate and is the point of the check: if verification were a separate
 * hard-coded "all good" path, it would confirm the fix by assuming it.
 *
 * <p>It produces three evidence records, one per check, and passes only if all three pass. The
 * most important consequence: if the target is still running an affected version, verification
 * <em>fails</em> and the case does not resolve.
 */
@Component
public class ToolBasedRemediationVerifier implements RemediationVerifier {

    /** The verification capability reported in the audit trail. */
    public static final String VERIFY_TOOL_NAME = "verify_remediation";

    private final ToolRegistry toolRegistry;
    private final AuditLog auditLog;
    private final SimulationClock clock;

    public ToolBasedRemediationVerifier(ToolRegistry toolRegistry,
                                        AuditLog auditLog,
                                        SimulationClock clock) {
        this.toolRegistry = Objects.requireNonNull(toolRegistry);
        this.auditLog = Objects.requireNonNull(auditLog);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public RemediationVerification verify(SecurityCase securityCase, SimulationWorld postFixWorld) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        Objects.requireNonNull(postFixWorld, "postFixWorld must not be null");

        securityCase.moveTo(CaseLifecycle.VERIFYING);
        auditLog.append(securityCase.caseId(), AuditActors.SECURITY_TOOL, "TOOL_INVOKED",
                VERIFY_TOOL_NAME + "(" + securityCase.assetId() + ")");

        List<RemediationVerification.Check> checks = new ArrayList<>();
        List<String> evidenceIds = new ArrayList<>();

        // Check 1: the patched version is actually running.
        Evidence versionEvidence = runTool(securityCase, postFixWorld,
                InspectServiceTool.NAME, Map.of());
        String observedVersion = postFixWorld.runtimeVersion();
        boolean versionPatched = !postFixWorld.isRuntimeAffected();
        checks.add(new RemediationVerification.Check(
                "Version Check",
                versionPatched ? "PATCHED (" + observedVersion + ")" : "STILL AFFECTED (" + observedVersion + ")",
                versionPatched));
        evidenceIds.add(versionEvidence.evidenceId());

        // Check 2: the vulnerability no longer validates as present.
        Evidence validationEvidence = runTool(securityCase, postFixWorld,
                ValidateVulnerabilityTool.NAME, Map.of());
        String validationResult = String.valueOf(
                validationEvidence.metadata().facts().get(FactKeys.VALIDATION_RESULT));
        boolean notVulnerable = ValidateVulnerabilityTool.isRuledOut(validationResult);
        checks.add(new RemediationVerification.Check(
                "Vulnerability Validation",
                notVulnerable ? "NOT VULNERABLE" : "STILL VULNERABLE",
                notVulnerable));
        evidenceIds.add(validationEvidence.evidenceId());

        // Check 3: the service is still serving.
        Evidence healthEvidence = runTool(securityCase, postFixWorld,
                CheckServiceHealthTool.NAME, Map.of());
        boolean healthy = CheckServiceHealthTool.isHealthy(healthEvidence.metadata().facts());
        checks.add(new RemediationVerification.Check(
                "Service Health",
                healthy ? CheckServiceHealthTool.HEALTHY : CheckServiceHealthTool.UNHEALTHY,
                healthy));
        evidenceIds.add(healthEvidence.evidenceId());

        boolean passed = checks.stream().allMatch(RemediationVerification.Check::passed);

        if (passed) {
            securityCase.moveTo(CaseLifecycle.RESOLVED);
            auditLog.append(securityCase.caseId(), AuditActors.SECURITY_TOOL, "VERIFICATION_PASSED",
                    "Version Check PATCHED | Vulnerability Validation NOT VULNERABLE | "
                            + "Service Health HEALTHY");
            auditLog.append(securityCase.caseId(), AuditActors.SYSTEM, "CASE_RESOLVED",
                    "remediation verified; case resolved");
        } else {
            // A failed verification is a first-class outcome, not an exception to swallow.
            // The case stays open and a human has to look at it.
            securityCase.blockAutomaticRemediation(
                    "remediation verification failed; the fix did not take effect");
            securityCase.moveTo(CaseLifecycle.ESCALATED);
            auditLog.append(securityCase.caseId(), AuditActors.SECURITY_TOOL, "VERIFICATION_FAILED",
                    checks.stream()
                            .filter(c -> !c.passed())
                            .map(RemediationVerification.Check::name)
                            .reduce((a, b) -> a + ", " + b)
                            .orElse("unknown")
                            + " | case escalated for human review");
        }

        return new RemediationVerification(
                securityCase.caseId(), checks, evidenceIds, passed, observedVersion);
    }

    /**
     * Runs a tool for its evidence side effect and records what it found.
     *
     * <p>Reuses {@link SecurityTool} execution so verification evidence looks exactly like
     * investigation evidence - same sources, same reliability semantics, same audit events.
     */
    private Evidence runTool(SecurityCase securityCase, SimulationWorld world,
                             String toolName, Map<String, Object> extras) {
        SecurityTool tool = toolRegistry.require(toolName);
        ToolResult result = tool.execute(
                securityCase, com.aisecurityguard.domain.ToolArguments.of(tool.targetArgument(securityCase)),
                world);

        EvidenceMetadata metadata = new EvidenceMetadata(
                result.evidence().type() + " (post-remediation)",
                result.evidence().source(),
                result.evidence().finding(),
                result.evidence().reliability(),
                result.evidence().facts());

        Evidence evidence = securityCase.appendEvidence(metadata, clock.tick());
        auditLog.append(securityCase.caseId(), AuditActors.SECURITY_TOOL, "EVIDENCE_CREATED",
                evidence.evidenceId() + " | " + toolName + " | " + result.status());
        return evidence;
    }
}
