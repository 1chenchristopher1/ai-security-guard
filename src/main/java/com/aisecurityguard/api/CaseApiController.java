package com.aisecurityguard.api;

import com.aisecurityguard.audit.AuditIntegrityReport;
import com.aisecurityguard.audit.AuditLog;
import com.aisecurityguard.casefile.CaseManagementService;
import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.ApprovalRequest;
import com.aisecurityguard.domain.AuditEvent;
import com.aisecurityguard.domain.Evidence;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.remediation.RemediationOutcome;
import com.aisecurityguard.verification.RemediationVerification;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The JSON API the user interface talks to.
 *
 * <p>Thin on purpose: it validates the shape of a request, calls {@link CaseManagementService}, and
 * maps the result for the page. It holds no state and makes no decisions, so every rule the UI
 * depends on is still enforced by the service - the API cannot be used to bypass the approval gate
 * any more than any other caller can.
 */
@RestController
@RequestMapping("/api")
public class CaseApiController {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final CaseManagementService caseManagement;
    private final AuditLog auditLog;

    /** Last verification result per case, so the UI can show what verification actually checked. */
    private final Map<String, RemediationVerification> verifications =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, RemediationOutcome> remediations =
            new java.util.concurrent.ConcurrentHashMap<>();

    public CaseApiController(CaseManagementService caseManagement, AuditLog auditLog) {
        this.caseManagement = Objects.requireNonNull(caseManagement);
        this.auditLog = Objects.requireNonNull(auditLog);
    }

    // ==================================================================
    // Reading
    // ==================================================================

    /** The scenarios the page may open, and what each demonstrates. */
    @GetMapping("/scenarios")
    public List<CaseView.ScenarioView> scenarios() {
        return ScenarioCatalog.all().stream()
                .map(entry -> new CaseView.ScenarioView(
                        entry.key(), entry.label(),
                        entry.newCase().caseId(), entry.assetId(),
                        entry.scannerClaim(), entry.expectedOutcome()))
                .toList();
    }

    /** All investigated cases, newest last. */
    @GetMapping("/cases")
    public List<CaseView.Summary> cases() {
        return caseManagement.allCases().stream().map(this::summarise).toList();
    }

    /** The full state of one case. */
    @GetMapping("/cases/{caseId}")
    public CaseView.Detail caseDetail(@PathVariable String caseId) {
        SecurityCase securityCase = requireCase(caseId);
        return detail(securityCase);
    }

    /** The audit trail for one case. */
    @GetMapping("/cases/{caseId}/audit")
    public List<CaseView.AuditEventView> audit(@PathVariable String caseId) {
        requireCase(caseId);
        return auditLog.forCase(caseId).stream().map(this::auditView).toList();
    }

    /**
     * Verifies the whole audit chain.
     *
     * <p>Exposed so the tamper-evidence claim can be demonstrated rather than asserted: the page
     * can show the chain verifying, and what the report says when it does not.
     */
    @GetMapping("/audit/integrity")
    public Map<String, Object> auditIntegrity() {
        AuditIntegrityReport report = auditLog.verifyIntegrity();
        return Map.of(
                "valid", report.isValid(),
                "eventsChecked", report.eventsChecked(),
                "firstBrokenSequence", report.firstBrokenSequence() == null
                        ? -1 : report.firstBrokenSequence(),
                "report", report.describe());
    }

    /** The raw audit rows, for the integrity demonstration. */
    @GetMapping("/audit")
    public List<CaseView.AuditEventView> allAudit() {
        return auditLog.all().stream().map(this::auditView).toList();
    }

    // ==================================================================
    // Acting
    // ==================================================================

    /** Opens a scenario and runs the agent investigation to a conclusion. */
    @PostMapping("/cases")
    public CaseView.Detail openCase(@RequestBody OpenCaseRequest request) {
        ScenarioCatalog.Entry entry = ScenarioCatalog.require(
                request.scenario() == null ? ScenarioCatalog.defaultScenario().key()
                        : request.scenario());

        SecurityCase securityCase = caseManagement.investigate(
                entry.newCase(), entry.scannerClaim(), entry.world());

        return detail(securityCase);
    }

    /**
     * Records a human decision on a case awaiting approval, and executes if approved.
     *
     * <p>Two steps deliberately: the decision is recorded, then the resulting token is exchanged
     * for execution. That mirrors the real gate, and it means a rejection needs no special
     * handling here - it simply yields no token.
     */
    @PostMapping("/cases/{caseId}/decision")
    public CaseView.Detail decide(@PathVariable String caseId,
                                 @RequestBody DecisionRequest request) {
        SecurityCase securityCase = requireCase(caseId);

        if (request.approver() == null || request.approver().isBlank()) {
            throw new IllegalArgumentException(
                    "an approval must name the person giving it");
        }
        LocalTime now = LocalTime.now().withNano(0);

        if (request.approved()) {
            caseManagement.decide(securityCase, ApprovalRequest.approvedBy(
                    caseId, request.approver().trim(), now));

            var token = caseManagement.tokenFor(securityCase).orElseThrow(() ->
                    new IllegalStateException(
                            "case " + caseId + " produced no execution token after approval"));

            var result = caseManagement.remediateAndVerify(securityCase, token);
            verifications.put(caseId, result.verification());
            remediations.put(caseId, result.remediation());
        } else {
            caseManagement.decide(securityCase, ApprovalRequest.rejectedBy(
                    caseId, request.approver().trim(), now,
                    request.reason() == null || request.reason().isBlank()
                            ? "no reason given" : request.reason().trim()));
        }

        return detail(securityCase);
    }

    /** Hands an escalated case to a named analyst. */
    @PostMapping("/cases/{caseId}/takeover")
    public CaseView.Detail takeOver(@PathVariable String caseId,
                                   @RequestBody DecisionRequest request) {
        SecurityCase securityCase = requireCase(caseId);
        caseManagement.takeOver(securityCase, request.approver());
        return detail(securityCase);
    }

    /**
     * Clears case storage so the demonstration can start from a clean slate.
     *
     * <p>Also drops this controller's cached verification results. That matters: the caches are
     * keyed by case id, and every run of a scenario reuses the same id, so without this a second
     * run would display the first run's verification checks - which would look like a successful
     * fix that never happened.
     */
    @PostMapping("/reset")
    public CaseView.Message reset() {
        caseManagement.reset();
        verifications.clear();
        remediations.clear();
        return CaseView.Message.of("Case storage cleared. The audit history is retained.");
    }

    // ==================================================================
    // Request bodies
    // ==================================================================

    /** Which scenario to open. */
    public record OpenCaseRequest(String scenario) {
    }

    /** A human decision: approve or reject, by a named person. */
    public record DecisionRequest(boolean approved, String approver, String reason) {
    }

    // ==================================================================
    // Errors
    // ==================================================================

    /**
     * Turns a refusal into a 4xx with the reason.
     *
     * <p>The messages the runtime produces are written for a human reader, so they are passed
     * through rather than replaced with something generic - "you cannot do that" is less useful
     * than "a confirmed vulnerability that cannot be prioritised must be escalated".
     */
    @ExceptionHandler({IllegalStateException.class, IllegalArgumentException.class})
    public ResponseEntity<CaseView.Message> onRefusal(RuntimeException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new CaseView.Message("The runtime refused that", e.getMessage()));
    }

    // ==================================================================
    // Mapping
    // ==================================================================

    private SecurityCase requireCase(String caseId) {
        return caseManagement.load(caseId).orElseThrow(() -> new IllegalArgumentException(
                "no case with id '" + caseId + "'. Investigate one first."));
    }

    private CaseView.Summary summarise(SecurityCase securityCase) {
        var assessment = securityCase.assessmentIfPresent();
        var status = caseManagement.approvalStatusFor(securityCase);

        return new CaseView.Summary(
                securityCase.caseId(),
                securityCase.assetId(),
                securityCase.cveId(),
                securityCase.lifecycle(),
                assessment.map(a -> a.findingStatus()).orElse(null),
                assessment.map(a -> a.priority()).orElse(null),
                assessment.map(a -> a.confidence()).orElse(null),
                CaseViewMapper.statusLabel(securityCase.lifecycle()),
                securityCase.evidenceCount(),
                status.approvalRequired(),
                status.outcome(),
                securityCase.isAutomaticRemediationBlocked(),
                auditLog.forCase(securityCase.caseId()).size());
    }

    private CaseView.Detail detail(SecurityCase securityCase) {
        var assessment = securityCase.assessmentIfPresent().orElse(null);
        var status = caseManagement.approvalStatusFor(securityCase);
        AuditIntegrityReport integrity = auditLog.verifyIntegrity();

        List<CaseView.CheckView> checks = new ArrayList<>();
        RemediationVerification verification = verifications.get(securityCase.caseId());
        if (verification != null) {
            verification.checks().forEach(check -> checks.add(
                    new CaseView.CheckView(check.name(), check.observation(), check.passed())));
        }

        RemediationOutcome remediation = remediations.get(securityCase.caseId());

        return new CaseView.Detail(
                securityCase.caseId(),
                securityCase.assetId(),
                securityCase.cveId(),
                securityCase.lifecycle(),
                CaseViewMapper.statusLabel(securityCase.lifecycle()),
                CaseViewMapper.statusTone(securityCase.lifecycle()),
                assessment == null ? null : assessment.findingStatus(),
                assessment == null ? null : assessment.priority(),
                assessment == null ? null : assessment.confidence(),
                assessment == null ? null : assessment.actionImpact(),
                assessment == null ? List.of() : assessment.reasons(),
                assessment == null ? null : assessment.rationale(),
                assessment == null ? null : assessment.proposedAction(),
                assessment != null && assessment.requiresHumanApproval(),
                status.approvalRequired(),
                status.outcome(),
                status.approverId(),
                securityCase.isAutomaticRemediationBlocked(),
                securityCase.escalationReason().orElse(null),
                status.conflictStatus(),
                securityCase.evidence().stream().map(this::evidenceView).toList(),
                decisionViews(securityCase),
                auditLog.forCase(securityCase.caseId()).stream().map(this::auditView).toList(),
                checks,
                remediation == null ? List.of() : remediation.steps(),
                remediation == null ? null : remediation.backupReference(),
                integrity.isValid(),
                integrity.describe());
    }

    private List<CaseView.DecisionView> decisionViews(SecurityCase securityCase) {
        List<CaseView.DecisionView> views = new ArrayList<>();
        int number = 0;
        for (AgentDecision decision : securityCase.decisions()) {
            number++;
            views.add(new CaseView.DecisionView(
                    number,
                    decision.decisionType().name(),
                    decision.selectedTool(),
                    decision.toolArguments() == null ? null : decision.toolArguments().target(),
                    decision.observedEvidenceIds(),
                    decision.missingEvidence(),
                    decision.rationale()));
        }
        return views;
    }

    private CaseView.EvidenceView evidenceView(Evidence evidence) {
        return new CaseView.EvidenceView(
                evidence.evidenceId(),
                evidence.type(),
                evidence.source(),
                evidence.finding(),
                evidence.reliability(),
                evidence.timestamp().format(TIME));
    }

    private CaseView.AuditEventView auditView(AuditEvent event) {
        return new CaseView.AuditEventView(
                event.sequence(),
                event.timestamp().format(TIME),
                event.actor(),
                event.eventType(),
                event.result(),
                event.hash().substring(0, 12));
    }

    /** Convenience for callers that need the impact label without the domain type. */
    public static String impactLabel(ActionImpact impact) {
        return CaseViewMapper.actionImpactLabel(impact);
    }
}
