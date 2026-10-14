package com.aisecurityguard.agent.llm;

import com.aisecurityguard.domain.ActionImpact;
import com.aisecurityguard.domain.AgentDecision;
import com.aisecurityguard.domain.AgentDecisionType;
import com.aisecurityguard.domain.Assessment;
import com.aisecurityguard.domain.Confidence;
import com.aisecurityguard.domain.FindingStatus;
import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.domain.ToolArguments;
import com.aisecurityguard.model.ModelResponse;
import com.aisecurityguard.tool.ToolRegistry;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Turns a model reply into an {@link AgentDecision}, or refuses to.
 *
 * <p>The model's output is untrusted input. It is parsed strictly and then <em>constrained</em>:
 * the runtime decides which values are acceptable, and anything outside that is rejected rather
 * than coerced into something plausible.
 *
 * <p>What the runtime refuses to take from the model:
 * <ul>
 *   <li><b>Priority and confidence.</b> Both are derived by the runtime
 *       ({@code PriorityPolicy}, {@code ConfidencePolicy}). If the model supplies them they are
 *       ignored, not honoured - a model must not be able to talk up its own confidence.</li>
 *   <li><b>Capability names that are not registered.</b> A hallucinated tool is a rejection, not
 *       a no-op.</li>
 *   <li><b>An assessment with no rationale, or an INVESTIGATE with no capability.</b> An
 *       unexplainable decision is not a decision.</li>
 *   <li><b>The evidence IDs it thinks it saw.</b> The observed-evidence list is taken from the
 *       case by the runtime, because a model could otherwise claim to have considered evidence
 *       that does not exist.</li>
 * </ul>
 *
 * <p>The draft confidence supplied here exists only because {@link Assessment} is structurally
 * complete at construction. It is a placeholder that {@code AssessmentService} overwrites.
 */
@Component
public class AgentDecisionParser {

    private static final Logger log = LoggerFactory.getLogger(AgentDecisionParser.class);

    /**
     * Placeholder confidence for a draft. C4 is used deliberately: if a draft ever escaped
     * finalisation, an unearned claim of certainty would be far worse than an unearned claim of
     * doubt.
     */
    private static final Confidence DRAFT_CONFIDENCE = Confidence.C4;

    private static final int MAX_RATIONALE_LENGTH = 600;

    private final ToolRegistry toolRegistry;
    private final ObjectMapper objectMapper;

    /**
     * Strict reader used only for model replies.
     *
     * <p>Separate from the application's shared mapper on purpose, and configured defensively,
     * because this is the one place the system reads something it does not control:
     * <ul>
     *   <li><b>Trailing content is an error.</b> A lenient reader accepts the first JSON object and
     *       silently discards whatever follows. A model that emits a benign object and then a
     *       second, different decision would have its second attempt ignored - the runtime and the
     *       model would disagree about what was decided, which is exactly the ambiguity an audit
     *       trail must not have.</li>
     *   <li><b>Duplicate keys are an error.</b> With duplicates, the reader silently picks one
     *       value, so two contradictory objects would collapse into one with no trace.</li>
     * </ul>
     * Both are rejections rather than repairs: an ambiguous reply is not a decision.
     */
    private final ObjectMapper strictReader;

    public AgentDecisionParser(ToolRegistry toolRegistry, ObjectMapper objectMapper) {
        this.toolRegistry = Objects.requireNonNull(toolRegistry);
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.strictReader = objectMapper.copy()
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    /** The shared mapper, for callers that need the same JSON conventions. */
    public ObjectMapper objectMapper() {
        return objectMapper;
    }

    /**
     * Parses and constrains a model reply into a decision.
     *
     * @param securityCase the case the decision is about; the source of observed evidence IDs
     * @param response     the raw model reply
     * @throws DecisionRejectedException if the reply cannot be accepted
     */
    public AgentDecision parse(SecurityCase securityCase, ModelResponse response) {
        Objects.requireNonNull(securityCase, "securityCase must not be null");
        Objects.requireNonNull(response, "response must not be null");

        if (response.isTruncated()) {
            throw new DecisionRejectedException(
                    "model reply was truncated, so its JSON is incomplete and cannot be trusted");
        }

        JsonNode root = readJson(response.content());

        AgentDecisionType decisionType = readDecisionType(root);
        String rationale = readRationale(root);
        List<String> missingEvidence = readStringList(root, "missingEvidence");

        // The runtime owns this list. The model does not get to say what it saw.
        List<String> observed = securityCase.evidenceIds();

        return switch (decisionType) {
            case INVESTIGATE -> parseInvestigate(securityCase, root, observed, missingEvidence, rationale);
            case ASSESS, ESCALATE -> parseConclusive(
                    root, decisionType, observed, missingEvidence, rationale);
        };
    }

    // ------------------------------------------------------------------

    private JsonNode readJson(String content) {
        String cleaned = stripCodeFences(content);
        try {
            JsonNode node = strictReader.readTree(cleaned);
            if (node == null || !node.isObject()) {
                throw new DecisionRejectedException(
                        "model reply was not a JSON object: " + truncate(cleaned));
            }
            return node;
        } catch (DecisionRejectedException e) {
            throw e;
        } catch (Exception e) {
            // Jackson's message includes a source snippet, which duplicates the reply and makes
            // the audit entry harder to read. Keep the reason, drop the echo.
            String reason = firstLine(e.getMessage());
            throw new DecisionRejectedException(
                    "model reply was not a single well-formed JSON object: " + reason
                            + " | reply=" + truncate(cleaned), e);
        }
    }

    /** The first line of a message, which is the part that says what went wrong. */
    private String firstLine(String message) {
        if (message == null || message.isBlank()) {
            return "unparseable";
        }
        int newline = message.indexOf('\n');
        return newline < 0 ? message : message.substring(0, newline).trim();
    }

    /** Models sometimes wrap JSON in markdown fences despite being told not to. */
    private String stripCodeFences(String content) {
        String trimmed = content == null ? "" : content.trim();
        if (trimmed.startsWith("```")) {
            int firstNewline = trimmed.indexOf('\n');
            int lastFence = trimmed.lastIndexOf("```");
            if (firstNewline > 0 && lastFence > firstNewline) {
                return trimmed.substring(firstNewline + 1, lastFence).trim();
            }
        }
        return trimmed;
    }

    private AgentDecisionType readDecisionType(JsonNode root) {
        String raw = root.path("decision").asText("").trim().toUpperCase(java.util.Locale.ROOT);
        try {
            return AgentDecisionType.valueOf(raw);
        } catch (IllegalArgumentException e) {
            throw new DecisionRejectedException(
                    "model returned an unrecognised decision '" + raw
                            + "'; expected INVESTIGATE, ASSESS or ESCALATE");
        }
    }

    private String readRationale(JsonNode root) {
        String rationale = root.path("rationale").asText("").trim();
        if (rationale.isBlank()) {
            throw new DecisionRejectedException(
                    "model returned no rationale; an unexplained decision cannot be audited");
        }
        if (rationale.length() > MAX_RATIONALE_LENGTH) {
            // A very long "rationale" is usually reasoning, which must not be stored or shown.
            rationale = rationale.substring(0, MAX_RATIONALE_LENGTH).trim() + "…";
            log.warn("model rationale exceeded {} chars and was truncated to a summary",
                    MAX_RATIONALE_LENGTH);
        }
        return rationale;
    }

    private List<String> readStringList(JsonNode root, String field) {
        JsonNode node = root.path(field);
        if (!node.isArray()) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        node.forEach(item -> {
            String text = item.asText("").trim();
            if (!text.isEmpty()) {
                values.add(text);
            }
        });
        return List.copyOf(values);
    }

    // ------------------------------------------------------------------

    private AgentDecision parseInvestigate(SecurityCase securityCase, JsonNode root,
                                           List<String> observed, List<String> missingEvidence,
                                           String rationale) {
        String capability = root.path("capability").asText("").trim();
        if (capability.isEmpty()) {
            throw new DecisionRejectedException(
                    "an INVESTIGATE decision must name a capability");
        }
        if (!toolRegistry.contains(capability)) {
            throw new DecisionRejectedException(
                    "model selected capability '" + capability + "' which is not available. "
                            + "Available: " + toolRegistry.toolNames());
        }
        if (missingEvidence.isEmpty()) {
            throw new DecisionRejectedException(
                    "an INVESTIGATE decision must state what evidence is missing");
        }

        ToolArguments arguments = toolRegistry.argumentsFor(capability, securityCase);

        return new AgentDecision(
                AgentDecisionType.INVESTIGATE,
                observed,
                missingEvidence,
                rationale,
                capability,
                arguments,
                null);
    }

    private AgentDecision parseConclusive(JsonNode root, AgentDecisionType decisionType,
                                          List<String> observed, List<String> missingEvidence,
                                          String rationale) {
        FindingStatus findingStatus = readFindingStatus(root, decisionType);

        // Priority is derived by the runtime, never read from the model.
        // Confidence is a placeholder and is overwritten during finalisation.
        ProposedAction proposed = readProposedAction(root, findingStatus);

        Assessment draft = new Assessment(
                findingStatus,
                proposed.priority(),
                DRAFT_CONFIDENCE,
                observed,
                rationale,
                List.of(),
                proposed.action(),
                proposed.impact());

        return new AgentDecision(
                decisionType,
                observed,
                decisionType == AgentDecisionType.ESCALATE ? missingEvidence : List.of(),
                rationale,
                null,
                null,
                draft);
    }

    private FindingStatus readFindingStatus(JsonNode root, AgentDecisionType decisionType) {
        String raw = root.path("findingStatus").asText("").trim().toUpperCase(java.util.Locale.ROOT);
        if (raw.isEmpty()) {
            // A missing status is only tolerated for ESCALATE, where "undetermined" is the
            // only sensible reading and the runtime would force it anyway.
            if (decisionType == AgentDecisionType.ESCALATE) {
                return FindingStatus.UNDETERMINED;
            }
            throw new DecisionRejectedException(
                    "an ASSESS decision must state findingStatus");
        }
        try {
            return FindingStatus.valueOf(raw);
        } catch (IllegalArgumentException e) {
            throw new DecisionRejectedException(
                    "model returned an unrecognised findingStatus '" + raw
                            + "'; expected CONFIRMED_VULNERABLE, NOT_AFFECTED or UNDETERMINED");
        }
    }

    /** The action a model proposed, with the priority left unassigned for the runtime to derive. */
    private record ProposedAction(com.aisecurityguard.domain.Priority priority,
                                  String action, ActionImpact impact) {
    }

    private ProposedAction readProposedAction(JsonNode root, FindingStatus findingStatus) {
        String action = root.path("proposedAction").asText("").trim();
        String impactRaw = root.path("actionImpact").asText("").trim().toUpperCase(java.util.Locale.ROOT);

        if (action.isEmpty() && impactRaw.isEmpty()) {
            return new ProposedAction(null, null, null);
        }

        // A finding status of anything other than CONFIRMED_VULNERABLE still has a legitimate
        // thing to say: "close this and record the evidence". That is bookkeeping, not a change to
        // the target, so it is A0 and needs no approval. What must never be accepted is a
        // *consequential* action attached to a finding that is not a confirmed vulnerability -
        // that is how an agent would get permission to change a machine it just said was fine.
        if (findingStatus != FindingStatus.CONFIRMED_VULNERABLE) {
            if (!ActionImpact.A0.name().equals(impactRaw)) {
                throw new DecisionRejectedException(
                        "the model proposed " + (impactRaw.isEmpty() ? "an action" : impactRaw)
                                + " for a finding that is " + findingStatus
                                + "; only an informational A0 note may accompany a finding that is "
                                + "not a confirmed vulnerability");
            }
            return new ProposedAction(null, action, ActionImpact.A0);
        }

        if (action.isEmpty() || impactRaw.isEmpty()) {
            throw new DecisionRejectedException(
                    "a proposed remediation must come with an actionImpact, and vice versa");
        }

        ActionImpact impact;
        try {
            impact = ActionImpact.valueOf(impactRaw);
        } catch (IllegalArgumentException e) {
            throw new DecisionRejectedException(
                    "model returned an unrecognised actionImpact '" + impactRaw
                            + "'; expected A0, A1 or A2");
        }

        return new ProposedAction(null, action, impact);
    }

    private String truncate(String value) {
        if (value == null) {
            return "";
        }
        return value.length() <= 300 ? value : value.substring(0, 300) + "...";
    }
}
