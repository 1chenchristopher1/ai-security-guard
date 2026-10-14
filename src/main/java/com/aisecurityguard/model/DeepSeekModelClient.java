package com.aisecurityguard.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * DeepSeek implementation of {@link ModelClient}, over the OpenAI-compatible chat completions API.
 *
 * <p>Kept deliberately thin. Protocol concerns (JSON shape, auth header, timeout, error mapping)
 * live here; everything that decides <em>what to ask</em> and <em>what to do with the answer</em>
 * lives on the agent side.
 *
 * <p>The API key is never logged and never included in an exception message.
 */
public class DeepSeekModelClient implements ModelClient {

    private static final Logger log = LoggerFactory.getLogger(DeepSeekModelClient.class);

    private static final String CHAT_COMPLETIONS_PATH = "/chat/completions";

    private final ModelProperties properties;
    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    public DeepSeekModelClient(ModelProperties properties, ObjectMapper objectMapper) {
        this(properties, objectMapper, RestClient.builder()
                .baseUrl(properties.baseUrl())
                .build());
    }

    /** Constructor allowing a pre-configured client, used by tests. */
    public DeepSeekModelClient(ModelProperties properties, ObjectMapper objectMapper,
                               RestClient restClient) {
        this.properties = Objects.requireNonNull(properties);
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.restClient = Objects.requireNonNull(restClient);
    }

    @Override
    public ModelResponse complete(ModelRequest request) {
        if (!properties.hasApiKey()) {
            throw new ModelUnavailableException(
                    "no API key configured: set the " + ModelProperties.API_KEY_ENV_VAR
                            + " environment variable to enable the language model. Without it the "
                            + "agent cannot reason, so the case must be handled by a human.");
        }

        String body;
        try {
            body = objectMapper.writeValueAsString(buildRequestBody(request));
        } catch (Exception e) {
            throw new ModelUnavailableException("could not serialise the model request", e);
        }

        String raw;
        try {
            raw = restClient.post()
                    .uri(CHAT_COMPLETIONS_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + properties.apiKey())
                    .body(body)
                    .retrieve()
                    .body(String.class);
        } catch (Exception e) {
            // The key is deliberately absent from this message.
            throw new ModelUnavailableException(
                    "model request to " + properties.baseUrl() + " failed: " + e.getMessage(), e);
        }

        return parseResponse(raw);
    }

    /** Builds the OpenAI-compatible chat completions request body. */
    private ObjectNode buildRequestBody(ModelRequest request) {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("model", properties.model());
        root.put("temperature", request.temperature());
        root.put("max_tokens", request.maxTokens());

        if (request.jsonResponse()) {
            ObjectNode format = root.putObject("response_format");
            format.put("type", "json_object");
        }

        ArrayNode messages = root.putArray("messages");
        messages.add(messageNode(ModelMessage.Role.SYSTEM, request.systemPrompt()));
        for (ModelMessage message : request.messages()) {
            messages.add(messageNode(message.role(), message.content()));
        }
        return root;
    }

    private ObjectNode messageNode(ModelMessage.Role role, String content) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("role", role.name().toLowerCase(java.util.Locale.ROOT));
        node.put("content", content);
        return node;
    }

    /** Extracts the assistant text from a chat completions response. */
    private ModelResponse parseResponse(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new ModelUnavailableException("model returned an empty response body");
        }
        try {
            JsonNode root = objectMapper.readTree(raw);
            JsonNode choices = root.path("choices");
            if (!choices.isArray() || choices.isEmpty()) {
                throw new ModelUnavailableException(
                        "model response contained no choices: " + truncate(raw));
            }
            JsonNode first = choices.get(0);
            String content = first.path("message").path("content").asText(null);
            if (content == null || content.isBlank()) {
                throw new ModelUnavailableException(
                        "model response contained no assistant content: " + truncate(raw));
            }
            String finishReason = first.path("finish_reason").asText("unknown");
            String model = root.path("model").asText(properties.model());
            int totalTokens = root.path("usage").path("total_tokens").asInt(0);

            if ("length".equalsIgnoreCase(finishReason)) {
                log.warn("model reply was truncated at max_tokens; the decision cannot be trusted");
            }
            return new ModelResponse(content, model, totalTokens, finishReason);
        } catch (ModelUnavailableException e) {
            throw e;
        } catch (Exception e) {
            throw new ModelUnavailableException(
                    "could not parse the model response: " + e.getMessage(), e);
        }
    }

    private String truncate(String value) {
        return value.length() <= 300 ? value : value.substring(0, 300) + "...";
    }

    /** The messages actually sent, for tests and diagnostics. */
    public List<ModelMessage> previewMessages(ModelRequest request) {
        return request.messages();
    }
}
