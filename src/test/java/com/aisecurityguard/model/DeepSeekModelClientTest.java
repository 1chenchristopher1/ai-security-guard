package com.aisecurityguard.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.web.client.RestClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The provider protocol layer.
 *
 * <p>Uses a mock request factory so no network call is made: this test is about the shape of what
 * is sent and how replies are handled, not about connectivity. The live call is exercised
 * separately and only when an API key is configured.
 */
class DeepSeekModelClientTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ModelProperties propertiesWithKey(String key) {
        return new ModelProperties("https://api.deepseek.com", "deepseek-chat", key, 30);
    }

    // ==================================================================

    @Test
    @DisplayName("a missing API key fails with an actionable message, not a null pointer")
    void missingKeyIsActionable() {
        DeepSeekModelClient client = new DeepSeekModelClient(
                propertiesWithKey(null), MAPPER);

        assertThatThrownBy(() -> client.complete(request()))
                .isInstanceOf(ModelUnavailableException.class)
                .hasMessageContaining("DEEPSEEK_API_KEY")
                .hasMessageContaining("human");
    }

    @Test
    @DisplayName("a blank API key counts as missing")
    void blankKeyIsMissing() {
        assertThat(propertiesWithKey("   ").hasApiKey()).isFalse();
    }

    @Test
    @DisplayName("the API key is never rendered by toString")
    void keyIsRedacted() {
        String rendered = propertiesWithKey("sk-super-secret-value").toString();

        assertThat(rendered).doesNotContain("sk-super-secret-value");
        assertThat(rendered).contains("***set***");
    }

    @Test
    @DisplayName("a missing key is reported as missing, not as set")
    void missingKeyIsRenderedAsMissing() {
        assertThat(propertiesWithKey(null).toString()).contains("***missing***");
    }

    @Test
    @DisplayName("defaults are applied when configuration is absent")
    void defaultsAreApplied() {
        ModelProperties properties = new ModelProperties(null, null, null, 0);

        assertThat(properties.baseUrl()).isEqualTo(ModelProperties.DEFAULT_BASE_URL);
        assertThat(properties.model()).isEqualTo(ModelProperties.DEFAULT_MODEL);
        assertThat(properties.timeoutSeconds()).isEqualTo(ModelProperties.DEFAULT_TIMEOUT_SECONDS);
    }

    @Test
    @DisplayName("the chat completions request carries the model, messages and JSON mode")
    void requestShapeIsCorrect() throws Exception {
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.POST,
                java.net.URI.create("https://api.deepseek.com/chat/completions"));
        RestClient restClient = RestClient.builder()
                .baseUrl("https://api.deepseek.com")
                .requestFactory((uri, httpMethod) -> request)
                .build();

        DeepSeekModelClient client = new DeepSeekModelClient(
                propertiesWithKey("test-key"), MAPPER, restClient);

        // Install the response before the call, since the mock request is written synchronously.
        request.setResponse(new org.springframework.mock.http.client.MockClientHttpResponse(
                ("{\"model\":\"deepseek-chat\",\"choices\":[{\"message\":{\"content\":"
                        + "\"{\\\"decision\\\":\\\"INVESTIGATE\\\"}\",\"role\":\"assistant\"},"
                        + "\"finish_reason\":\"stop\"}],\"usage\":{\"total_tokens\":17}}")
                        .getBytes(),
                org.springframework.http.HttpStatus.OK));
        request.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        ModelResponse response = client.complete(new ModelRequest(
                "system instructions",
                List.of(ModelMessage.user("case state")),
                0.0,
                true,
                500));

        // --- what was sent ---
        String sentBody = request.getBodyAsString();
        JsonNode sent = MAPPER.readTree(sentBody);
        assertThat(sent.path("model").asText()).isEqualTo("deepseek-chat");
        assertThat(sent.path("temperature").asDouble()).isZero();
        assertThat(sent.path("max_tokens").asInt()).isEqualTo(500);
        assertThat(sent.path("response_format").path("type").asText()).isEqualTo("json_object");
        assertThat(sent.path("messages")).hasSize(2);
        assertThat(sent.path("messages").get(0).path("role").asText()).isEqualTo("system");
        assertThat(sent.path("messages").get(0).path("content").asText())
                .isEqualTo("system instructions");
        assertThat(sent.path("messages").get(1).path("role").asText()).isEqualTo("user");
        assertThat(sent.path("messages").get(1).path("content").asText()).isEqualTo("case state");

        assertThat(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer test-key");

        // --- what was returned ---
        assertThat(response.content()).contains("INVESTIGATE");
        assertThat(response.model()).isEqualTo("deepseek-chat");
        assertThat(response.totalTokens()).isEqualTo(17);
        assertThat(response.isTruncated()).isFalse();
    }

    @Test
    @DisplayName("a truncated reply is flagged so the agent can refuse it")
    void truncationIsFlagged() {
        ModelResponse response = new ModelResponse("partial", "m", 5, "length");

        assertThat(response.isTruncated()).isTrue();
    }

    private static ModelRequest request() {
        return new ModelRequest("system", List.of(ModelMessage.user("case")), 0.0, true, 100);
    }
}
