package com.aisecurityguard.model;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * A scripted {@link ModelClient} for tests.
 *
 * <p>Lets the whole LLM pipeline be exercised deterministically and offline: prompt construction,
 * strict parsing, grounding validation and safe degradation. No network, no API key, no variance.
 *
 * <p>It also records what it was asked, so tests can assert that the prompt really did carry the
 * case facts - a model that is not told the runtime version cannot possibly reason about it.
 */
public final class FakeModelClient implements ModelClient {

    private final Deque<Object> scriptedReplies = new ArrayDeque<>();
    private final List<ModelRequest> receivedRequests = new ArrayList<>();
    private boolean exhausted;

    /** Queues a reply to be returned by the next call. */
    public FakeModelClient thenReply(String content) {
        scriptedReplies.add(new ModelResponse(content, "fake-model", 42, "stop"));
        return this;
    }

    /** Queues a reply that will be returned verbatim, including truncation metadata. */
    public FakeModelClient thenReply(ModelResponse response) {
        scriptedReplies.add(response);
        return this;
    }

    /** Queues a failure to be thrown by the next call. */
    public FakeModelClient thenFail(ModelUnavailableException failure) {
        scriptedReplies.add(failure);
        return this;
    }

    @Override
    public ModelResponse complete(ModelRequest request) {
        receivedRequests.add(request);
        Object next = scriptedReplies.poll();
        if (next == null) {
            // Running past the script is not a test failure in itself. Returning a benign
            // escalation lets the workflow terminate and the test's own assertions decide the
            // outcome, instead of the test dying on "the fake ran out" - which says nothing about
            // the behaviour under test and makes every script change a chore.
            exhausted = true;
            return ESCALATION_WHEN_EXHAUSTED;
        }
        if (next instanceof ModelUnavailableException failure) {
            throw failure;
        }
        return (ModelResponse) next;
    }

    /** A benign, well-formed escalation, used when the script runs out. */
    private static final ModelResponse ESCALATION_WHEN_EXHAUSTED = new ModelResponse(
            """
            {"decision":"ESCALATE",
             "missingEvidence":["a verdict the evidence can support"],
             "rationale":"The scripted model had no further reply; escalating.",
             "findingStatus":"UNDETERMINED"}
            """,
            "fake-model", 0, "stop");

    /** Every request this client received, in order. */
    public List<ModelRequest> requests() {
        return List.copyOf(receivedRequests);
    }

    /** True when the script ran out and a fallback was returned. */
    public boolean wasExhausted() {
        return exhausted;
    }

    /** The most recent request. */
    public ModelRequest lastRequest() {
        if (receivedRequests.isEmpty()) {
            throw new IllegalStateException("no request was made");
        }
        return receivedRequests.get(receivedRequests.size() - 1);
    }

    /** True when nothing further was scripted. */
    public boolean isExhausted() {
        return scriptedReplies.isEmpty();
    }
}
