package com.aisecurityguard.domain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalTime;
import java.util.HexFormat;

/**
 * One entry in the append-only audit trail, cryptographically chained to its predecessor.
 *
 * <p>Append-only by convention is not the same as append-only by construction. A plain list can be
 * edited in place, reordered, or have an entry removed, and nothing about the data would reveal it.
 * Each entry therefore carries a hash over its own content <em>and</em> the previous entry's hash,
 * so any change to any entry invalidates every entry after it.
 *
 * <p>This is tamper-<b>evident</b>, not tamper-<b>proof</b>: an attacker with write access to the
 * whole log can recompute the entire chain. What it buys is that a partial or careless edit - the
 * realistic case, and the one an auditor cares about - is detectable, and that the trail cannot be
 * silently reordered or have an inconvenient entry dropped.
 *
 * <p>The hash covers every field, including the timestamp and the case id, so an entry cannot be
 * moved between cases or back-dated without detection.
 *
 * <p>The four actor values mirror the prototype's audit icons:
 * {@code System}, {@code AI Agent}, {@code Security Tool}, {@code Human}.
 *
 * @param sequence     gap-free, strictly increasing order of append; starts at 1
 * @param timestamp    when the event was recorded
 * @param actor        who caused it: System, AI Agent, Security Tool or Human
 * @param eventType    machine-readable event type, e.g. {@code AGENT_DECISION}
 * @param result       concise outcome, e.g. {@code CONFIRMED_VULNERABLE / P0 / C0}
 * @param caseId       the case this event belongs to
 * @param previousHash hash of the preceding entry, or {@link #GENESIS_HASH} for the first
 * @param hash         hash over this entry's content and {@code previousHash}
 */
public record AuditEvent(
        long sequence,
        LocalTime timestamp,
        String actor,
        String eventType,
        String result,
        String caseId,
        String previousHash,
        String hash) {

    /** The {@code previousHash} of the first entry, so the chain has a defined origin. */
    public static final String GENESIS_HASH =
            "0000000000000000000000000000000000000000000000000000000000000000";

    /** SHA-256, hex-encoded: a fixed 64 characters, which makes the field self-describing. */
    private static final String HASH_ALGORITHM = "SHA-256";

    /** Field separator. Chosen because it cannot occur in any field's content. */
    private static final char FIELD_SEPARATOR = '\u001F';

    public AuditEvent {
        if (sequence < 1) {
            throw new IllegalArgumentException("audit sequence starts at 1");
        }
        if (timestamp == null) {
            throw new IllegalArgumentException("audit timestamp must not be null");
        }
        if (actor == null || actor.isBlank()) {
            throw new IllegalArgumentException("audit actor must not be blank");
        }
        if (eventType == null || eventType.isBlank()) {
            throw new IllegalArgumentException("audit eventType must not be blank");
        }
        if (result == null || result.isBlank()) {
            throw new IllegalArgumentException("audit result must not be blank");
        }
        if (caseId == null || caseId.isBlank()) {
            throw new IllegalArgumentException("audit caseId must not be blank");
        }
        if (previousHash == null || previousHash.isBlank()) {
            throw new IllegalArgumentException("audit previousHash must not be blank");
        }
        if (hash == null || hash.isBlank()) {
            throw new IllegalArgumentException("audit hash must not be blank");
        }
    }

    /**
     * Builds the next entry in a chain, computing its hash from the previous entry.
     *
     * <p>This is the only supported way to create an event, so a caller cannot mint an entry whose
     * hash does not match its content.
     *
     * @param previous the entry this one follows, or {@code null} to start a chain
     */
    public static AuditEvent append(long sequence, LocalTime timestamp, String actor,
                                    String eventType, String result, String caseId,
                                    AuditEvent previous) {
        String previousHash = previous == null ? GENESIS_HASH : previous.hash();
        String hash = computeHash(sequence, timestamp, actor, eventType, result, caseId,
                previousHash);
        return new AuditEvent(sequence, timestamp, actor, eventType, result, caseId,
                previousHash, hash);
    }

    /**
     * Recomputes this entry's hash from its content and its recorded {@code previousHash}.
     *
     * <p>Comparing this against {@link #hash()} detects any edit to the entry's own fields.
     */
    public String recomputeHash() {
        return computeHash(sequence, timestamp, actor, eventType, result, caseId, previousHash);
    }

    /** True when this entry's stored hash matches its content. */
    public boolean isSelfConsistent() {
        return hash.equals(recomputeHash());
    }

    /** True when this entry correctly links to the given predecessor. */
    public boolean linksTo(AuditEvent previous) {
        if (previous == null) {
            return GENESIS_HASH.equals(previousHash) && sequence == 1;
        }
        return previousHash.equals(previous.hash()) && sequence == previous.sequence() + 1;
    }

    /**
     * The canonical string that is hashed.
     *
     * <p>Every field is included, in a fixed order, separated by a character that cannot appear in
     * any field. Without a separator, {@code ("ab", "c")} and {@code ("a", "bc")} would hash
     * identically, which would let an attacker move text between fields undetected.
     */
    private static String hashInput(long sequence, LocalTime timestamp, String actor,
                                    String eventType, String result, String caseId,
                                    String previousHash) {
        return String.join(String.valueOf(FIELD_SEPARATOR),
                Long.toString(sequence),
                timestamp.toString(),
                actor,
                eventType,
                result,
                caseId,
                previousHash);
    }

    private static String computeHash(long sequence, LocalTime timestamp, String actor,
                                      String eventType, String result, String caseId,
                                      String previousHash) {
        String input = hashInput(sequence, timestamp, actor, eventType, result, caseId, previousHash);
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hashed = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashed);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required of every Java platform, so this cannot happen in practice.
            throw new IllegalStateException("SHA-256 is unavailable in this JVM", e);
        }
    }
}
