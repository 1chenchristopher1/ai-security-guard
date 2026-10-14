package com.aisecurityguard.audit;

import java.util.List;

/**
 * The result of verifying an audit trail's hash chain.
 *
 * <p>A verification answer that is only "valid or not" is not much use to an incident responder:
 * they need to know <em>where</em> the chain broke and <em>how</em>, because a broken link at event
 * 3 means something different from a broken link at the last event.
 *
 * @param eventsChecked      how many entries were examined
 * @param brokenSelfHashes   sequences whose stored hash does not match their content
 * @param brokenLinks        sequences that do not correctly follow their predecessor
 * @param firstBrokenSequence the earliest problem, or {@code null} when the chain is intact
 */
public record AuditIntegrityReport(
        int eventsChecked,
        List<Long> brokenSelfHashes,
        List<Long> brokenLinks,
        Long firstBrokenSequence) {

    public AuditIntegrityReport {
        brokenSelfHashes = List.copyOf(brokenSelfHashes);
        brokenLinks = List.copyOf(brokenLinks);
    }

    /** True when the chain is intact. */
    public boolean isValid() {
        return brokenSelfHashes.isEmpty() && brokenLinks.isEmpty();
    }

    /** A human-readable explanation, suitable for a log line or an incident note. */
    public String describe() {
        if (isValid()) {
            return "audit chain intact across " + eventsChecked + " events";
        }
        StringBuilder description = new StringBuilder("audit chain BROKEN");
        if (!brokenSelfHashes.isEmpty()) {
            description.append("; entries whose content does not match their hash: ")
                    .append(brokenSelfHashes);
        }
        if (!brokenLinks.isEmpty()) {
            description.append("; entries that do not correctly follow their predecessor: ")
                    .append(brokenLinks);
        }
        description.append("; first problem at sequence ").append(firstBrokenSequence);
        return description.toString();
    }
}
