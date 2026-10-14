package com.aisecurityguard.audit;

import com.aisecurityguard.domain.AuditEvent;

import java.util.List;

/**
 * Append-only, tamper-evident audit trail.
 *
 * <p>There is intentionally no update or delete operation. Sequence numbers are assigned by the log
 * and are gap-free and strictly increasing, which is what makes the trail usable as an ordering
 * proof for the workflow. Each entry is hash-chained to its predecessor, so a partial edit,
 * reordering or removal is detectable rather than silent.
 */
public interface AuditLog {

    /**
     * Appends an event and extends the hash chain.
     *
     * @return the stored {@link AuditEvent}, including its assigned sequence number, timestamp,
     *         link to its predecessor and content hash
     */
    AuditEvent append(String caseId, String actor, String eventType, String result);

    /** All events, in append order. */
    List<AuditEvent> all();

    /** All events for one case, in append order. */
    List<AuditEvent> forCase(String caseId);

    /** Total number of events appended. */
    int size();

    /**
     * Verifies the hash chain over the whole trail.
     *
     * <p>This is the operation that makes the trail evidence rather than a log: it detects an entry
     * being altered, dropped, reordered, or moved between cases.
     */
    AuditIntegrityReport verifyIntegrity();
}
