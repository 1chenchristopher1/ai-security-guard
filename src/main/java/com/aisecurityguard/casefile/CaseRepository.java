package com.aisecurityguard.casefile;

import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.SimulationWorld;

import java.time.LocalTime;
import java.util.List;
import java.util.Optional;

/**
 * Storage for investigated cases.
 *
 * <p>Before this existed, the workflow service held case state in its own private map. That worked
 * only because nothing was ever restarted, and it left the observed environment stranded in the
 * orchestration layer - an environment is not the orchestrator's business, but it <em>is</em> part
 * of what was investigated, so it has to live with the case.
 *
 * <p>The interface is deliberately narrow: save a case, load a case, list them. No update or delete
 * of individual fields, because a case's history is append-only, and no query language, because
 * nothing needs one yet.
 */
public interface CaseRepository {

    /**
     * A stored investigation: the case, and the state of the target it was investigated against.
     *
     * <p>The observed world is kept because it is the only record of what the evidence was gathered
     * <em>from</em>. Without it, a later remediation could not tell what it was changing, and
     * verification could not tell what had changed.
     *
     * @param securityCase  the case, carrying its evidence, facts, decisions and assessment
     * @param observedWorld the target as it was observed during investigation
     * @param storedAt      when this record was last written
     */
    record StoredCase(SecurityCase securityCase, SimulationWorld observedWorld, LocalTime storedAt) {
    }

    /**
     * Saves a case, replacing any previous record for the same case id.
     *
     * <p>Replacement rather than mutation: the case object is the unit of consistency, so a reader
     * never sees a half-updated case.
     */
    void save(SecurityCase securityCase, SimulationWorld observedWorld, LocalTime storedAt);

    /** Loads a case by id. */
    Optional<StoredCase> find(String caseId);

    /** All stored cases, in the order they were first saved. */
    List<StoredCase> all();

    /** Number of stored cases. */
    int size();

    /** True when a case with this id is stored. */
    boolean contains(String caseId);

    /**
     * Removes every stored case.
     *
     * <p>Exists so the demonstration can be reset to a clean slate between takes. It is not part
     * of the case lifecycle: real cases are never deleted, which is why this is documented as a
     * demonstration affordance rather than a domain operation. The audit trail is deliberately
     * <em>not</em> cleared with it, because an audit trail that can be wiped on demand is not an
     * audit trail.
     */
    void clear();
}
