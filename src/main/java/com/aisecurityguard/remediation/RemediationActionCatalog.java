package com.aisecurityguard.remediation;

import com.aisecurityguard.domain.SecurityCase;
import com.aisecurityguard.tool.SimulationWorld;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The catalogue of remediation actions the system is permitted to perform.
 *
 * <p>This is where the proposal's rule "execute_remediation may only perform predefined and
 * controlled remediation actions" is actually enforced. An action is not a command: it is a named,
 * catalogued entry with a fixed plan and a fixed effect. There is no way for a caller - or a
 * model - to describe an arbitrary action and have it run, because the only way in is to name a
 * key that already exists here.
 *
 * <p>Each action also knows the version it upgrades to, which is what lets the executor produce a
 * coherent post-fix world for verification to check.
 */
@Component
public class RemediationActionCatalog {

    /**
     * A predefined remediation action.
     *
     * @param actionId        stable identifier, e.g. {@code upgrade-apache-httpd}
     * @param description     what the action does, shown to the approver
     * @param applicableCves  the CVEs this action addresses
     * @param patchedVersion  the version the target is upgraded to
     * @param estimatedSeconds how long the operation is expected to take
     */
    public record RemediationAction(
            String actionId,
            String description,
            List<String> applicableCves,
            String patchedVersion,
            int estimatedSeconds) {

        public RemediationAction {
            applicableCves = List.copyOf(applicableCves);
        }
    }

    private final Map<String, RemediationAction> actionsById = new LinkedHashMap<>();

    public RemediationActionCatalog() {
        register(new RemediationAction(
                "upgrade-apache-httpd",
                "Upgrade Apache HTTP Server to a patched version.",
                List.of("CVE-2021-41773"),
                "2.4.58",
                10));
        register(new RemediationAction(
                "restrict-service-exposure",
                "Remove the service from the internet-facing network segment.",
                List.of("CVE-2021-41773"),
                "2.4.49",
                5));
    }

    private void register(RemediationAction action) {
        actionsById.put(action.actionId(), action);
    }

    /**
     * Resolves the predefined action for a case.
     *
     * @throws IllegalStateException when no catalogued action addresses this vulnerability, which
     *                               means the system must not attempt remediation at all
     */
    public RemediationAction resolveFor(SecurityCase securityCase) {
        return actionsById.values().stream()
                .filter(action -> action.applicableCves().contains(securityCase.cveId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "no predefined remediation action addresses " + securityCase.cveId()
                                + ". Arbitrary remediation is not permitted; this case must be "
                                + "handled by a human."));
    }

    public Optional<RemediationAction> find(String actionId) {
        return Optional.ofNullable(actionsById.get(actionId));
    }

    /**
     * Applies an action to the world, returning the resulting state.
     *
     * <p>Simulated: a real implementation would drive the Docker lab. The important property is
     * that the effect is defined by the catalogue entry, not by the caller.
     */
    public SimulationWorld apply(RemediationAction action, SimulationWorld world) {
        return world.withRuntimeVersion(action.patchedVersion());
    }

    /** The catalogue's action identifiers. */
    public java.util.Set<String> actionIds() {
        return java.util.Set.copyOf(actionsById.keySet());
    }
}
