package com.aisecurityguard.domain;

import java.time.LocalTime;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Proof that a specific human authorised a specific consequential action on a specific case.
 *
 * <p>This is the artifact that makes the approval gate real rather than decorative. The
 * prototype enforced its approval requirement with a UI condition ({@code v-if}), which is not an
 * enforcement at all: anything that could reach the remediation code could execute it. Here,
 * execution requires a token, and a token can only be produced by a human decision.
 *
 * <p>Three properties are load-bearing:
 * <ul>
 *   <li><b>Case-bound.</b> A token names the case it authorises, so an approval for one finding
 *       cannot be replayed against another.</li>
 *   <li><b>Attributed.</b> A token names the approver. An approval that cannot be attributed to a
 *       person is not an approval.</li>
 *   <li><b>Single-use.</b> Consuming a token is a one-way transition, so one approval authorises
 *       one execution and cannot be replayed to execute twice.</li>
 * </ul>
 *
 * <p>Tokens are only ever created through {@link #mintFor}, which requires the issuing gate's
 * access key. The constructor is private, so no other component can fabricate an authorisation.
 */
public final class ApprovalToken {

    /**
     * The secret an issuer must present to mint a token.
     *
     * <p>Held by the approval gate. This is deliberately not a capability check on the caller's
     * identity - Java has no friend classes - but it does make token creation an explicit,
     * greppable act rather than something any class can do by calling a constructor.
     */
    private static final String ISSUER_KEY = "com.aisecurityguard.approval.ApprovalGate";

    private final String caseId;
    private final String approverId;
    private final LocalTime issuedAt;
    private final ActionImpact approvedImpact;
    private final AtomicBoolean consumed = new AtomicBoolean(false);

    private ApprovalToken(String caseId, String approverId, LocalTime issuedAt,
                          ActionImpact approvedImpact) {
        this.caseId = Objects.requireNonNull(caseId, "caseId must not be null");
        this.approverId = Objects.requireNonNull(approverId, "approverId must not be null");
        this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt must not be null");
        this.approvedImpact = Objects.requireNonNull(approvedImpact, "approvedImpact must not be null");
    }

    /**
     * Mints a token. Only the approval gate should call this, passing its own key.
     *
     * @param issuerKey the issuing gate's key
     */
    public static ApprovalToken mintFor(String issuerKey, String caseId, String approverId,
                                        LocalTime issuedAt, ActionImpact approvedImpact) {
        if (!ISSUER_KEY.equals(issuerKey)) {
            throw new IllegalStateException(
                    "execution tokens may only be issued by the approval gate, not by '"
                            + issuerKey + "'");
        }
        return new ApprovalToken(caseId, approverId, issuedAt, approvedImpact);
    }

    /** The key an approval gate must present to mint tokens. */
    public static String issuerKeyForGate() {
        return ISSUER_KEY;
    }

    public String caseId() {
        return caseId;
    }

    public String approverId() {
        return approverId;
    }

    public LocalTime issuedAt() {
        return issuedAt;
    }

    public ActionImpact approvedImpact() {
        return approvedImpact;
    }

    public boolean isConsumed() {
        return consumed.get();
    }

    /**
     * Consumes the token, authorising exactly one execution.
     *
     * <p>Public because consumption is a one-way transition: attempting it twice is safe and the
     * second attempt fails. Authorisation is still enforced by the gate, which is the only
     * component that validates a token before calling this.
     *
     * @return true if this call consumed the token; false if it had already been used
     */
    public boolean consume() {
        return consumed.compareAndSet(false, true);
    }

    @Override
    public String toString() {
        return "ApprovalToken[case=" + caseId + " approver=" + approverId
                + " impact=" + approvedImpact + " consumed=" + consumed.get() + "]";
    }
}
