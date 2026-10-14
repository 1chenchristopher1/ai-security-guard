package com.aisecurityguard.domain;

/**
 * Execution outcome of a tool call.
 *
 * <p>Note that {@link #INCONCLUSIVE} is a distinct outcome from {@link #FAILED}:
 * <ul>
 *   <li>{@code FAILED} - the tool could not run at all (unavailable, crashed, timed out).</li>
 *   <li>{@code INCONCLUSIVE} - the tool ran but could not resolve the question it was asked.</li>
 * </ul>
 * Both produce evidence with {@link EvidenceReliability#INCONCLUSIVE} and neither may be read as
 * "not vulnerable".
 */
public enum ToolStatus {

    /** The tool ran and produced a usable result. */
    SUCCESS,

    /** The tool could not produce a usable result. */
    FAILED,

    /** The tool ran but could not resolve the question. */
    INCONCLUSIVE
}
