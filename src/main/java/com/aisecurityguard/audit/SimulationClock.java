package com.aisecurityguard.audit;

import java.time.LocalTime;

/**
 * Deterministic clock used for evidence and audit timestamps.
 *
 * <p>Milestone 0 must be reproducible: running the same scenario twice must produce the same
 * evidence and audit content. The real wall clock would make that impossible, so this clock starts
 * at a fixed time and advances by a fixed amount per call, mirroring the prototype's synthetic
 * {@code ts()} counter (which started at 09:12:01 and ticked forward per event).
 *
 * <p>This is a simulation concern and is expected to be swapped for {@code java.time.Clock} once
 * real tools arrive.
 */
public final class SimulationClock {

    /** Fixed start time, matching the prototype's first audit timestamp. */
    public static final LocalTime START = LocalTime.of(9, 12, 1);

    private static final long TICK_SECONDS = 1;

    private LocalTime current = START;
    private long ticks;

    /** The current simulated time without advancing it. */
    public LocalTime now() {
        return current;
    }

    /** Advances the clock by one tick and returns the new time. */
    public LocalTime tick() {
        ticks++;
        current = START.plusSeconds(ticks * TICK_SECONDS);
        return current;
    }

    public long ticks() {
        return ticks;
    }

    /** Resets to the fixed start time. */
    public void reset() {
        current = START;
        ticks = 0;
    }
}
