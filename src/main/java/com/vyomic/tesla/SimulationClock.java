package com.vyomic.tesla;
import java.time.*;
/** Explicitly controlled monotonic clock for the demonstration and tests. */
public final class SimulationClock extends Clock {
    private long millis;
    private final Trace trace;
    public SimulationClock(long millis) { this(millis, Trace.disabled()); }
    public SimulationClock(long millis, Trace trace) {
        this.millis = millis;
        this.trace = java.util.Objects.requireNonNull(trace);
    }
    /** Move time forward explicitly; negative steps and timestamp overflow are rejected. */
    public void advance(long delta) {
        if (delta < 0) throw new IllegalArgumentException("Cannot reverse time");
        long previous = millis;
        millis = Math.addExact(millis, delta);
        trace.event("CLOCK", "Advanced time from " + previous + " ms to " + millis + " ms.");
    }
    @Override public ZoneId getZone() { return ZoneOffset.UTC; }
    @Override public Clock withZone(ZoneId zone) { if (!ZoneOffset.UTC.equals(zone)) throw new IllegalArgumentException("UTC only"); return this; }
    @Override public Instant instant() { return Instant.ofEpochMilli(millis); }
    @Override public long millis() { return millis; }
}
