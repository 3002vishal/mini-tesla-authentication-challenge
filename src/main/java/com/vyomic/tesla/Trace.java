package com.vyomic.tesla;

import java.io.PrintStream;
import java.util.Objects;

/** Optional execution trace shared by demo components; disabled for existing callers by default. */
public final class Trace {
    private static final Trace DISABLED = new Trace(null);
    private final PrintStream output;

    private Trace(PrintStream output) { this.output = output; }

    public static Trace disabled() { return DISABLED; }

    /** Select the destination explicitly so tests can capture output without changing global state. */
    public static Trace console(PrintStream output) { return new Trace(Objects.requireNonNull(output)); }

    /** Callers provide only explanatory text and public metadata, never keys or payload bytes. */
    public void event(String component, String message) {
        if (output != null) output.println("[" + component + "] " + message);
    }
}
