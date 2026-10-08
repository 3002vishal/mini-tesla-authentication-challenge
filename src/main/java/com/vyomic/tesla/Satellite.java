package com.vyomic.tesla;
import static com.vyomic.tesla.Protocol.*;
/** Sender-facing component; all secret-key operations are delegated to its HSM. */
public final class Satellite {
    private final Hsm hsm;
    private final Trace trace;

    public Satellite(Hsm hsm) { this(hsm, Trace.disabled()); }
    public Satellite(Hsm hsm, Trace trace) {
        this.hsm = java.util.Objects.requireNonNull(hsm);
        this.trace = java.util.Objects.requireNonNull(trace);
    }
    /** Public bootstrap configuration to deliver through a trusted channel. */
    public Trust commitment() {
        trace.event("SATELLITE", "Providing public commitment and schedule through the trusted bootstrap channel.");
        return hsm.configuration();
    }
    /** Return a tagged packet without exposing the authentication key. */
    public Message send(byte[] payload) {
        trace.event("SATELLITE", "Requesting message authentication from the sender HSM.");
        Message message = hsm.authenticate(payload);
        trace.event("SATELLITE", "Sending tagged message: interval=" + message.interval() + ", sequence=" + message.sequence() + ".");
        return message;
    }
    /** Release an earlier interval's key; the HSM enforces the disclosure deadline. */
    public Disclosure disclose(int interval) {
        trace.event("SATELLITE", "Requesting key disclosure for interval=" + interval + ".");
        Disclosure disclosure = hsm.disclose(interval);
        trace.event("SATELLITE", "Sending disclosed key for interval=" + interval + ".");
        return disclosure;
    }
}
