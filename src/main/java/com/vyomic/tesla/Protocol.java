package com.vyomic.tesla;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** Immutable packets and unambiguous, versioned MAC encoding. */
public final class Protocol {
    private Protocol() {}
    // Bound packet size before buffering or MAC calculation.
    public static final int MAX_PAYLOAD = 65_536;
    /** Public bootstrap data. Its source must be authenticated independently of message packets. */
    public record Trust(UUID session, long startMillis, long intervalMillis, int delay, int intervals, byte[] commitment) {
        public Trust {
            if (session == null || startMillis < 0 || intervalMillis <= 0 || delay < 1 || intervals < 1 || intervals > 10_000 || commitment == null || commitment.length != 32)
                throw new IllegalArgumentException("Invalid trusted configuration");
            // Reject schedules whose future timestamps would overflow a long.
            Math.addExact(startMillis, Math.multiplyExact(intervalMillis, (long) intervals + delay));
            // Java records do not automatically make array contents immutable.
            commitment = commitment.clone();
        }
        @Override public byte[] commitment() { return commitment.clone(); }
        /** Earliest time the key for interval i may be released: start + (i + delay) * duration. */
        public long disclosureTime(int interval) {
            checkInterval(interval);
            return Math.addExact(startMillis, Math.multiplyExact(intervalMillis, (long) interval + delay));
        }
        public void checkInterval(int interval) {
            if (interval < 0 || interval >= intervals) throw new IllegalArgumentException("Invalid interval");
        }
    }
    /** Tagged data packet; sequence numbers are unique across the sender's entire session. */
    public record Message(UUID session, int interval, long sequence, byte[] payload, byte[] tag) {
        public Message {
            if (session == null || interval < 0 || sequence < 0 || payload == null || payload.length > MAX_PAYLOAD || tag == null || tag.length != 32)
                throw new IllegalArgumentException("Malformed message");
            // Copy at construction and in accessors so callers cannot change a buffered packet.
            payload = payload.clone(); tag = tag.clone();
        }
        @Override public byte[] payload() { return payload.clone(); }
        @Override public byte[] tag() { return tag.clone(); }
    }
    /** Public key-disclosure packet; the key is trusted only after chain validation. */
    public record Disclosure(UUID session, int interval, byte[] key) {
        public Disclosure {
            if (session == null || interval < 0 || key == null || key.length != 32) throw new IllegalArgumentException("Malformed disclosure");
            key = key.clone();
        }
        @Override public byte[] key() { return key.clone(); }
    }
    /** Both participants must MAC this exact layout; DataOutputStream uses big-endian integers. */
    static byte[] encode(UUID session, int interval, long sequence, byte[] payload) {
        try {
            var bytes = new ByteArrayOutputStream();
            var out = new DataOutputStream(bytes);
            // Domain/version marker prevents interpreting these bytes as another protocol's input.
            out.write("MINI-TESLA-v1".getBytes(StandardCharsets.US_ASCII));
            out.writeLong(session.getMostSignificantBits()); out.writeLong(session.getLeastSignificantBits());
            // Explicit field widths and payload length avoid ambiguous concatenation.
            out.writeInt(interval); out.writeLong(sequence); out.writeInt(payload.length); out.write(payload);
            return bytes.toByteArray();
        } catch (IOException e) { throw new UncheckedIOException(e); }
    }
}
