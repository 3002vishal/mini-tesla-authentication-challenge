package com.vyomic.tesla;
import java.time.Clock;
import java.util.*;
import static com.vyomic.tesla.Protocol.*;

/** Buffers safe arrivals, verifies them after disclosure, and tracks accepted sequences per session. */
public final class Receiver {
    // BUFFERED is pending authentication; ACCEPTED is the only successful final outcome.
    public enum Status { BUFFERED, ACCEPTED, BAD_MAC, BAD_KEY, REPLAY, UNSAFE_TIME, WRONG_SESSION, INVALID_INTERVAL, BUFFER_FULL }
    /** A BAD_KEY result has no message because the rejected input was a disclosure packet. */
    public record Result(Message message, Status status) {}
    private final Hsm hsm;
    private final Trust trust;
    private final Clock clock;
    private final Trace trace;
    // Upper bound on how far the sender's time could be ahead of our local arrival time.
    private final long uncertaintyMillis;
    private final List<Message> buffer = new ArrayList<>();
    // Unauthenticated packets never reserve a sequence number in this replay set.
    private final Set<Long> accepted = new HashSet<>();
    /** Bootstrap one receiver session with its own HSM and authenticated public configuration. */
    public Receiver(Hsm hsm, Trust trust, Clock clock, long uncertaintyMillis) {
        this(hsm, trust, clock, uncertaintyMillis, Trace.disabled());
    }
    public Receiver(Hsm hsm, Trust trust, Clock clock, long uncertaintyMillis, Trace trace) {
        if (uncertaintyMillis < 0) throw new IllegalArgumentException("Negative clock uncertainty");
        this.hsm = Objects.requireNonNull(hsm); this.trust = Objects.requireNonNull(trust); this.clock = Objects.requireNonNull(clock);
        this.trace = Objects.requireNonNull(trace);
        this.uncertaintyMillis = uncertaintyMillis; hsm.installTrust(trust);
        trace.event("RECEIVER", "Ready to buffer safe arrivals; clock uncertainty=" + uncertaintyMillis + " ms.");
    }
    /** Receive a data packet; safe packets remain untrusted until their key is disclosed. */
    public synchronized Status receive(Message message) {
        if (message == null || !trust.session().equals(message.session())) return reject(Status.WRONG_SESSION, "Packet does not belong to the trusted session.");
        trace.event("RECEIVER", "Received message: interval=" + message.interval() + ", sequence=" + message.sequence() + ".");
        if (message.interval() >= trust.intervals()) return reject(Status.INVALID_INTERVAL, "Packet interval is outside the trusted schedule.");
        if (accepted.contains(message.sequence())) return reject(Status.REPLAY, "Sequence=" + message.sequence() + " was already accepted.");
        long now = clock.millis();
        long opening = trust.startMillis() + trust.intervalMillis() * message.interval();
        long deadline = trust.disclosureTime(message.interval());
        trace.event("RECEIVER", "Checking arrival: now=" + now + " ms, interval opens=" + opening + " ms, disclosure=" + deadline + " ms, uncertainty=" + uncertaintyMillis + " ms.");
        // Only local arrival time and trusted schedule matter, never a packet timestamp.
        // Even if a disclosure packet is lost, its key may already be public to attackers.
        // Require now + uncertainty < disclosureTime; subtraction avoids addition overflow.
        if (now < opening) return reject(Status.UNSAFE_TIME, "The packet's interval has not opened.");
        if (now >= deadline || uncertaintyMillis >= deadline - now) return reject(Status.UNSAFE_TIME, "Cannot establish arrival before key disclosure, including clock uncertainty.");
        if (hsm.isDisclosed(message.interval())) return reject(Status.UNSAFE_TIME, "The interval key is already known.");
        // Bound memory use when an attacker floods the receiver or disclosures never arrive.
        if (buffer.size() >= 1024) return reject(Status.BUFFER_FULL, "The pending-message buffer reached its limit.");
        buffer.add(message);
        trace.event("RECEIVER", "BUFFERED sequence=" + message.sequence() + "; arrival is safe, but authentication awaits a validated disclosed key.");
        return Status.BUFFERED;
    }
    /** Validate a key, then process buffered packets for exactly that key's interval. */
    public synchronized List<Result> receive(Disclosure disclosure) {
        // Leave the buffer untouched when key validation fails so a genuine key can still arrive.
        trace.event("RECEIVER", "Received a key disclosure; requesting HSM validation before touching the buffer.");
        if (!hsm.acceptDisclosure(disclosure)) {
            trace.event("RECEIVER", "BAD_KEY: disclosure rejected; buffered messages remain pending.");
            return List.of(new Result(null, Status.BAD_KEY));
        }
        trace.event("RECEIVER", "Processing buffered messages for interval=" + disclosure.interval() + ".");
        List<Result> results = new ArrayList<>();
        Iterator<Message> iterator = buffer.iterator();
        while (iterator.hasNext()) {
            Message message = iterator.next();
            if (message.interval() != disclosure.interval()) continue;
            // Check replay again: duplicates may have entered the buffer before either was accepted.
            Status status = accepted.contains(message.sequence()) ? Status.REPLAY : !hsm.verify(message) ? Status.BAD_MAC : Status.ACCEPTED;
            if (status == Status.ACCEPTED) accepted.add(message.sequence());
            String reason = switch (status) {
                case ACCEPTED -> "MAC matches; sequence recorded for replay protection.";
                case REPLAY -> "A copy of this sequence was already accepted.";
                default -> "Protected fields do not match the authentication tag.";
            };
            trace.event("RECEIVER", status + " sequence=" + message.sequence() + ": " + reason);
            // Both accepted and rejected packets are finished once their valid key is available.
            results.add(new Result(message, status)); iterator.remove();
        }
        trace.event("RECEIVER", "Finished interval=" + disclosure.interval() + "; processed=" + results.size() + ", still buffered=" + buffer.size() + ".");
        return List.copyOf(results);
    }
    private Status reject(Status status, String reason) {
        trace.event("RECEIVER", status + ": " + reason);
        return status;
    }
}
