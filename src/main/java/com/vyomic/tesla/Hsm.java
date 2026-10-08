package com.vyomic.tesla;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import static com.vyomic.tesla.Protocol.*;

/**
 * Encapsulates key generation, authentication, disclosure, and encrypted persistence.
 * A sender holds a private key chain; a receiver holds only trusted public configuration
 * and keys that have passed disclosure validation. This is a software simulation,
 * so it does not protect keys against a compromised JVM.
 * Synchronized operations serialize access to mutable state, including sequence allocation.
 */
public final class Hsm {
    // Public file signature and format version, authenticated as GCM associated data.
    private static final byte[] HEADER = { 'M', 'T', 'H', 'S', 'M', 1 };
    private final Clock clock;
    private final Trace trace;
    private Trust trust;
    // Sender only: keys[0] is the commitment; interval i uses keys[i + 1].
    private byte[][] keys;
    // Receiver only: entries are inserted after validation against the commitment.
    private final Map<Integer, byte[]> disclosed = new HashMap<>();
    private long nextSequence;
    public Hsm(Clock clock) { this(clock, Trace.disabled()); }
    public Hsm(Clock clock, Trace trace) {
        this.clock = Objects.requireNonNull(clock);
        this.trace = Objects.requireNonNull(trace);
    }
    /** Initialize a sender once and return its public bootstrap configuration. */
    public synchronized Trust generate(long start, long duration, int delay, int count) {
        if (trust != null) throw new IllegalStateException("HSM already initialized");
        // Validate bounds and schedule arithmetic before allocating a potentially large chain.
        new Trust(UUID.randomUUID(), start, duration, delay, count, new byte[32]);
        trace.event("SENDER HSM", "Generating a random final key and hashing backwards with SHA-256 for " + count + " intervals.");
        byte[][] chain = new byte[count + 1][32];
        // Generate the last key randomly, then hash backwards: K[i] = SHA-256(K[i + 1]).
        // Knowing K[i] does not let a receiver compute a future key K[i + 1].
        new SecureRandom().nextBytes(chain[count]);
        for (int i = count - 1; i >= 0; i--) chain[i] = hash(chain[i + 1]);
        trust = new Trust(UUID.randomUUID(), start, duration, delay, count, chain[0]);
        keys = chain;
        trace.event("SENDER HSM", "Key chain generated; only the public commitment and schedule leave the HSM during bootstrap.");
        trace.event("SENDER HSM", "Schedule: start=" + start + " ms, interval=" + duration + " ms, disclosure delay=" + delay + " interval(s).");
        return trust;
    }
    /** Install configuration received through a trusted bootstrap channel, not a data packet. */
    public synchronized void installTrust(Trust configuration) {
        if (trust != null) throw new IllegalStateException("HSM already initialized");
        trust = Objects.requireNonNull(configuration);
        trace.event("RECEIVER HSM", "Installed trusted commitment and schedule; no sender key chain was received.");
    }
    /** Allocate a session-wide sequence number and MAC a payload with the current secret key. */
    public synchronized Message authenticate(byte[] payload) {
        requireSender();
        if (payload == null || payload.length > MAX_PAYLOAD) throw new IllegalArgumentException("Invalid payload");
        // Derive the interval from the trusted clock, rather than allowing the caller to choose it.
        long elapsed = clock.millis() - trust.startMillis();
        if (elapsed < 0 || elapsed / trust.intervalMillis() >= trust.intervals()) throw new IllegalStateException("Outside sending window");
        int interval = (int) (elapsed / trust.intervalMillis());
        trace.event("SENDER HSM", "Current time=" + clock.millis() + " ms selects sending interval=" + interval + ".");
        if (nextSequence == Long.MAX_VALUE) throw new IllegalStateException("Sequence exhausted");
        long sequence = nextSequence++;
        // Copy first so MAC calculation and the returned packet use the same bytes.
        byte[] stablePayload = payload.clone();
        trace.event("SENDER HSM", "Encoding version, session, interval, sequence, payload length, and payload into deterministic bytes.");
        Message message = new Message(trust.session(), interval, sequence, stablePayload, mac(keys[interval + 1], encode(trust.session(), interval, sequence, stablePayload)));
        trace.event("SENDER HSM", "HMAC-SHA256 generated for sequence=" + sequence + " using the undisclosed interval key.");
        return message;
    }
    /** The explicit sender operation that releases a key after its scheduled disclosure time. */
    public synchronized Disclosure disclose(int interval) {
        requireSender(); trust.checkInterval(interval);
        trace.event("SENDER HSM", "Checking disclosure deadline: now=" + clock.millis() + " ms, deadline=" + trust.disclosureTime(interval) + " ms.");
        if (clock.millis() < trust.disclosureTime(interval)) {
            trace.event("SENDER HSM", "Disclosure rejected: the interval key must remain secret until its deadline.");
            throw new IllegalStateException("Disclosure is premature");
        }
        trace.event("SENDER HSM", "Disclosure time reached; releasing the key for interval=" + interval + ".");
        return new Disclosure(trust.session(), interval, keys[interval + 1]);
    }
    /** Validate a receiver's disclosed key before making it available for MAC verification. */
    public synchronized boolean acceptDisclosure(Disclosure packet) {
        if (trust == null || keys != null || packet == null || !trust.session().equals(packet.session()) || packet.interval() >= trust.intervals()) {
            trace.event("RECEIVER HSM", "Disclosure rejected: receiver state, session, or interval is invalid.");
            return false;
        }
        if (clock.millis() < trust.disclosureTime(packet.interval())) {
            trace.event("RECEIVER HSM", "Disclosure rejected: its scheduled disclosure time has not arrived.");
            return false;
        }
        byte[] candidate = packet.key();
        byte[] commitment = candidate;
        // Interval i discloses K[i + 1]; i + 1 hashes must reach the trusted K[0].
        // Starting from the original commitment also allows disclosures to arrive out of order.
        trace.event("RECEIVER HSM", "Hashing disclosed key " + (packet.interval() + 1) + " time(s) to compare with the trusted commitment.");
        for (int i = 0; i <= packet.interval(); i++) commitment = hash(commitment);
        if (!MessageDigest.isEqual(commitment, trust.commitment())) {
            trace.event("RECEIVER HSM", "Key-chain validation failed for interval=" + packet.interval() + ".");
            return false;
        }
        disclosed.put(packet.interval(), candidate);
        trace.event("RECEIVER HSM", "Key-chain validation passed for interval=" + packet.interval() + "; key stored for verification.");
        return true;
    }
    /** Verify a MAC using a validated disclosed key; arrival and replay checks belong to Receiver. */
    public synchronized boolean verify(Message packet) {
        if (trust == null || packet == null || !trust.session().equals(packet.session())) {
            trace.event("RECEIVER HSM", "MAC verification unavailable: missing trust or mismatched packet session.");
            return false;
        }
        byte[] key = disclosed.get(packet.interval());
        if (key == null) {
            trace.event("RECEIVER HSM", "MAC verification pending: no validated disclosed key for interval=" + packet.interval() + ".");
            return false;
        }
        trace.event("RECEIVER HSM", "Recomputing HMAC-SHA256 over the protected fields for sequence=" + packet.sequence() + ".");
        boolean valid = MessageDigest.isEqual(packet.tag(), mac(key, encode(packet.session(), packet.interval(), packet.sequence(), packet.payload())));
        trace.event("RECEIVER HSM", "MAC verification " + (valid ? "passed" : "failed") + " for sequence=" + packet.sequence() + ".");
        return valid;
    }
    public synchronized boolean isDisclosed(int interval) { return disclosed.containsKey(interval); }
    /** Return public session metadata and the commitment, without exposing sender keys. */
    public synchronized Trust configuration() {
        if (trust == null) throw new IllegalStateException("Uninitialized HSM");
        return trust;
    }
    private void requireSender() { if (keys == null) throw new IllegalStateException("Sender key store required"); }
    private static byte[] hash(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    private static byte[] mac(byte[] key, byte[] bytes) {
        try { Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256")); return mac.doFinal(bytes); }
        catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    /** Require exactly 256 bits of externally supplied encryption key material. */
    private static byte[] masterKey() {
        String value = System.getenv("TESLA_MASTER_KEY");
        try {
            byte[] key = Base64.getDecoder().decode(value == null ? "" : value);
            if (key.length != 32) throw new IllegalArgumentException();
            return key;
        } catch (IllegalArgumentException e) { throw new IllegalStateException("TESLA_MASTER_KEY must contain a Base64-encoded 32-byte key"); }
    }
    /** Encrypt a complete HSM snapshot; no plaintext key store is written to disk. */
    public synchronized void exportStore(Path path) throws IOException, GeneralSecurityException {
        configuration();
        byte[] master = masterKey();
        byte[] plaintext = serialize();
        try {
            trace.event(keys == null ? "RECEIVER HSM" : "SENDER HSM", "Encrypting key store with AES-256-GCM and a fresh random nonce.");
            // GCM requires a fresh nonce for each encryption under the same master key.
            byte[] nonce = new byte[12]; new SecureRandom().nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(master, "AES"), new GCMParameterSpec(128, nonce)); cipher.updateAAD(HEADER);
            byte[] encrypted = cipher.doFinal(plaintext);
            // File layout: versioned header | 12-byte nonce | ciphertext with 16-byte GCM tag.
            // Authenticate the header even though it is public and not encrypted.
            Path destination = path.toAbsolutePath();
            Path temporary = Files.createTempFile(destination.getParent(), "tesla-", ".tmp");
            try {
                try (OutputStream out = Files.newOutputStream(temporary)) { out.write(HEADER); out.write(nonce); out.write(encrypted); }
                // Prefer atomic replacement so an interrupted write does not leave a partial store.
                try { Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
                catch (AtomicMoveNotSupportedException e) { Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING); }
            } finally { Files.deleteIfExists(temporary); }
            trace.event(keys == null ? "RECEIVER HSM" : "SENDER HSM", "Encrypted key store exported; plaintext key material was not written to disk.");
        // Best-effort cleanup of these temporary arrays; JVM/provider copies may still exist.
        } finally { Arrays.fill(master, (byte) 0); Arrays.fill(plaintext, (byte) 0); }
    }
    /** Authenticate and decrypt a snapshot, then return a new HSM only after validation succeeds. */
    public static Hsm importStore(Path path, Clock clock) throws IOException, GeneralSecurityException {
        return importStore(path, clock, Trace.disabled());
    }
    /** Restore state with optional tracing; the original overload remains quiet. */
    public static Hsm importStore(Path path, Clock clock, Trace trace) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(trace);
        if (Files.size(path) > 1_000_000) throw new IOException("Oversized key store");
        byte[] file = Files.readAllBytes(path);
        if (file.length < HEADER.length + 12 + 16 || !Arrays.equals(HEADER, Arrays.copyOf(file, HEADER.length))) throw new IOException("Invalid key store header");
        byte[] master = masterKey(); byte[] plaintext = null;
        try {
            trace.event("HSM", "Authenticating and decrypting key store with AES-256-GCM before parsing state.");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(master, "AES"), new GCMParameterSpec(128, file, HEADER.length, 12)); cipher.updateAAD(HEADER);
            // doFinal checks the GCM tag; wrong keys or altered ciphertext fail before parsing.
            plaintext = cipher.doFinal(file, HEADER.length + 12, file.length - HEADER.length - 12);
            Hsm restored = deserialize(plaintext, clock, trace);
            trace.event(restored.keys == null ? "RECEIVER HSM" : "SENDER HSM", "Key store imported; authentication and stored chain consistency checks passed.");
            return restored;
        } catch (GeneralSecurityException | IOException e) {
            trace.event("HSM", "Key store import failed; no restored HSM state is returned.");
            throw e;
        } finally { Arrays.fill(master, (byte) 0); if (plaintext != null) Arrays.fill(plaintext, (byte) 0); }
    }
    /** Internal binary snapshot format; deserialize must read fields in this exact order. */
    private byte[] serialize() throws IOException {
        var bytes = new ByteArrayOutputStream(); var out = new DataOutputStream(bytes);
        out.writeLong(trust.session().getMostSignificantBits()); out.writeLong(trust.session().getLeastSignificantBits());
        out.writeLong(trust.startMillis()); out.writeLong(trust.intervalMillis()); out.writeInt(trust.delay()); out.writeInt(trust.intervals()); out.write(trust.commitment());
        // Preserve sequence allocation across sender restores; the flag distinguishes sender stores.
        out.writeLong(nextSequence); out.writeBoolean(keys != null);
        if (keys != null) for (byte[] key : keys) out.write(key);
        out.writeInt(disclosed.size());
        for (var entry : disclosed.entrySet()) { out.writeInt(entry.getKey()); out.write(entry.getValue()); }
        return bytes.toByteArray();
    }
    /** Check structure and key-chain consistency even after successful file authentication. */
    private static Hsm deserialize(byte[] bytes, Clock clock, Trace trace) throws IOException {
        try {
            var in = new DataInputStream(new ByteArrayInputStream(bytes)); Hsm hsm = new Hsm(clock, trace);
            UUID session = new UUID(in.readLong(), in.readLong());
            hsm.trust = new Trust(session, in.readLong(), in.readLong(), in.readInt(), in.readInt(), readKey(in));
            hsm.nextSequence = in.readLong(); if (hsm.nextSequence < 0) throw new IOException("Invalid sequence");
            if (in.readBoolean()) {
                hsm.keys = new byte[hsm.trust.intervals() + 1][];
                for (int i = 0; i < hsm.keys.length; i++) hsm.keys[i] = readKey(in);
                // Every adjacent key must hash to its predecessor, and K[0] must match the commitment.
                if (!MessageDigest.isEqual(hsm.keys[0], hsm.trust.commitment())) throw new IOException("Invalid commitment");
                for (int i = 1; i < hsm.keys.length; i++) if (!MessageDigest.isEqual(hash(hsm.keys[i]), hsm.keys[i - 1])) throw new IOException("Invalid chain");
            }
            int count = in.readInt(); if (count < 0 || count > hsm.trust.intervals()) throw new IOException("Invalid key count");
            for (int i = 0; i < count; i++) {
                int interval = in.readInt(); byte[] key = readKey(in); hsm.trust.checkInterval(interval);
                // Restored receiver keys must satisfy the same chain check as live disclosures.
                byte[] candidate = key; for (int j = 0; j <= interval; j++) candidate = hash(candidate);
                if (!MessageDigest.isEqual(candidate, hsm.trust.commitment()) || hsm.disclosed.put(interval, key) != null) throw new IOException("Invalid disclosed key");
            }
            if (in.available() != 0) throw new IOException("Trailing key store data");
            return hsm;
        } catch (IllegalArgumentException | ArithmeticException e) { throw new IOException("Malformed key store", e); }
    }
    /** readFully rejects truncated keys rather than silently accepting fewer than 32 bytes. */
    private static byte[] readKey(DataInputStream in) throws IOException {
        byte[] key = new byte[32]; in.readFully(key); return key;
    }
}
