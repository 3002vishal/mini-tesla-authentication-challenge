package com.vyomic.tesla;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static com.vyomic.tesla.Protocol.*;

/** Exercises protocol safety and encrypted persistence with deterministic time and real cryptography. */
class ProtocolTest {
    SimulationClock clock; Hsm sender; Satellite satellite; Receiver receiver;
    // Each test gets a fresh session, four one-second intervals, and separate participant HSMs.
    @BeforeEach void setup() {
        clock = new SimulationClock(1_000); sender = new Hsm(clock);
        sender.generate(1_000, 1_000, 1, 4); satellite = new Satellite(sender);
        receiver = new Receiver(new Hsm(clock), satellite.commitment(), clock, 0);
    }
    // Payload content is arbitrary; timing, metadata, and MAC checks are what these tests exercise.
    Message message() { return satellite.send(new byte[]{1, 2, 3}); }
    // A message stays pending until disclosure; acceptance also enables replay rejection.
    @Test void delayedAuthenticationAcrossIntervalsAndReplay() {
        Message first = message(); assertEquals(Receiver.Status.BUFFERED, receiver.receive(first));
        assertThrows(IllegalStateException.class, () -> satellite.disclose(0));
        clock.advance(1_000);
        assertEquals(Receiver.Status.ACCEPTED, receiver.receive(satellite.disclose(0)).get(0).status());
        assertEquals(Receiver.Status.REPLAY, receiver.receive(first));
        assertEquals(Receiver.Status.BUFFERED, receiver.receive(message())); clock.advance(1_000);
        assertEquals(Receiver.Status.ACCEPTED, receiver.receive(satellite.disclose(1)).get(0).status());
    }
    // Forged packets sharing a valid sequence must not prevent the genuine packet's acceptance.
    @Test void modifiedPayloadTagAndMetadataRejectedWithoutPoisoningReplayState() {
        Message valid = message(); byte[] badTag = valid.tag(); badTag[0] ^= 1;
        receiver.receive(new Message(valid.session(), 0, valid.sequence(), new byte[]{9}, valid.tag()));
        receiver.receive(new Message(valid.session(), 0, valid.sequence(), valid.payload(), badTag));
        receiver.receive(new Message(valid.session(), 0, valid.sequence() + 1, valid.payload(), valid.tag()));
        receiver.receive(valid); clock.advance(1_000);
        assertEquals(java.util.List.of(Receiver.Status.BAD_MAC, Receiver.Status.BAD_MAC, Receiver.Status.BAD_MAC, Receiver.Status.ACCEPTED), receiver.receive(satellite.disclose(0)).stream().map(Receiver.Result::status).toList());
    }
    // Replay detection must also run when draining the buffer, not only on packet arrival.
    @Test void duplicateBufferedPacketAcceptedOnlyOnce() {
        Message packet = message(); receiver.receive(packet); receiver.receive(packet); clock.advance(1_000);
        assertEquals(java.util.List.of(Receiver.Status.ACCEPTED, Receiver.Status.REPLAY), receiver.receive(satellite.disclose(0)).stream().map(Receiver.Result::status).toList());
    }
    // A malicious disclosure must not discard messages waiting for the correct key.
    @Test void badKeyDoesNotDrainBuffer() {
        receiver.receive(message()); clock.advance(1_000);
        assertEquals(Receiver.Status.BAD_KEY, receiver.receive(new Disclosure(satellite.commitment().session(), 0, new byte[32])).get(0).status());
        assertEquals(Receiver.Status.ACCEPTED, receiver.receive(satellite.disclose(0)).get(0).status());
    }
    // The schedule closes the arrival window even when no disclosure packet has reached us.
    @Test void lateArrivalRejectedEvenIfDisclosurePacketIsDelayed() {
        Message packet = message(); clock.advance(1_000);
        assertEquals(Receiver.Status.UNSAFE_TIME, receiver.receive(packet));
    }
    // With 100 ms uncertainty, a local arrival at 1,900 ms may already be at disclosure time.
    @Test void clockUncertaintyClosesSafetyWindowEarly() {
        Receiver cautious = new Receiver(new Hsm(clock), satellite.commitment(), clock, 100);
        Message packet = message(); clock.advance(900);
        assertEquals(Receiver.Status.UNSAFE_TIME, cautious.receive(packet));
    }
    // Validate each key against the original commitment, allowing interval 1 before interval 0.
    @Test void reorderingDisclosuresWorks() {
        receiver.receive(message()); clock.advance(1_000); receiver.receive(message()); clock.advance(1_000);
        assertEquals(Receiver.Status.ACCEPTED, receiver.receive(satellite.disclose(1)).get(0).status());
        assertEquals(Receiver.Status.ACCEPTED, receiver.receive(satellite.disclose(0)).get(0).status());
    }
    // Distinguish invalid session/range, an interval not yet open, and malformed packet structure.
    @Test void wrongSessionFutureIntervalAndMalformedPackets() {
        Message p = message();
        assertEquals(Receiver.Status.WRONG_SESSION, receiver.receive(new Message(UUID.randomUUID(), 0, 0, p.payload(), p.tag())));
        assertEquals(Receiver.Status.INVALID_INTERVAL, receiver.receive(new Message(p.session(), 4, 0, p.payload(), p.tag())));
        assertEquals(Receiver.Status.UNSAFE_TIME, receiver.receive(new Message(p.session(), 1, 0, p.payload(), p.tag())));
        assertThrows(IllegalArgumentException.class, () -> new Message(p.session(), 0, 0, p.payload(), new byte[1]));
        assertThrows(IllegalArgumentException.class, () -> new Disclosure(p.session(), -1, new byte[32]));
    }
    // Mutating arrays returned by accessors must leave packets and trusted commitments unchanged.
    @Test void packetArraysAreDefensivelyCopied() {
        Message p = message(); byte[] original = p.payload(); p.payload()[0] ^= 1;
        assertArrayEquals(original, p.payload()); byte[] c = satellite.commitment().commitment(); c[0] ^= 1;
        receiver.receive(p); clock.advance(1_000);
        assertEquals(Receiver.Status.ACCEPTED, receiver.receive(satellite.disclose(0)).get(0).status());
    }
    // Pending packets cannot grow memory without a fixed limit, even when keys never arrive.
    @Test void bufferHasBound() {
        Message p = message(); for (int i = 0; i < 1024; i++) assertEquals(Receiver.Status.BUFFERED, receiver.receive(p));
        assertEquals(Receiver.Status.BUFFER_FULL, receiver.receive(p));
    }
    // JUnit supplies an isolated temporary directory and cleans up the encrypted test files.
    @Test void encryptedRoundTripAndTampering(@TempDir Path dir) throws Exception {
        assertNotNull(System.getenv("TESLA_MASTER_KEY"), "Set TESLA_MASTER_KEY before running tests");
        Message before = message(); Path store = dir.resolve("keys.hsm"); sender.exportStore(store);
        // Identical plaintext exports should differ because encryption uses a fresh random nonce.
        byte[] firstExport = Files.readAllBytes(store); sender.exportStore(store);
        assertFalse(java.util.Arrays.equals(firstExport, Files.readAllBytes(store)), "Each export needs a fresh nonce");
        Hsm restored = Hsm.importStore(store, clock);
        assertEquals(sender.configuration().session(), restored.configuration().session());
        // Restoring must preserve sequence allocation and the original disclosure deadline.
        assertTrue(restored.authenticate(new byte[]{4}).sequence() > before.sequence());
        assertThrows(IllegalStateException.class, () -> restored.disclose(0));
        receiver.receive(before); clock.advance(1_000);
        assertEquals(Receiver.Status.ACCEPTED, receiver.receive(restored.disclose(0)).get(0).status());
        // Changing even one bit of the stored GCM tag must prevent a successful import.
        byte[] damaged = Files.readAllBytes(store); damaged[damaged.length - 1] ^= 1; Files.write(store, damaged);
        assertThrows(javax.crypto.AEADBadTagException.class, () -> Hsm.importStore(store, clock));
        Files.write(store, new byte[]{1}); assertThrows(java.io.IOException.class, () -> Hsm.importStore(store, clock));
    }
}
