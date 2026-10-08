package com.vyomic.tesla;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.vyomic.tesla.Protocol.Disclosure;
import com.vyomic.tesla.Protocol.Message;

/** Checks that tracing explains execution without changing protocol behavior or exposing keys. */
class TraceTest {
    private static final String PRIVATE_PAYLOAD = "private-payload-must-not-appear-in-trace";

    @Test
    void existingConstructorsKeepNormalExecutionQuiet() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        PrintStream originalOutput = System.out;

        // Capture the default console so accidental prints inside any component are detected.
        try (PrintStream console = new PrintStream(output, true, StandardCharsets.UTF_8)) {
            System.setOut(console);
            try {
                SimulationClock clock = new SimulationClock(1_000);
                Hsm senderHsm = new Hsm(clock);
                senderHsm.generate(1_000, 1_000, 1, 3);
                Satellite satellite = new Satellite(senderHsm);
                Receiver receiver = new Receiver(new Hsm(clock), satellite.commitment(), clock, 0);

                Message message = satellite.send(payload());
                assertEquals(Receiver.Status.BUFFERED, receiver.receive(message));
                clock.advance(1_000);
                assertEquals(Receiver.Status.ACCEPTED,
                        receiver.receive(satellite.disclose(0)).get(0).status());
                assertEquals(Receiver.Status.REPLAY, receiver.receive(message));
            } finally {
                System.setOut(originalOutput);
            }
        }

        assertEquals("", output.toString(StandardCharsets.UTF_8));
    }

    @Test
    void verboseTraceExplainsBufferingValidationTamperingAndReplay() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (PrintStream console = new PrintStream(output, true, StandardCharsets.UTF_8)) {
            Trace trace = Trace.console(console);
            SimulationClock clock = new SimulationClock(1_000, trace);
            Hsm senderHsm = new Hsm(clock, trace);
            senderHsm.generate(1_000, 1_000, 1, 3);
            Satellite satellite = new Satellite(senderHsm, trace);
            Receiver receiver = new Receiver(new Hsm(clock, trace), satellite.commitment(), clock, 0, trace);

            Message original = satellite.send(payload());
            Message altered = new Message(original.session(), original.interval(), original.sequence() + 100,
                    "changed-private-payload".getBytes(StandardCharsets.UTF_8), original.tag());
            assertEquals(Receiver.Status.BUFFERED, receiver.receive(original));
            assertEquals(Receiver.Status.BUFFERED, receiver.receive(altered));
            clock.advance(1_000);

            List<Receiver.Result> badKeyResults = receiver.receive(
                    new Disclosure(original.session(), original.interval(), new byte[32]));
            assertEquals(Receiver.Status.BAD_KEY, badKeyResults.get(0).status());

            Disclosure disclosure = satellite.disclose(0);
            List<Receiver.Result> verified = receiver.receive(disclosure);
            assertEquals(2, verified.size());
            assertTrue(verified.stream().anyMatch(result -> result.status() == Receiver.Status.ACCEPTED));
            assertTrue(verified.stream().anyMatch(result -> result.status() == Receiver.Status.BAD_MAC));
            assertEquals(Receiver.Status.REPLAY, receiver.receive(original));

            String transcript = output.toString(StandardCharsets.UTF_8);
            assertTrue(transcript.contains("[SATELLITE]"), transcript);
            assertTrue(transcript.contains("[SENDER HSM]"), transcript);
            assertOrdered(transcript,
                    "[RECEIVER] BUFFERED",
                    "[CLOCK] Advanced time",
                    "[RECEIVER HSM] Key-chain validation failed",
                    "[RECEIVER HSM] Key-chain validation passed",
                    "[RECEIVER HSM] MAC verification passed",
                    "[RECEIVER] ACCEPTED");
            assertOrdered(transcript,
                    "[RECEIVER HSM] MAC verification failed",
                    "[RECEIVER] BAD_MAC",
                    "[RECEIVER] REPLAY");
            assertFalse(transcript.contains(PRIVATE_PAYLOAD));
            assertFalse(transcript.contains("changed-private-payload"));
            assertKeyAbsent(transcript, disclosure.key());
            assertKeyAbsent(transcript, original.tag());
        }
    }

    @Test
    void persistenceTraceExplainsEncryptionAndRestoreWithoutExposingState(@TempDir Path directory)
            throws Exception {
        String masterKey = System.getenv("TESLA_MASTER_KEY");
        assumeTrue(masterKey != null && !masterKey.isBlank(), "Persistence requires TESLA_MASTER_KEY");

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (PrintStream console = new PrintStream(output, true, StandardCharsets.UTF_8)) {
            Trace trace = Trace.console(console);
            SimulationClock clock = new SimulationClock(1_000, trace);
            Hsm senderHsm = new Hsm(clock, trace);
            senderHsm.generate(1_000, 1_000, 1, 3);
            Satellite satellite = new Satellite(senderHsm, trace);
            Message original = satellite.send(payload());

            Path store = directory.resolve("trace-test.hsm");
            senderHsm.exportStore(store);
            Hsm restored = Hsm.importStore(store, clock, trace);
            Message resumed = new Satellite(restored, trace).send(payload());

            // The traced restore must preserve the protocol session and sequence counter.
            assertEquals(original.session(), resumed.session());
            assertEquals(original.sequence() + 1, resumed.sequence());
            clock.advance(1_000);
            Disclosure disclosure = satellite.disclose(0);

            String transcript = output.toString(StandardCharsets.UTF_8);
            assertOrdered(transcript,
                    "[SENDER HSM] Encrypting key store with AES-256-GCM",
                    "[SENDER HSM] Encrypted key store exported",
                    "[HSM] Authenticating and decrypting key store",
                    "[SENDER HSM] Key store imported");
            assertFalse(transcript.contains(masterKey));
            assertFalse(transcript.contains(PRIVATE_PAYLOAD));
            assertKeyAbsent(transcript, disclosure.key());
        }
    }

    private static byte[] payload() {
        return PRIVATE_PAYLOAD.getBytes(StandardCharsets.UTF_8);
    }

    private static void assertKeyAbsent(String transcript, byte[] value) {
        assertFalse(transcript.contains(Base64.getEncoder().encodeToString(value)),
                "Trace must not contain encoded key or MAC bytes");
        assertFalse(transcript.toLowerCase().contains(HexFormat.of().formatHex(value)),
                "Trace must not contain hexadecimal key or MAC bytes");
    }

    private static void assertOrdered(String transcript, String... events) {
        int position = 0;
        for (String event : events) {
            int next = transcript.indexOf(event, position);
            assertTrue(next >= 0, "Missing or out-of-order trace event: " + event + "\n" + transcript);
            position = next + event.length();
        }
    }
}
