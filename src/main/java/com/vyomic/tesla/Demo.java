package com.vyomic.tesla;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import static com.vyomic.tesla.Protocol.*;
/** Runs the complete authentication flow and demonstrates encrypted HSM persistence. */
public final class Demo {
    public static void main(String[] args) throws Exception {
        // --verbose enables intermediate explanations; the optional positional argument is the store path.
        boolean verbose = false;
        Path store = Path.of("demo.hsm");
        boolean storeProvided = false;
        for (String argument : args) {
            if (argument.equals("--verbose")) {
                verbose = true;
            } else if (argument.equals("--help")) {
                System.out.println("Usage: java -cp target/classes com.vyomic.tesla.Demo [--verbose] [store-path]");
                return;
            } else if (argument.startsWith("-") || storeProvided) {
                throw new IllegalArgumentException("Expected [--verbose] [store-path]; use --help for usage.");
            } else {
                store = Path.of(argument);
                storeProvided = true;
            }
        }
        Trace trace = verbose ? Trace.console(System.out) : Trace.disabled();
        trace.event("DEMO", "1. Create the sender key chain and bootstrap a separate receiver HSM.");
        // Step 1: Use controlled time so disclosure delays require no real sleeps.
        SimulationClock clock = new SimulationClock(1_000, trace);
        Hsm senderHsm = new Hsm(clock, trace);
        // Start now, use one-second intervals, disclose one interval later, and create three intervals.
        senderHsm.generate(clock.millis(), 1_000, 1, 3);
        Satellite satellite = new Satellite(senderHsm, trace);
        // Step 2: Bootstrap a separate receiver HSM with public trust data only.
        // Direct transfer models a trusted channel; zero means no clock uncertainty in this demo.
        Trust configuration = satellite.commitment();
        Receiver receiver = new Receiver(new Hsm(clock, trace), configuration, clock, 0, trace);

        trace.event("DEMO", "2. Send a valid message while its authentication key is still secret.");
        // Step 3: Send a tagged message. The receiver buffers it until its key becomes public.
        Message first = satellite.send("Position: 42".getBytes(StandardCharsets.UTF_8));
        System.out.println("Valid packet: " + receiver.receive(first));
        // Simulate an attacker changing protected fields while retaining the original MAC.
        trace.event("DEMO", "3. Modify protected fields but retain the original tag; verification must later fail.");
        Message altered = new Message(first.session(), first.interval(), first.sequence() + 100, "Position: 99".getBytes(StandardCharsets.UTF_8), first.tag());
        System.out.println("Modified packet: " + receiver.receive(altered));
        // Step 4: Reach interval 0's disclosure time (2,000 ms).
        trace.event("DEMO", "4. Advance to disclosure time and submit a fabricated key before the genuine key.");
        clock.advance(1_000);
        // A fabricated key fails chain validation without removing the buffered packets.
        printResults("Invalid key", receiver.receive(new Disclosure(first.session(), 0, new byte[32])));
        // The real key authenticates the original packet and exposes the modified packet's bad MAC.
        printResults("Interval 0 disclosure", receiver.receive(satellite.disclose(0)));
        // Step 5: A previously accepted sequence number cannot be accepted again.
        trace.event("DEMO", "5. Replay the accepted message; its sequence is already recorded.");
        System.out.println("Replay: " + receiver.receive(first));
        // Step 6: Repeat with interval 1, which uses a different authentication key.
        trace.event("DEMO", "6. Repeat authentication and delayed disclosure in the next interval.");
        Message second = satellite.send("Position: 43".getBytes(StandardCharsets.UTF_8));
        System.out.println("Second interval packet: " + receiver.receive(second));
        clock.advance(1_000);
        printResults("Interval 1 disclosure", receiver.receive(satellite.disclose(1)));
        // Step 7: Encrypt the sender's state, then restore it using TESLA_MASTER_KEY.
        trace.event("DEMO", "7. Export and restore the encrypted HSM state using the environment master key.");
        senderHsm.exportStore(store);
        Hsm restored = Hsm.importStore(store, clock, trace);
        System.out.println("AES-256-GCM store restored: " + restored.configuration().session().equals(configuration.session()));
    }
    /** Print outcomes without dumping payloads or key material. */
    private static void printResults(String label, java.util.List<Receiver.Result> results) {
        for (Receiver.Result result : results) {
            String sequence = result.message() == null ? "" : " sequence=" + result.message().sequence();
            System.out.println(label + sequence + ": " + result.status());
        }
    }
}
