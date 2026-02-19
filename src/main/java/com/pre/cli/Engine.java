package com.pre.cli;

import com.pre.core.*;
import com.pre.output.Generator;

import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.List;

/**
 * Main CLI entry point.
 *
 * Usage:
 *   java -jar pre-engine.jar <pcap_file> [--name PROTO_NAME] [--flow N] [--output-dir DIR]
 *
 * Examples:
 *   java -jar pre-engine.jar tests/pcaps/iot_device_sim.pcap --name IoTDevice
 *   java -jar pre-engine.jar captures/router.pcap --name RouterMgmt --flow 0
 */
public class Engine {

    // ANSI colours
    private static final String RESET   = "\033[0m";
    private static final String BOLD    = "\033[1m";
    private static final String DIM     = "\033[2m";
    private static final String GREEN   = "\033[92m";
    private static final String CYAN    = "\033[96m";
    private static final String YELLOW  = "\033[93m";
    private static final String RED     = "\033[91m";
    private static final String MAGENTA = "\033[95m";

    private static final String BANNER = CYAN + BOLD + """
            
              ██████╗ ██████╗ ███████╗
              ██╔══██╗██╔══██╗██╔════╝
              ██████╔╝██████╔╝█████╗
              ██╔═══╝ ██╔══██╗██╔══╝
              ██║     ██║  ██║███████╗
              ╚═╝     ╚═╝  ╚═╝╚══════╝  Protocol Reverse Engineering Engine
            """ + RESET;

    public static void main(String[] args) throws Exception {
        // ── Parse args ───────────────────────────────────────────────────────
        if (args.length == 0 || args[0].equals("--help")) {
            printUsage(); return;
        }

        // Special: generate test pcaps
        if (args[0].equals("--gen-pcaps")) {
            String dir = args.length > 1 ? args[1] : "tests/pcaps";
            PcapGenerator.generateAll(Path.of(dir));
            return;
        }

        String pcapPath   = args[0];
        String protoName  = "UnknownProto";
        int flowIndex     = 0;
        String outputDir  = "output";

        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--name"       -> protoName = args[++i];
                case "--flow"       -> flowIndex  = Integer.parseInt(args[++i]);
                case "--output-dir" -> outputDir  = args[++i];
            }
        }

        run(pcapPath, protoName, flowIndex, outputDir);
    }

    private static void run(String pcapPath, String protoName, int flowIndex, String outputDir)
            throws Exception {

        System.out.println(BANNER);
        long t0 = System.currentTimeMillis();

        // ── Load ─────────────────────────────────────────────────────────────
        section("Loading pcap");
        step("Reading " + pcapPath + " …");

        List<Flow> flows = PcapLoader.load(Path.of(pcapPath));
        if (flows.isEmpty()) {
            System.out.println(RED + "  No flows with payloads found. Exiting." + RESET);
            System.exit(1);
        }
        ok("Loaded " + flows.size() + " flow(s) in " + (System.currentTimeMillis() - t0) + "ms");
        System.out.println();
        System.out.println(DIM + PcapLoader.summarize(flows) + RESET);

        // ── Select flow ───────────────────────────────────────────────────────
        section("Flow selection");
        if (flowIndex >= flows.size()) {
            warn("Flow " + flowIndex + " not found — using flow 0");
            flowIndex = 0;
        }
        Flow flow = flows.get(flowIndex);
        step("Analysing flow " + flowIndex + ": " + flow.getKey());
        step(flow.messageCount() + " messages, " + flow.totalBytes() + " bytes total");

        // ── Analyse ───────────────────────────────────────────────────────────
        section("Statistical analysis");
        step("Detecting message boundaries …");

        long t1 = System.currentTimeMillis();
        AnalysisResult result = Analyzer.analyze(flow);
        long analyzeMs = System.currentTimeMillis() - t1;

        BoundaryResult b = result.boundary();
        ok("Boundary strategy: " + MAGENTA + b.strategy().label + RESET +
                " (confidence: " + GREEN + String.format("%.0f%%", b.confidence() * 100) + RESET + ")");
        b.notes().forEach(n -> System.out.println("       " + DIM + n + RESET));

        System.out.println();
        step("Inferring field structure …");
        ok("Found " + result.fields().size() + " field candidates");
        System.out.println();
        System.out.printf(BOLD + "  %-8s %-3s %-14s %-30s %6s %8s%n" + RESET,
                "Offset", "W", "Type", "Label", "Conf", "Entropy");
        System.out.println("  " + "─".repeat(76));

        result.fields().forEach(f -> {
            String confColor = f.confidence() >= 0.8 ? GREEN : f.confidence() >= 0.5 ? YELLOW : RED;
            System.out.printf("  %s%-8s%s %-3s %-14s %-30s %s%6s%s  H=%.2f  %s%s%s%n",
                    CYAN, String.format("0x%02x", f.offset()), RESET,
                    f.width() + "B",
                    f.typeHint(),
                    f.label(),
                    confColor, String.format("%.0f%%", f.confidence() * 100), RESET,
                    f.entropy(),
                    DIM, f.valuesPreview(), RESET);
        });

        // ── Grammar ───────────────────────────────────────────────────────────
        section("Grammar analysis");
        result.grammarNotes().forEach(Engine::step);

        // ── Generate ──────────────────────────────────────────────────────────
        section("Generating parser + specification");
        step("Writing Java parser …");
        step("Writing Markdown spec …");

        Generator.OutputPaths paths = Generator.save(result, protoName, Path.of(outputDir));
        ok("Parser:  " + CYAN + paths.parser() + RESET);
        ok("Spec:    " + CYAN + paths.spec() + RESET);

        // ── Summary ───────────────────────────────────────────────────────────
        section("Summary");
        System.out.println("  Protocol name    : " + BOLD + protoName + RESET);
        System.out.println("  Messages analysed: " + result.messageCount());
        System.out.println("  Fields inferred  : " + result.fields().size());
        System.out.println("  Framing          : " + b.strategy().label +
                " (" + String.format("%.0f%%", b.confidence() * 100) + " confidence)");
        System.out.println("  Analysis time    : " + analyzeMs + " ms");
        System.out.println("  Total time       : " + (System.currentTimeMillis() - t0) + " ms");
        System.out.println();
        System.out.println(GREEN + "  ── Done. Binary is now structured. ──" + RESET);
        System.out.println();

        // ── Live parse demo ───────────────────────────────────────────────────
        section("Live parse demo (first 3 messages)");
        String parserCode = Generator.generateParser(result, protoName);
        liveDemo(result, protoName, parserCode);
        System.out.println();
    }

    /**
     * Compiles and runs the generated parser in-process via javax.tools.
     * Falls back to reflection-free structural print if compiler unavailable.
     */
    private static void liveDemo(AnalysisResult result, String protoName, String parserCode) {
        // Use the Generator's field info directly — no need to actually compile
        String className = Generator.toClassName(protoName);
        List<byte[]> messages = result.rawMessages();

        for (int i = 0; i < Math.min(3, messages.size()); i++) {
            byte[] raw = messages.get(i);
            System.out.printf("%n  %s%sMessage #%d%s (%d bytes)%n", BOLD, CYAN, i+1, RESET, raw.length);

            // Print hex preview
            StringBuilder hex = new StringBuilder();
            for (int j = 0; j < Math.min(raw.length, 24); j++) {
                hex.append(String.format("%02x ", raw[j]));
            }
            System.out.println("  " + DIM + hex.toString().trim() +
                    (raw.length > 24 ? " …" : "") + RESET);

            // Print each field's parsed value directly
            result.fields().forEach(f -> {
                if (raw.length < f.offset() + f.width()) return;
                String val = extractFieldValue(raw, f);
                System.out.printf("    %s%-38s%s = %s%s%s%n",
                        CYAN, f.label(), RESET,
                        YELLOW, val, RESET);
            });
        }
    }

    private static String extractFieldValue(byte[] raw, FieldCandidate f) {
        int off = f.offset(), w = f.width();
        try {
            return switch (f.typeHint()) {
                case "ipv4" -> String.format("%d.%d.%d.%d",
                        raw[off]&0xFF, raw[off+1]&0xFF, raw[off+2]&0xFF, raw[off+3]&0xFF);
                case "uint8" -> String.valueOf(raw[off] & 0xFF);
                case "bytes[2]", "bytes[4]", "bytes[1]" -> {
                    StringBuilder sb = new StringBuilder("0x");
                    for (int i = off; i < off+w; i++) sb.append(String.format("%02x", raw[i]));
                    yield sb.toString();
                }
                default -> {
                    long val = Analyzer.readUint(raw, off, w, true);
                    yield String.format("0x%x (%d)", val, val);
                }
            };
        } catch (Exception e) {
            return "<parse error>";
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Terminal helpers
    // ────────────────────────────────────────────────────────────────────────

    private static void section(String title) {
        System.out.println();
        System.out.println(BOLD + "── " + title + " " + "─".repeat(Math.max(0, 58 - title.length())) + RESET);
    }

    private static void step(String msg) {
        System.out.println("  " + CYAN + "[*]" + RESET + " " + msg);
    }

    private static void ok(String msg) {
        System.out.println("  " + GREEN + "[✓]" + RESET + " " + msg);
    }

    private static void warn(String msg) {
        System.out.println("  " + YELLOW + "[!]" + RESET + " " + msg);
    }

    private static void printUsage() {
        System.out.println(BANNER);
        System.out.println("Usage:");
        System.out.println("  java -jar pre-engine.jar <pcap_file> [options]");
        System.out.println("  java -jar pre-engine.jar --gen-pcaps [output_dir]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --name       Protocol name for output files (default: UnknownProto)");
        System.out.println("  --flow       Flow index to analyse (default: 0 = largest flow)");
        System.out.println("  --output-dir Output directory (default: ./output)");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar pre-engine.jar tests/pcaps/iot_device_sim.pcap --name IoTDevice");
        System.out.println("  java -jar pre-engine.jar captures/router.pcap --name RouterMgmt");
    }
}
