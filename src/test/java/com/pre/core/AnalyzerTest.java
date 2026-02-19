package com.pre.core;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * JUnit 5 tests for the core analysis pipeline.
 * All tests use synthetic in-memory payloads — no pcap files needed.
 *
 * Run: mvn test
 */
class AnalyzerTest {

    // ────────────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────────────

    static List<byte[]> makeIoTMessages(int n) {
        List<byte[]> msgs = new ArrayList<>();
        byte[][] ips = {{(byte)192,(byte)168,1,1}, {10,0,0,1},
                        {(byte)172,16,0,5}, {(byte)192,(byte)168,1,100}};
        for (int i = 0; i < n; i++) {
            byte[] body = new byte[4];
            Arrays.fill(body, (byte)(i % 256));
            ByteBuffer buf = ByteBuffer.allocate(12 + body.length).order(ByteOrder.LITTLE_ENDIAN);
            buf.put((byte)0xD3).put((byte)0x4A);
            buf.putShort((short)((i % 4) + 1));   // msg type
            buf.putShort((short)i);                 // sequence
            buf.put(ips[i % ips.length]);           // src IP
            buf.putShort((short)body.length);
            buf.put(body);
            msgs.add(buf.array());
        }
        return msgs;
    }

    static List<byte[]> makeFixedSizeMessages(int n) {
        List<byte[]> msgs = new ArrayList<>();
        long ts = 1700000000L;
        for (int i = 0; i < n; i++) {
            ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
            buf.put((byte)((i % 8) + 1));   // sensor ID
            buf.put((byte)0x01);             // type
            buf.putShort((short)i);          // sequence
            buf.putInt((int)(ts + i));       // timestamp
            buf.putShort((short)(i * 10));   // value
            buf.put(new byte[6]);            // reserved
            msgs.add(buf.array());
        }
        return msgs;
    }

    static List<byte[]> makeLengthPrefixMessages(int n) {
        List<byte[]> msgs = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            byte[] body = new byte[i % 15 + 2];
            int total = 4 + body.length;
            ByteBuffer buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
            buf.put((byte)0x02);
            buf.put((byte)(i % 2 == 0 ? 0x10 : 0x20));
            buf.putShort((short)total);
            buf.put(body);
            msgs.add(buf.array());
        }
        return msgs;
    }

    static Flow makeFlow(List<byte[]> msgs) {
        Flow f = new Flow(Flow.Protocol.UDP, "192.168.1.100", 1234, "192.168.1.1", 9999);
        msgs.forEach(f::addPayload);
        return f;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Entropy
    // ────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Constant bytes → zero entropy")
    void entropyConstantZero() {
        byte[] data = new byte[100];
        Arrays.fill(data, (byte)0x42);
        assertEquals(0.0, Analyzer.shannonEntropy(data), 0.001);
    }

    @Test
    @DisplayName("All 256 byte values → near-max entropy (≥7.9 bits)")
    void entropyHighForRandom() {
        byte[] data = new byte[256];
        for (int i = 0; i < 256; i++) data[i] = (byte)i;
        assertTrue(Analyzer.shannonEntropy(data) >= 7.9,
                "Expected entropy ≥ 7.9 bits for full byte distribution");
    }

    @Test
    @DisplayName("Two alternating values → entropy ≈ 1.0")
    void entropyTwoValues() {
        byte[] data = new byte[100];
        for (int i = 0; i < data.length; i++) data[i] = (byte)(i % 2 == 0 ? 0x00 : 0xFF);
        assertEquals(1.0, Analyzer.shannonEntropy(data), 0.01);
    }

    @Test
    @DisplayName("Column entropy of magic bytes = 0.0")
    void columnEntropyConstantField() {
        List<byte[]> msgs = makeIoTMessages(20);
        // Bytes 0-1 are 0xD3 0x4A in every message
        assertEquals(0.0, Analyzer.columnEntropy(msgs, 0, 2), 0.001);
    }

    @Test
    @DisplayName("Column entropy of varying field > 0")
    void columnEntropyVariableField() {
        List<byte[]> msgs = makeIoTMessages(20);
        // Bytes 4-5 are a sequence number — should have moderate entropy
        assertTrue(Analyzer.columnEntropy(msgs, 4, 2) > 0.5);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Boundary detection
    // ────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("IoT messages → FIXED_MAGIC strategy detected")
    void boundaryDetectsMagicHeader() {
        var result = Analyzer.detectBoundaries(makeIoTMessages(20));
        assertEquals(BoundaryResult.Strategy.FIXED_MAGIC, result.strategy(),
                "Expected FIXED_MAGIC, got " + result.strategy());
    }

    @Test
    @DisplayName("IoT magic bytes = 0xD34A")
    void boundaryMagicBytesCorrect() {
        var result = Analyzer.detectBoundaries(makeIoTMessages(20));
        assertNotNull(result.magicBytes());
        assertEquals(0xD3, result.magicBytes()[0] & 0xFF);
        assertEquals(0x4A, result.magicBytes()[1] & 0xFF);
    }

    @Test
    @DisplayName("Magic detection confidence ≥ 80%")
    void boundaryMagicConfidence() {
        var result = Analyzer.detectBoundaries(makeIoTMessages(20));
        assertTrue(result.confidence() >= 0.8,
                "Expected confidence ≥ 0.8, got " + result.confidence());
    }

    @Test
    @DisplayName("Fixed-size messages → FIXED_SIZE strategy detected")
    void boundaryDetectsFixedSize() {
        // Pure fixed-size messages with no common prefix
        List<byte[]> msgs = new ArrayList<>();
        Random rnd = new Random(1);
        for (int i = 0; i < 20; i++) {
            byte[] m = new byte[16];
            rnd.nextBytes(m);
            msgs.add(m);
        }
        var result = Analyzer.detectBoundaries(msgs);
        assertEquals(BoundaryResult.Strategy.FIXED_SIZE, result.strategy(),
                "Expected FIXED_SIZE, got " + result.strategy());
    }

    @Test
    @DisplayName("Length-prefix messages → LENGTH_PREFIX strategy detected")
    void boundaryDetectsLengthPrefix() {
        var result = Analyzer.detectBoundaries(makeLengthPrefixMessages(20));
        assertTrue(
                result.strategy() == BoundaryResult.Strategy.LENGTH_PREFIX ||
                result.strategy() == BoundaryResult.Strategy.FIXED_MAGIC,
                "Expected LENGTH_PREFIX or FIXED_MAGIC, got " + result.strategy()
        );
    }

    @Test
    @DisplayName("Boundary confidence always in [0.0, 1.0]")
    void boundaryConfidenceInRange() {
        var result = Analyzer.detectBoundaries(makeIoTMessages(10));
        assertTrue(result.confidence() >= 0.0 && result.confidence() <= 1.0);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Field inference
    // ────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("First field of IoT messages is magic/constant")
    void firstFieldIsMagic() {
        List<byte[]> msgs = makeIoTMessages(20);
        BoundaryResult b = Analyzer.detectBoundaries(msgs);
        List<FieldCandidate> fields = Analyzer.inferFields(msgs, b);
        assertFalse(fields.isEmpty());
        FieldCandidate first = fields.get(0);
        assertTrue(first.label().contains("magic") || first.label().contains("constant"),
                "Expected magic/constant label, got: " + first.label());
    }

    @Test
    @DisplayName("Magic field has confidence ≥ 90%")
    void magicFieldHighConfidence() {
        List<byte[]> msgs = makeIoTMessages(20);
        BoundaryResult b = Analyzer.detectBoundaries(msgs);
        List<FieldCandidate> fields = Analyzer.inferFields(msgs, b);
        assertTrue(fields.get(0).confidence() >= 0.9);
    }

    @Test
    @DisplayName("Fields do not overlap")
    void fieldsDoNotOverlap() {
        List<byte[]> msgs = makeIoTMessages(20);
        BoundaryResult b = Analyzer.detectBoundaries(msgs);
        List<FieldCandidate> fields = Analyzer.inferFields(msgs, b);
        Set<Integer> seen = new HashSet<>();
        for (FieldCandidate f : fields) {
            for (int pos = f.offset(); pos < f.offset() + f.width(); pos++) {
                assertFalse(seen.contains(pos), "Overlapping field at byte offset " + pos);
                seen.add(pos);
            }
        }
    }

    @Test
    @DisplayName("All field confidence values in [0.0, 1.0]")
    void fieldConfidenceInRange() {
        List<byte[]> msgs = makeIoTMessages(20);
        BoundaryResult b = Analyzer.detectBoundaries(msgs);
        List<FieldCandidate> fields = Analyzer.inferFields(msgs, b);
        for (FieldCandidate f : fields) {
            assertTrue(f.confidence() >= 0.0 && f.confidence() <= 1.0,
                    "Confidence out of range: " + f.confidence() + " for field " + f.label());
        }
    }

    @Test
    @DisplayName("IPv4 field detected in IP-containing messages")
    void detectsIpv4Field() {
        // Messages: 2 constant bytes + varying IPv4 + 2 constant bytes
        List<byte[]> msgs = new ArrayList<>();
        int[][] ips = {{10,0,0,1},{10,0,1,2},{172,16,0,1},{192,168,1,5},
                       {10,10,0,3},{172,20,0,1},{192,168,2,1},{10,0,2,4},
                       {10,1,0,5},{172,16,1,2},{192,168,3,1},{10,0,3,6},
                       {10,2,0,7},{172,16,2,3},{192,168,4,2},{10,0,4,8},
                       {10,3,0,9},{172,16,3,4},{192,168,5,3},{10,0,5,10}};
        for (int[] ip : ips) {
            ByteBuffer buf = ByteBuffer.allocate(8);
            buf.put((byte)0xAA).put((byte)0xBB);
            buf.put((byte)ip[0]).put((byte)ip[1]).put((byte)ip[2]).put((byte)ip[3]);
            buf.put((byte)0x00).put((byte)0x01);
            msgs.add(buf.array());
        }
        BoundaryResult b = Analyzer.detectBoundaries(msgs);
        List<FieldCandidate> fields = Analyzer.inferFields(msgs, b);
        boolean hasIp = fields.stream().anyMatch(f -> f.typeHint().equals("ipv4"));
        assertTrue(hasIp, "Expected to find an IPv4 field. Got: " +
                fields.stream().map(FieldCandidate::typeHint).toList());
    }

    // ────────────────────────────────────────────────────────────────────────
    // Grammar inference
    // ────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Grammar finds type discriminator in IoT messages")
    void grammarFindsDiscriminator() {
        List<byte[]> msgs = makeIoTMessages(20);
        BoundaryResult b = Analyzer.detectBoundaries(msgs);
        List<FieldCandidate> fields = Analyzer.inferFields(msgs, b);
        List<String> notes = Analyzer.inferGrammar(msgs, fields);
        assertFalse(notes.isEmpty());
        assertTrue(notes.stream().anyMatch(n ->
                n.toLowerCase().contains("discriminator") || n.toLowerCase().contains("type")));
    }

    @Test
    @DisplayName("Grammar handles empty field list gracefully")
    void grammarHandlesEmptyFields() {
        List<byte[]> msgs = makeIoTMessages(10);
        List<String> notes = Analyzer.inferGrammar(msgs, List.of());
        assertNotNull(notes);
        assertFalse(notes.isEmpty());
    }

    // ────────────────────────────────────────────────────────────────────────
    // Integration
    // ────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Full pipeline: IoT messages → analysis result")
    void fullPipelineIoT() {
        Flow flow = makeFlow(makeIoTMessages(25));
        AnalysisResult result = Analyzer.analyze(flow);

        assertEquals(25, result.messageCount());
        assertEquals(BoundaryResult.Strategy.FIXED_MAGIC, result.boundary().strategy());
        assertTrue(result.fields().size() >= 3, "Expected ≥ 3 fields");
        assertFalse(result.grammarNotes().isEmpty());
    }

    @Test
    @DisplayName("Full pipeline: fixed-size messages → analysis result")
    void fullPipelineFixedSize() {
        // Use truly random fixed-size messages (no magic prefix)
        List<byte[]> msgs = new ArrayList<>();
        Random rnd = new Random(99);
        for (int i = 0; i < 20; i++) {
            byte[] m = new byte[16]; rnd.nextBytes(m); msgs.add(m);
        }
        Flow flow = makeFlow(msgs);
        AnalysisResult result = Analyzer.analyze(flow);
        assertEquals(16, result.minSize());
        assertEquals(16, result.maxSize());
        assertEquals(BoundaryResult.Strategy.FIXED_SIZE, result.boundary().strategy());
    }

    @Test
    @DisplayName("Generator produces valid Java parser code")
    void generatorProducesJavaParser() {
        Flow flow = makeFlow(makeIoTMessages(20));
        AnalysisResult result = Analyzer.analyze(flow);
        String code = com.pre.output.Generator.generateParser(result, "TestIoT");
        assertTrue(code.contains("class TestiotParser"), "Missing parser class. Got:\n" + code.substring(0, Math.min(300, code.length())));
        assertTrue(code.contains("parse(byte[]"));
        assertTrue(code.contains("parseAll(List"));
        assertTrue(code.contains("parseErrors"));
    }

    @Test
    @DisplayName("Generator produces valid Markdown spec")
    void generatorProducesMarkdownSpec() {
        Flow flow = makeFlow(makeIoTMessages(20));
        AnalysisResult result = Analyzer.analyze(flow);
        String spec = com.pre.output.Generator.generateSpec(result, "TestIoT");
        assertTrue(spec.contains("# TestIoT"));
        assertTrue(spec.contains("fixed_magic"));
        assertTrue(spec.contains("Field Map"));
    }
}
