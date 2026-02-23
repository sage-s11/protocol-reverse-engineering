package com.pre.core;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * Reassembles TCP byte streams into application-layer messages.
 *
 * TCP is a byte stream — segments can split or merge application messages
 * arbitrarily. This class:
 *   1. Concatenates per-direction TCP payloads into a byte stream
 *   2. Detects application-layer message boundaries via heuristics
 *   3. Splits the stream into individual messages for protocol analysis
 *
 * Supported framing strategies:
 *   - Length-prefix: first 1/2/4 bytes encode message length
 *   - Line-delimited: messages end with \r\n (SMTP, IRC, HTTP)
 *   - Fixed-size: all messages same length (unlikely for C2, but handled)
 *   - Fallback: scan for repeating byte patterns at regular intervals
 */
public class TcpReassembler {

    /** Result of reassembly: the detected messages and framing info */
    public record ReassemblyResult(
            List<byte[]> messages,
            String framingMethod,
            int streamBytes
    ) {}

    /**
     * Reassemble a TCP flow's raw segments into application-layer messages.
     *
     * Takes the raw payloads (one per TCP segment, in capture order)
     * and attempts to find message boundaries.
     *
     * @param segments Raw TCP segment payloads in capture order
     * @param srcIp    Source IP of flow (to separate directions)
     * @param srcPort  Source port of flow
     * @return Reassembled application-layer messages
     */
    public static ReassemblyResult reassemble(List<byte[]> segments,
                                               String srcIp, int srcPort,
                                               String dstIp, int dstPort) {
        if (segments.isEmpty()) {
            return new ReassemblyResult(List.of(), "none", 0);
        }

        // Concatenate all segments into one byte stream
        // (We don't have sequence numbers from pcap4j's high-level API,
        //  but segments arrive in capture order which is almost always
        //  correct for non-lossy captures.)
        byte[] stream = concatenate(segments);

        if (stream.length == 0) {
            return new ReassemblyResult(List.of(), "none", 0);
        }

        // Strategy 1: Line-delimited (cleartext text protocols)
        ReassemblyResult result = tryLineDelimited(stream);
        if (result != null) return result;

        // Strategy 2: Length-prefix with width ≥ 2 (strong binary framing)
        // Try this before XOR — if we find solid 2-byte or 4-byte length fields,
        // the protocol is binary-framed, not XOR'd text.
        result = tryLengthPrefix(stream);
        if (result != null) return result;

        // Strategy 3: XOR + framing (obfuscated text protocols like IRC bots)
        // Only reach here if no line-delimited AND no length-prefix matched.
        // This limits the expensive brute-force to streams with no clear structure.
        if (stream.length > 100 && stream.length < 500000) { // cap at 500KB for performance
            // Build chunks for XOR detector
            List<byte[]> chunks = new ArrayList<>();
            int chunkSize = Math.min(512, stream.length / 4);
            if (chunkSize < 50) chunkSize = stream.length;
            for (int i = 0; i < stream.length && chunks.size() < 30; i += chunkSize) {
                int end = Math.min(i + chunkSize, stream.length);
                chunks.add(java.util.Arrays.copyOfRange(stream, i, end));
            }

            XorDeobfuscator.XorResult xor = XorDeobfuscator.detect(chunks);
            if (xor.detected() && xor.confidence() >= 0.50) {
                byte[] decStream = new byte[stream.length];
                for (int i = 0; i < stream.length; i++) {
                    decStream[i] = (byte)(stream[i] ^ xor.key()[i % xor.key().length]);
                }
                ReassemblyResult decResult = tryLineDelimited(decStream);
                if (decResult == null) decResult = tryLengthPrefix(decStream);
                if (decResult != null) {
                    return new ReassemblyResult(decResult.messages(),
                            "xor(" + xor.keyHex() + ")+" + decResult.framingMethod(),
                            stream.length);
                }
            }
        }

        // Strategy 4: Repeating header pattern
        result = tryRepeatingPattern(stream, segments);
        if (result != null) return result;

        // Fallback
        return new ReassemblyResult(segments, "raw_segments", stream.length);
    }

    /** Try all framing strategies on a stream, return null if none match */
    private static ReassemblyResult tryFraming(byte[] stream, List<byte[]> origSegments) {
        ReassemblyResult result;
        result = tryLineDelimited(stream);
        if (result != null) return result;
        result = tryLengthPrefix(stream);
        if (result != null) return result;
        result = tryRepeatingPattern(stream, origSegments);
        if (result != null) return result;
        return null;
    }

    /** Try all framing strategies, fall back to raw segments */
    private static ReassemblyResult tryFramingOrFallback(byte[] stream, List<byte[]> segments) {
        ReassemblyResult result = tryFraming(stream, segments);
        if (result != null) return result;
        return new ReassemblyResult(segments, "raw_segments", stream.length);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Strategy 1: Length-prefix framing
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Scan the stream for length-prefix framing.
     * Tests offset 0..7, widths 1/2/4, both endians.
     * A match means: reading the length field, then skipping that many bytes,
     * lands on another valid length field, repeatedly.
     */
    private static ReassemblyResult tryLengthPrefix(byte[] stream) {
        if (stream.length < 8) return null;

        int bestOffset = -1, bestWidth = -1;
        boolean bestBE = true;
        int bestCount = 0;
        String bestMode = null;  // "remainder" or "total"

        for (int width : new int[]{2, 4, 1}) {
            for (int offset = 0; offset < Math.min(8, stream.length - width); offset++) {
                for (boolean bigEndian : new boolean[]{true, false}) {
                    // Try: length = bytes remaining after length field
                    int count = countLengthPrefixMessages(stream, offset, width, bigEndian, false);
                    if (count > bestCount) {
                        bestCount = count; bestOffset = offset; bestWidth = width;
                        bestBE = bigEndian; bestMode = "remainder";
                    }

                    // Try: length = total message size
                    count = countLengthPrefixMessages(stream, offset, width, bigEndian, true);
                    if (count > bestCount) {
                        bestCount = count; bestOffset = offset; bestWidth = width;
                        bestBE = bigEndian; bestMode = "total";
                    }
                }
            }
        }

        // Need at least 3 messages, and more for narrow widths (high false-positive risk)
        int minRequired = (bestWidth == 1) ? 10 : 3;
        if (bestCount < minRequired) return null;

        // Now extract the actual messages
        List<byte[]> messages = extractLengthPrefixMessages(
                stream, bestOffset, bestWidth, bestBE, "total".equals(bestMode));

        if (messages.size() < 3) return null;

        String desc = String.format("length_prefix(offset=%d,width=%d,%s,%s)",
                bestOffset, bestWidth, bestBE ? "BE" : "LE", bestMode);
        return new ReassemblyResult(messages, desc, stream.length);
    }

    private static int countLengthPrefixMessages(byte[] stream, int offset, int width,
                                                  boolean bigEndian, boolean totalSize) {
        int count = 0;
        int pos = 0;
        int maxMessages = 500; // safety limit

        while (pos < stream.length && count < maxMessages) {
            if (pos + offset + width > stream.length) break;

            long lenVal = readUint(stream, pos + offset, width, bigEndian);

            // Sanity: length must be reasonable (1 byte to 64KB)
            if (lenVal < 1 || lenVal > 65536) break;

            int msgSize;
            if (totalSize) {
                msgSize = (int) lenVal;
                if (msgSize <= offset + width) break;  // must be bigger than header
            } else {
                // Length covers bytes after the length field
                msgSize = offset + width + (int) lenVal;
            }

            if (msgSize < 2 || msgSize > 65536) break;
            if (pos + msgSize > stream.length + 1) break; // allow +1 for last message truncation

            count++;
            pos += msgSize;
        }

        return count;
    }

    private static List<byte[]> extractLengthPrefixMessages(byte[] stream, int offset, int width,
                                                             boolean bigEndian, boolean totalSize) {
        List<byte[]> messages = new ArrayList<>();
        int pos = 0;

        while (pos < stream.length) {
            if (pos + offset + width > stream.length) break;

            long lenVal = readUint(stream, pos + offset, width, bigEndian);
            if (lenVal < 1 || lenVal > 65536) break;

            int msgSize;
            if (totalSize) {
                msgSize = (int) lenVal;
                if (msgSize <= offset + width) break;
            } else {
                msgSize = offset + width + (int) lenVal;
            }

            if (msgSize < 2 || msgSize > 65536) break;

            int end = Math.min(pos + msgSize, stream.length);
            messages.add(Arrays.copyOfRange(stream, pos, end));
            pos += msgSize;
        }

        return messages;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Strategy 2: Line-delimited framing
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Check if the stream is mostly line-delimited text (SMTP, IRC, HTTP).
     * Requirements: ≥80% printable ASCII, ≥3 CRLF or LF delimiters.
     */
    private static ReassemblyResult tryLineDelimited(byte[] stream) {
        int printable = 0;
        int crlfCount = 0;
        int lfCount = 0;

        for (int i = 0; i < stream.length; i++) {
            int b = stream[i] & 0xFF;
            if ((b >= 0x20 && b <= 0x7E) || b == 0x0A || b == 0x0D || b == 0x09) {
                printable++;
            }
            if (b == 0x0A) {
                lfCount++;
                if (i > 0 && (stream[i - 1] & 0xFF) == 0x0D) crlfCount++;
            }
        }

        double printableRatio = (double) printable / stream.length;
        if (printableRatio < 0.80 || lfCount < 3) return null;

        // Split by lines
        boolean useCRLF = crlfCount > lfCount / 2;
        List<byte[]> messages = new ArrayList<>();
        int start = 0;

        for (int i = 0; i < stream.length; i++) {
            if ((stream[i] & 0xFF) == 0x0A) {
                int end = (useCRLF && i > 0 && (stream[i - 1] & 0xFF) == 0x0D) ? i - 1 : i;
                if (end > start) {
                    messages.add(Arrays.copyOfRange(stream, start, end));
                }
                start = i + 1;
            }
        }
        // Remaining bytes
        if (start < stream.length) {
            byte[] last = Arrays.copyOfRange(stream, start, stream.length);
            if (last.length > 0) messages.add(last);
        }

        if (messages.size() < 3) return null;

        return new ReassemblyResult(messages, "line_delimited", stream.length);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Strategy 3: Repeating header pattern
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Look for a repeating byte pattern that marks message starts.
     * Scan the first few original segment boundaries to find common
     * leading bytes, then use those as message delimiters in the full stream.
     */
    private static ReassemblyResult tryRepeatingPattern(byte[] stream, List<byte[]> segments) {
        if (segments.size() < 5) return null;

        // Check if many segments start with the same 2-4 bytes
        for (int patLen = 4; patLen >= 2; patLen--) {
            Map<String, Integer> prefixCounts = new HashMap<>();
            int eligible = 0;

            for (byte[] seg : segments) {
                if (seg.length >= patLen) {
                    eligible++;
                    String prefix = hexOf(seg, 0, patLen);
                    prefixCounts.merge(prefix, 1, Integer::sum);
                }
            }

            // Find the most common prefix
            var best = prefixCounts.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .orElse(null);

            if (best == null || eligible < 5) continue;

            double ratio = (double) best.getValue() / eligible;
            if (ratio < 0.30) continue;  // at least 30% of segments share this prefix

            // Use this pattern to split the stream
            byte[] pattern = hexToBytes(best.getKey());
            List<byte[]> messages = splitByPattern(stream, pattern);

            if (messages.size() >= 3) {
                return new ReassemblyResult(messages,
                        "repeating_header(0x" + best.getKey() + ")", stream.length);
            }
        }

        return null;
    }

    private static List<byte[]> splitByPattern(byte[] stream, byte[] pattern) {
        List<Integer> starts = new ArrayList<>();

        for (int i = 0; i <= stream.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (stream[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) starts.add(i);
        }

        List<byte[]> messages = new ArrayList<>();
        for (int i = 0; i < starts.size(); i++) {
            int from = starts.get(i);
            int to = (i + 1 < starts.size()) ? starts.get(i + 1) : stream.length;
            if (to > from) {
                messages.add(Arrays.copyOfRange(stream, from, to));
            }
        }
        return messages;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Utilities
    // ────────────────────────────────────────────────────────────────────────

    private static byte[] concatenate(List<byte[]> segments) {
        int total = segments.stream().mapToInt(s -> s.length).sum();
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] seg : segments) {
            System.arraycopy(seg, 0, result, pos, seg.length);
            pos += seg.length;
        }
        return result;
    }

    private static long readUint(byte[] data, int offset, int width, boolean bigEndian) {
        long val = 0;
        if (bigEndian) {
            for (int i = 0; i < width; i++) val = (val << 8) | (data[offset + i] & 0xFF);
        } else {
            for (int i = width - 1; i >= 0; i--) val = (val << 8) | (data[offset + i] & 0xFF);
        }
        return val;
    }

    private static String hexOf(byte[] data, int offset, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < offset + len && i < data.length; i++) {
            sb.append(String.format("%02x", data[i]));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    /** Shannon entropy of byte array (0.0 = constant, 8.0 = max random) */
    private static double shannonEntropy(byte[] data) {
        if (data.length == 0) return 0;
        int[] freq = new int[256];
        // Sample first 10KB for performance
        int len = Math.min(data.length, 10240);
        for (int i = 0; i < len; i++) freq[data[i] & 0xFF]++;
        double entropy = 0;
        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }
}
