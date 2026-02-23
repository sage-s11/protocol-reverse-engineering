package com.pre.core;

import java.util.*;

/**
 * XOR Deobfuscation Engine.
 *
 * Many malware C2 channels (IRC bots, custom protocols) XOR their traffic
 * with a fixed key to evade signature-based IDS. This module:
 *
 *   1. Detects if a byte stream is likely XOR-obfuscated
 *   2. Recovers the XOR key using known-plaintext attack (cribs)
 *   3. Decrypts the stream for further analysis
 *
 * Supported crib sets:
 *   - IRC: PRIVMSG, NICK, JOIN, PING, PONG, MODE, :, USER
 *   - SMTP: EHLO, HELO, MAIL FROM, RCPT TO, DATA, QUIT, 220, 250
 *   - HTTP: GET, POST, HTTP/1., Host:, Content-
 *   - Generic: \r\n (CRLF line endings)
 */
public class XorDeobfuscator {

    /** Result of XOR analysis */
    public record XorResult(
            boolean detected,
            byte[] key,
            String keyHex,
            int keyLength,
            String cribMatched,
            double confidence,
            List<byte[]> decryptedMessages
    ) {
        public static XorResult none() {
            return new XorResult(false, null, "", 0, "", 0.0, List.of());
        }
    }

    // Known plaintext cribs organized by protocol
    // IMPORTANT: minimum 4 characters per crib to avoid false positives
    // on encrypted/random data. Short patterns like "\r\n" match too often.
    private static final String[][] CRIBS = {
            // IRC protocol (all ≥4 chars)
            {"PRIVMSG ", "NICK ", "JOIN ", "PING ", "PONG ", "MODE ", "USER ",
             "QUIT ", "PART ", "NOTICE ", "KICK ", "TOPIC ", ":irc."},
            // SMTP protocol (all ≥5 chars to avoid false positives)
            {"EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:", "DATA\r\n", "AUTH "},
            // HTTP protocol
            {"GET /", "POST /", "HTTP/1.0", "HTTP/1.1",
             "Host: ", "Content-Length:", "User-Agent:"}
    };

    private static final String[] CRIB_LABELS = {"IRC", "SMTP", "HTTP"};

    /**
     * Attempt to detect and break XOR obfuscation on a set of messages.
     *
     * Tries single-byte keys (0x01-0xFF), then multi-byte keys up to 16 bytes.
     *
     * @param messages The raw (possibly XOR'd) messages
     * @return XorResult with key and decrypted messages if found
     */
    public static XorResult detect(List<byte[]> messages) {
        if (messages == null || messages.isEmpty()) return XorResult.none();

        // Quick check: if messages are already mostly printable ASCII, skip
        if (isPrintableRatio(messages) > 0.75) return XorResult.none();

        // Note: We previously had an entropy pre-check here, but removed it.
        // Single-byte XOR is a bijective mapping that preserves Shannon entropy,
        // so entropy cannot distinguish XOR'd text from encrypted data.
        // Instead, we rely on: (1) crib matching, (2) minimum score of 10,
        // (3) Engine's 50% confidence threshold to reject false positives.

        // Phase 1: Try single-byte XOR keys (most common in malware)
        // Require a CRIB match (not just printable ratio)
        XorResult result = trySingleByteKeys(messages);
        if (result.detected()) return result;

        // Phase 2: Try multi-byte XOR keys (2-16 bytes)
        result = tryMultiByteKeys(messages);
        if (result.detected()) return result;

        // Phase 3: Frequency analysis — only if a crib matches
        result = tryFrequencyAnalysis(messages);
        if (result.detected()) return result;

        return XorResult.none();
    }

    // ────────────────────────────────────────────────────────────────────────
    // Phase 1: Single-byte XOR brute force
    // ────────────────────────────────────────────────────────────────────────

    private static XorResult trySingleByteKeys(List<byte[]> messages) {
        byte[] concat = concatenateFirstN(messages, 20); // first 20 messages
        if (concat.length < 10) return XorResult.none();

        int bestKey = -1;
        String bestCrib = "";
        double bestScore = 0;
        boolean hasCribMatch = false;

        for (int key = 0x01; key <= 0xFF; key++) {
            byte[] decrypted = xorSingleByte(concat, (byte) key);

            // Check cribs — these are the strong signals
            for (int g = 0; g < CRIBS.length; g++) {
                for (String crib : CRIBS[g]) {
                    int matches = countOccurrences(decrypted, crib.getBytes());
                    if (matches > 0) {
                        // Score = matches * crib length (longer cribs are more significant)
                        double score = matches * crib.length();
                        if (score > bestScore) {
                            bestScore = score;
                            bestKey = key;
                            bestCrib = CRIB_LABELS[g] + ":\"" + crib.trim() + "\"";
                            hasCribMatch = true;
                        }
                    }
                }
            }

            // Printable ratio only used as a TIE-BREAKER for high-confidence matches
            // NOT as primary detection (too many false positives on encrypted data)
            if (!hasCribMatch) {
                double printable = printableRatio(decrypted);
                // Require 90%+ printable AND low entropy in decrypted result
                if (printable > 0.90) {
                    double decEntropy = shannonEntropy(decrypted);
                    if (decEntropy < 6.0) { // text-like entropy
                        double score = printable * concat.length * 0.3;
                        if (score > bestScore) {
                            bestScore = score;
                            bestKey = key;
                            bestCrib = "printable_ascii(" + String.format("%.0f%%", printable * 100) + ")";
                        }
                    }
                }
            }
        }

        if (bestKey < 0 || bestScore < 10) return XorResult.none();

        // Require crib match for detection — printable-only is unreliable
        if (!hasCribMatch) return XorResult.none();

        // Decrypt all messages
        byte[] keyBytes = new byte[]{(byte) bestKey};
        List<byte[]> decrypted = new ArrayList<>();
        for (byte[] msg : messages) {
            decrypted.add(xorSingleByte(msg, (byte) bestKey));
        }

        double confidence = Math.min(1.0, bestScore / 50.0);
        return new XorResult(true, keyBytes,
                String.format("0x%02x", bestKey), 1,
                bestCrib, confidence, decrypted);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Phase 2: Multi-byte XOR key recovery
    // ────────────────────────────────────────────────────────────────────────

    private static XorResult tryMultiByteKeys(List<byte[]> messages) {
        byte[] concat = concatenateFirstN(messages, 20);
        if (concat.length < 20) return XorResult.none();

        // Try key lengths 2-16
        for (int keyLen = 2; keyLen <= 16; keyLen++) {
            byte[] key = recoverMultiByteKey(concat, keyLen);
            if (key == null) continue;

            byte[] decrypted = xorMultiByte(concat, key);

            // Validate with cribs and printable ratio
            String matchedCrib = null;
            for (int g = 0; g < CRIBS.length; g++) {
                for (String crib : CRIBS[g]) {
                    if (countOccurrences(decrypted, crib.getBytes()) > 0) {
                        matchedCrib = CRIB_LABELS[g] + ":\"" + crib.trim() + "\"";
                        break;
                    }
                }
                if (matchedCrib != null) break;
            }

            double printable = printableRatio(decrypted);
            if (matchedCrib != null && printable > 0.60) {
                // Found it!
                List<byte[]> decryptedMsgs = new ArrayList<>();
                for (byte[] msg : messages) {
                    decryptedMsgs.add(xorMultiByte(msg, key));
                }

                StringBuilder keyHex = new StringBuilder();
                for (byte b : key) keyHex.append(String.format("%02x", b));

                double confidence = Math.min(1.0, printable + 0.3);
                return new XorResult(true, key, "0x" + keyHex, keyLen,
                        matchedCrib, confidence, decryptedMsgs);
            }
        }

        return XorResult.none();
    }

    /**
     * Recover a multi-byte XOR key by assuming the most common byte
     * at each key position corresponds to a space (0x20) or null (0x00).
     */
    private static byte[] recoverMultiByteKey(byte[] data, int keyLen) {
        byte[] key = new byte[keyLen];

        for (int pos = 0; pos < keyLen; pos++) {
            // Count byte frequencies at this key position
            int[] freq = new int[256];
            int count = 0;
            for (int i = pos; i < data.length; i += keyLen) {
                freq[data[i] & 0xFF]++;
                count++;
            }
            if (count < 5) return null;

            // Find the most frequent byte
            int maxFreq = 0, maxByte = 0;
            for (int b = 0; b < 256; b++) {
                if (freq[b] > maxFreq) {
                    maxFreq = freq[b];
                    maxByte = b;
                }
            }

            // Try: most frequent byte = space (0x20) — common in text protocols
            byte keyCandidateSpace = (byte) (maxByte ^ 0x20);
            // Try: most frequent byte = null (0x00) — common in binary protocols
            byte keyCandidateNull = (byte) maxByte;

            // Test which produces better results
            int printableSpace = 0, printableNull = 0;
            for (int i = pos; i < data.length; i += keyLen) {
                int dSpace = (data[i] ^ keyCandidateSpace) & 0xFF;
                int dNull = (data[i] ^ keyCandidateNull) & 0xFF;
                if (isPrintable(dSpace)) printableSpace++;
                if (isPrintable(dNull)) printableNull++;
            }

            key[pos] = (printableSpace >= printableNull) ? keyCandidateSpace : keyCandidateNull;
        }

        return key;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Phase 3: Frequency analysis (single-byte)
    // ────────────────────────────────────────────────────────────────────────

    private static XorResult tryFrequencyAnalysis(List<byte[]> messages) {
        byte[] concat = concatenateFirstN(messages, 30);
        if (concat.length < 50) return XorResult.none();

        // In English text / protocol commands, space (0x20) is the most common byte.
        int[] freq = new int[256];
        for (byte b : concat) freq[b & 0xFF]++;

        // Find top-3 most frequent bytes
        Integer[] indices = new Integer[256];
        for (int i = 0; i < 256; i++) indices[i] = i;
        Arrays.sort(indices, (a, b) -> freq[b] - freq[a]);

        for (int rank = 0; rank < 3; rank++) {
            int candidateByte = indices[rank];
            int key = candidateByte ^ 0x20;
            if (key == 0) continue;

            byte[] decrypted = xorSingleByte(concat, (byte) key);
            double printable = printableRatio(decrypted);

            if (printable > 0.75) {
                // MUST have a crib match — printable alone is not enough
                String matchedCrib = null;
                for (int g = 0; g < CRIBS.length; g++) {
                    for (String crib : CRIBS[g]) {
                        if (countOccurrences(decrypted, crib.getBytes()) > 0) {
                            matchedCrib = CRIB_LABELS[g] + ":\"" + crib.trim() + "\" (freq)";
                            break;
                        }
                    }
                    if (matchedCrib != null) break;
                }

                if (matchedCrib == null) continue; // No crib → skip

                List<byte[]> decryptedMsgs = new ArrayList<>();
                for (byte[] msg : messages) {
                    decryptedMsgs.add(xorSingleByte(msg, (byte) key));
                }

                return new XorResult(true, new byte[]{(byte) key},
                        String.format("0x%02x", key), 1,
                        matchedCrib, Math.min(1.0, printable),
                        decryptedMsgs);
            }
        }

        return XorResult.none();
    }

    // ────────────────────────────────────────────────────────────────────────
    // XOR operations
    // ────────────────────────────────────────────────────────────────────────

    private static byte[] xorSingleByte(byte[] data, byte key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key);
        }
        return result;
    }

    private static byte[] xorMultiByte(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Utilities
    // ────────────────────────────────────────────────────────────────────────

    /** Calculate Shannon entropy of a byte array (0.0 = uniform, 8.0 = max) */
    private static double shannonEntropy(byte[] data) {
        if (data.length == 0) return 0;
        int[] freq = new int[256];
        for (byte b : data) freq[b & 0xFF]++;
        double entropy = 0;
        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / data.length;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    private static byte[] concatenateFirstN(List<byte[]> messages, int n) {
        int total = 0;
        int count = Math.min(n, messages.size());
        for (int i = 0; i < count; i++) total += messages.get(i).length;

        byte[] result = new byte[total];
        int pos = 0;
        for (int i = 0; i < count; i++) {
            System.arraycopy(messages.get(i), 0, result, pos, messages.get(i).length);
            pos += messages.get(i).length;
        }
        return result;
    }

    private static int countOccurrences(byte[] data, byte[] pattern) {
        if (pattern.length == 0 || data.length < pattern.length) return 0;
        int count = 0;
        outer:
        for (int i = 0; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) continue outer;
            }
            count++;
        }
        return count;
    }

    private static double printableRatio(byte[] data) {
        if (data.length == 0) return 0;
        int printable = 0;
        for (byte b : data) {
            if (isPrintable(b & 0xFF)) printable++;
        }
        return (double) printable / data.length;
    }

    private static double isPrintableRatio(List<byte[]> messages) {
        int total = 0, printable = 0;
        int count = Math.min(10, messages.size());
        for (int i = 0; i < count; i++) {
            for (byte b : messages.get(i)) {
                total++;
                if (isPrintable(b & 0xFF)) printable++;
            }
        }
        return total == 0 ? 0 : (double) printable / total;
    }

    private static boolean isPrintable(int b) {
        return (b >= 0x20 && b <= 0x7E) || b == 0x0A || b == 0x0D || b == 0x09;
    }

    /**
     * Quick preview: return first N bytes of decrypted stream as printable string
     */
    public static String previewDecrypted(byte[] data, int maxLen) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(data.length, maxLen); i++) {
            int b = data[i] & 0xFF;
            if (isPrintable(b)) {
                sb.append((char) b);
            } else {
                sb.append('.');
            }
        }
        return sb.toString();
    }
}
