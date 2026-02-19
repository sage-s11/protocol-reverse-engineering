package com.pre.core;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Core statistical analysis engine.
 *
 * Pipeline:
 *   1. detectBoundaries()  → how are messages framed?
 *   2. inferFields()       → what are the fields at each byte offset?
 *   3. inferGrammar()      → request/response patterns, type sequences
 */
public class Analyzer {

    // ────────────────────────────────────────────────────────────────────────
    // Public entry point
    // ────────────────────────────────────────────────────────────────────────

    public static AnalysisResult analyze(Flow flow) {
        List<byte[]> messages = flow.getPayloads();
        if (messages.isEmpty()) {
            throw new IllegalArgumentException("Flow has no payloads");
        }

        int[] sizes = messages.stream().mapToInt(m -> m.length).toArray();
        Arrays.sort(sizes);

        BoundaryResult boundary = detectBoundaries(messages);
        List<FieldCandidate> fields = inferFields(messages, boundary);
        List<String> grammar = inferGrammar(messages, fields);

        return new AnalysisResult(
                flow.getKey(),
                messages.size(),
                sizes[0],
                sizes[sizes.length - 1],
                sizes[sizes.length / 2],
                boundary,
                fields,
                grammar,
                messages
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Entropy
    // ────────────────────────────────────────────────────────────────────────

    /** Shannon entropy in bits/byte over a byte array. */
    public static double shannonEntropy(byte[] data) {
        if (data == null || data.length == 0) return 0.0;
        int[] counts = new int[256];
        for (byte b : data) counts[b & 0xFF]++;
        double entropy = 0.0;
        for (int c : counts) {
            if (c > 0) {
                double p = (double) c / data.length;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    /**
     * Entropy of a single byte column (offset..offset+width) across all messages.
     * Low entropy = structured/constant field. High entropy = random/payload.
     */
    public static double columnEntropy(List<byte[]> messages, int offset, int width) {
        Map<String, Integer> counts = new HashMap<>();
        int total = 0;
        for (byte[] msg : messages) {
            if (msg.length >= offset + width) {
                String key = hexSlice(msg, offset, width);
                counts.merge(key, 1, Integer::sum);
                total++;
            }
        }
        if (total == 0) return 0.0;
        double entropy = 0.0;
        for (int c : counts.values()) {
            double p = (double) c / total;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Boundary detection
    // ────────────────────────────────────────────────────────────────────────

    public static BoundaryResult detectBoundaries(List<byte[]> payloads) {
        List<BoundaryResult> candidates = new ArrayList<>();

        BoundaryResult magic  = detectMagicHeader(payloads);
        BoundaryResult fixed  = detectFixedSize(payloads);
        BoundaryResult length = detectLengthPrefix(payloads);

        if (magic  != null) candidates.add(magic);
        if (fixed  != null) candidates.add(fixed);
        if (length != null) candidates.add(length);

        if (candidates.isEmpty()) {
            return new BoundaryResult(
                    BoundaryResult.Strategy.UNKNOWN, 0.0, null, 0, null, null,
                    List.of("No clear framing detected — collect more samples")
            );
        }

        return candidates.stream()
                .max(Comparator.comparingDouble(BoundaryResult::weightedConfidence))
                .orElseThrow();
    }

    private static BoundaryResult detectMagicHeader(List<byte[]> payloads) {
        if (payloads.size() < 3) return null;
        int minLen = payloads.stream().mapToInt(p -> p.length).min().orElse(0);
        int commonLen = 0;
        outer:
        for (int i = 0; i < Math.min(minLen, 8); i++) {
            byte first = payloads.get(0)[i];
            for (byte[] p : payloads) {
                if (p[i] != first) break outer;
            }
            commonLen = i + 1;
        }
        if (commonLen < 2) return null;

        byte[] magic = Arrays.copyOf(payloads.get(0), commonLen);
        double conf = Math.min(0.50 + commonLen * 0.10 + payloads.size() * 0.01, 0.97);
        return new BoundaryResult(
                BoundaryResult.Strategy.FIXED_MAGIC, conf, magic, commonLen, null, null,
                List.of(String.format("Magic bytes: %s (%dB prefix constant across all %d messages)",
                        toHex(magic), commonLen, payloads.size()))
        );
    }

    private static BoundaryResult detectFixedSize(List<byte[]> payloads) {
        Set<Integer> sizes = payloads.stream().map(p -> p.length).collect(Collectors.toSet());
        if (sizes.size() != 1) return null;
        int sz = sizes.iterator().next();
        double conf = Math.min(0.60 + payloads.size() * 0.02, 0.90);
        return new BoundaryResult(
                BoundaryResult.Strategy.FIXED_SIZE, conf, null, sz, null, null,
                List.of(String.format("All %d messages are exactly %d bytes — fixed-size framing",
                        payloads.size(), sz))
        );
    }

    private static BoundaryResult detectLengthPrefix(List<byte[]> payloads) {
        if (payloads.size() < 4) return null;
        double bestScore = 0;
        int bestOffset = -1, bestWidth = -1;
        boolean bestBigEndian = false;

        for (int width : new int[]{2, 4, 1}) {
            for (int offset = 0; offset < Math.min(8, minLen(payloads) - width); offset++) {
                for (boolean bigEndian : new boolean[]{true, false}) {
                    int matches = 0;
                    for (byte[] p : payloads) {
                        if (p.length < offset + width) continue;
                        long val = readUint(p, offset, width, bigEndian);
                        int remainder = p.length - (offset + width);
                        if (val == remainder || val == p.length) matches++;
                    }
                    double score = (double) matches / payloads.size();
                    if (score > bestScore) {
                        bestScore = score; bestOffset = offset;
                        bestWidth = width; bestBigEndian = bigEndian;
                    }
                }
            }
        }
        if (bestScore < 0.6) return null;

        return new BoundaryResult(
                BoundaryResult.Strategy.LENGTH_PREFIX, bestScore * 0.95,
                null, bestOffset + bestWidth, bestOffset, bestWidth,
                List.of(String.format(
                        "Length field at offset 0x%02x width=%dB endian=%s (matched %.0f%% of messages)",
                        bestOffset, bestWidth, bestBigEndian ? "big" : "little", bestScore * 100))
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Field inference
    // ────────────────────────────────────────────────────────────────────────

    /** Semantic type hints that should win over narrow constant fields */
    private static final Set<String> SEMANTIC_TYPES =
            Set.of("ipv4", "length", "sequence_number", "timestamp_unix");

    public static List<FieldCandidate> inferFields(List<byte[]> messages, BoundaryResult boundary) {
        if (messages.isEmpty()) return List.of();
        int minLen = minLen(messages);
        List<FieldCandidate> fields = new ArrayList<>();
        int offset = 0;

        while (offset < minLen) {
            List<FieldCandidate> atOffset = new ArrayList<>();
            for (int width : new int[]{4, 2, 1}) {
                if (offset + width > minLen) continue;
                double ent = columnEntropy(messages, offset, width);
                atOffset.add(classifyField(messages, offset, width, ent, boundary));
            }
            if (atOffset.isEmpty()) break;

            // Prefer semantic types over bare constants of narrower width
            FieldCandidate best = atOffset.stream()
                    .filter(f -> SEMANTIC_TYPES.contains(f.typeHint()))
                    .max(Comparator.comparingDouble(f -> f.width() * 10 + f.confidence()))
                    .orElseGet(() -> atOffset.stream()
                            .max(Comparator.comparingDouble(FieldCandidate::confidence))
                            .orElseThrow());

            // ── 4B → 2B+2B split heuristic ─────────────────────────────────
            // If we picked a 4B field, check whether its two 2B halves behave
            // as independent fields. Three tests:
            //   (a) Entropy mismatch: halves have very different entropy
            //   (b) Independence: the halves vary independently — the number
            //       of distinct 4B values is close to the product of the
            //       distinct counts of each 2B half, meaning they don't
            //       co-vary. Truly combined fields (like a single 32-bit
            //       counter) would have correlated halves.
            //   (c) Value mismatch: both halves are near-constant but with
            //       different values.
            if (best.width() == 4 && offset + 4 <= minLen) {
                double entropyHigh = columnEntropy(messages, offset, 2);
                double entropyLow  = columnEntropy(messages, offset + 2, 2);

                // Collect distinct value counts for the 4B whole and each 2B half
                Set<String> unique4B = new HashSet<>();
                Set<String> uniqueHi = new HashSet<>();
                Set<String> uniqueLo = new HashSet<>();
                for (byte[] msg : messages) {
                    if (msg.length >= offset + 4) {
                        unique4B.add(hexSlice(msg, offset, 4));
                        uniqueHi.add(hexSlice(msg, offset, 2));
                        uniqueLo.add(hexSlice(msg, offset + 2, 2));
                    }
                }

                boolean shouldSplit = false;

                // (a) Entropy mismatch — one half is structured, the other varies
                if (Math.abs(entropyHigh - entropyLow) > 1.0) {
                    shouldSplit = true;
                }

                // (b) Independence test — if the halves are separate fields,
                //     the 4B distinct count ≈ |uniqueHi| × |uniqueLo|.
                //     For a true single 4B field the 4B count would be much
                //     less than the product (values are correlated).
                //     We trigger if the 4B count is >= 70% of the product.
                int product = uniqueHi.size() * uniqueLo.size();
                if (product > 1 && unique4B.size() >= product * 0.70) {
                    shouldSplit = true;
                }

                // (c) Value mismatch — both halves are low entropy but with
                //     different constant values (e.g. flags=0x0100 + qdcount=0x0001)
                if (!shouldSplit && entropyHigh < 0.3 && entropyLow < 0.3) {
                    long hiSample = readUint(messages.get(0), offset, 2, true);
                    long loSample = readUint(messages.get(0), offset + 2, 2, true);
                    if (hiSample != loSample) {
                        shouldSplit = true;
                    }
                }

                if (shouldSplit) {
                    // Re-classify each 2B half independently
                    FieldCandidate halfHi = classifyField(messages, offset, 2, entropyHigh, boundary);
                    FieldCandidate halfLo = classifyField(messages, offset + 2, 2, entropyLow, boundary);
                    fields.add(halfHi);
                    fields.add(halfLo);
                    offset += 4;
                    continue;
                }
            }

            fields.add(best);
            offset += best.width();
        }

        // ── Post-pass: merge 1B constant-zero fields with neighbors ────────
        // In big-endian protocols, a uint16 field with values < 256 has a
        // constant 0x00 high byte. The main loop classifies this as a 1B
        // constant at 95% confidence, which then misaligns everything after.
        // Fix: if a 1B field with value 0x00 is followed by another 1B or
        // the start of the next field, and the merged 2B view yields a
        // meaningful classification (enum, flags, or even a "better" constant),
        // replace the pair with the merged 2B field.
        fields = mergeConstantZeroBytes(fields, messages, boundary);

        return fields;
    }

    /**
     * Scan the field list for 1B constant-zero entries. For each one, try
     * merging with the following byte to form a 2B field. Accept the merge if
     * the 2B classification is meaningful (enum, flags, length, sequence, or
     * a non-trivial constant).
     *
     * When a merge is accepted, all fields after the merge point are discarded
     * and re-inferred from scratch at the corrected alignment. This ensures
     * the alignment fix cascades properly through the rest of the header.
     */
    private static List<FieldCandidate> mergeConstantZeroBytes(
            List<FieldCandidate> fields, List<byte[]> messages, BoundaryResult boundary) {

        if (fields.size() < 2) return fields;
        int minLen = minLen(messages);

        for (int i = 0; i < fields.size(); i++) {
            FieldCandidate current = fields.get(i);

            // Is this a 1B constant with value 0x00?
            if (current.width() != 1
                    || !current.label().contains("magic/constant")
                    || current.observedValues().isEmpty()
                    || !"00".equals(current.observedValues().get(0).toString())) {
                continue;
            }

            int mergedOffset = current.offset();
            if (mergedOffset + 2 > minLen) continue;

            // Try the 2B classification at this offset
            double mergedEntropy = columnEntropy(messages, mergedOffset, 2);
            FieldCandidate merged = classifyField(
                    messages, mergedOffset, 2, mergedEntropy, boundary);

            boolean mergedIsUseful =
                    merged.label().contains("enum")
                    || merged.label().contains("flags")
                    || merged.label().contains("length")
                    || merged.label().contains("sequence")
                    || (merged.label().contains("magic/constant")
                        && !"0000".equals(merged.observedValues().get(0).toString()));

            if (!mergedIsUseful) continue;

            // Merge accepted. Keep fields [0..i), add the merged 2B field,
            // then re-infer everything from mergedOffset+2 onward.
            List<FieldCandidate> result = new ArrayList<>(fields.subList(0, i));
            result.add(merged);

            int resumeOffset = mergedOffset + 2;
            while (resumeOffset < minLen) {
                List<FieldCandidate> atOffset = new ArrayList<>();
                for (int width : new int[]{4, 2, 1}) {
                    if (resumeOffset + width > minLen) continue;
                    double ent = columnEntropy(messages, resumeOffset, width);
                    atOffset.add(classifyField(messages, resumeOffset, width, ent, boundary));
                }
                if (atOffset.isEmpty()) break;

                FieldCandidate best = atOffset.stream()
                        .filter(f -> SEMANTIC_TYPES.contains(f.typeHint()))
                        .max(Comparator.comparingDouble(f -> f.width() * 10 + f.confidence()))
                        .orElseGet(() -> atOffset.stream()
                                .max(Comparator.comparingDouble(FieldCandidate::confidence))
                                .orElseThrow());

                result.add(best);
                resumeOffset += best.width();
            }

            // Recurse: there might be another 1B zero in the re-inferred tail
            return mergeConstantZeroBytes(result, messages, boundary);
        }

        // No merges found — return as-is
        return fields;
    }

    /**
     * Detect whether a set of 4-byte field samples looks like text or
     * DNS-style length-prefixed label data rather than binary numeric data.
     *
     * DNS wire-format names use length-prefix bytes (0x01-0x3F) followed by
     * printable ASCII label characters. A 4-byte window sliding over this
     * will contain a mix of small control bytes and ASCII letters — which
     * can fool both IPv4 and timestamp classifiers.
     *
     * We classify each byte as:
     *   - printable ASCII (0x20-0x7E)
     *   - small label-length prefix (0x01-0x1F) — common in DNS/TLV encodings
     *   - null terminator (0x00) — end of DNS name, end of C-string
     *
     * If ≥80% of samples have ALL 4 bytes in this "text-or-label" set,
     * the field is almost certainly not a numeric value like an IP or timestamp.
     */
    private static boolean looksLikeTextOrLabels(List<byte[]> rawVals) {
        long textLike = rawVals.stream().filter(rv -> {
            for (byte b : rv) {
                int v = b & 0xFF;
                // Printable ASCII, small length-prefix (DNS/TLV), or null terminator
                boolean isTextOrLabel = (v >= 0x20 && v <= 0x7E) // printable ASCII
                        || (v >= 0x01 && v <= 0x3F)               // DNS label length / small TLV
                        || (v == 0x00);                            // null terminator
                if (!isTextOrLabel) return false;
            }
            return true;
        }).count();
        return rawVals.size() > 0 && (double) textLike / rawVals.size() > 0.80;
    }

    private static FieldCandidate classifyField(
            List<byte[]> messages, int offset, int width, double entropy, BoundaryResult boundary) {

        List<byte[]> rawVals = messages.stream()
                .filter(m -> m.length >= offset + width)
                .map(m -> Arrays.copyOfRange(m, offset, offset + width))
                .collect(Collectors.toList());

        Set<String> unique = rawVals.stream().map(Analyzer::toHex).collect(Collectors.toSet());
        int uniqueCount = unique.size();

        List<Long> intVals = rawVals.stream()
                .map(rv -> readUint(rv, 0, width, true))
                .collect(Collectors.toList());

        // ── Constant / magic ───────────────────────────────────────────────
        if (uniqueCount == 1) {
            return new FieldCandidate(offset, width, "magic/constant", 0.95,
                    "bytes[" + width + "]", List.of(toHex(rawVals.get(0))), entropy);
        }

        // ── Enum (low cardinality) ─────────────────────────────────────────
        if (uniqueCount <= 8 && rawVals.size() >= 5) {
            List<Object> vals = intVals.stream().distinct().sorted().limit(8)
                    .map(v -> (Object) v).collect(Collectors.toList());
            return new FieldCandidate(offset, width, "enum (" + uniqueCount + " values)", 0.82,
                    "uint" + (width * 8), vals, entropy);
        }

        // ── IPv4 address ───────────────────────────────────────────────────
        // Require: 4 bytes, high entropy, field varies across messages,
        // and bytes don't look like text or DNS label encoding.
        if (width == 4 && entropy > 2.0 && uniqueCount > 1 && !looksLikeTextOrLabels(rawVals)) {
            long ipLike = rawVals.stream().filter(rv -> {
                int a = rv[0] & 0xFF, b = rv[1] & 0xFF, c = rv[2] & 0xFF, d = rv[3] & 0xFF;
                return a >= 1 && a < 224 && d != 0 && !(a == 0 && b == 0 && c == 0 && d == 0);
            }).count();
            if ((double) ipLike / rawVals.size() > 0.70) {
                List<Object> vals = rawVals.stream().limit(4)
                        .map(rv -> (Object) String.format("%d.%d.%d.%d",
                                rv[0] & 0xFF, rv[1] & 0xFF, rv[2] & 0xFF, rv[3] & 0xFF))
                        .collect(Collectors.toList());
                return new FieldCandidate(offset, width, "ipv4_address", 0.88,
                        "ipv4", vals, entropy);
            }
        }

        // ── Length field ───────────────────────────────────────────────────
        if (width <= 4) {
            int[] msgSizes = messages.stream()
                    .filter(m -> m.length >= offset + width)
                    .mapToInt(m -> m.length).toArray();
            long matches = 0;
            for (int i = 0; i < Math.min(intVals.size(), msgSizes.length); i++) {
                long val = intVals.get(i);
                if (val == msgSizes[i] || val == msgSizes[i] - (offset + width)) matches++;
            }
            if (intVals.size() > 0 && (double) matches / intVals.size() > 0.60) {
                return new FieldCandidate(offset, width, "length", 0.90,
                        "uint" + (width * 8) + "_le",
                        intVals.stream().limit(6).map(v -> (Object) v).collect(Collectors.toList()),
                        entropy);
            }
        }

        // ── Sequence / counter ─────────────────────────────────────────────
        if (intVals.size() >= 4) {
            boolean monotone = true;
            Set<Long> diffs = new HashSet<>();
            for (int i = 1; i < intVals.size(); i++) {
                long d = intVals.get(i) - intVals.get(i - 1);
                if (d < 0) { monotone = false; break; }
                diffs.add(d);
            }
            if (monotone && diffs.size() <= 3) {
                return new FieldCandidate(offset, width, "sequence_number", 0.78,
                        "uint" + (width * 8),
                        intVals.stream().limit(6).map(v -> (Object) v).collect(Collectors.toList()),
                        entropy);
            }
        }

        // ── Unix timestamp (4B in plausible range) ─────────────────────────
        // Guard: reject if bytes look like text or DNS label encoding.
        // ASCII chars in the 0x60-0x7A range (lowercase letters) produce
        // uint32 values in the 1.6–2.0 billion range which overlaps the
        // current Unix epoch — e.g. "goog" = 0x676f6f67 ≈ Dec 2024.
        if (width == 4 && !looksLikeTextOrLabels(rawVals)) {
            long tsLike = intVals.stream()
                    .filter(v -> v > 1_000_000_000L && v < 2_000_000_000L).count();
            if ((double) tsLike / intVals.size() > 0.6) {
                return new FieldCandidate(offset, width, "timestamp_unix", 0.75,
                        "uint32_le",
                        intVals.stream().limit(4).map(v -> (Object) v).collect(Collectors.toList()),
                        entropy);
            }
        }

        // ── High entropy — random/payload ──────────────────────────────────
        if (entropy > 3.5) {
            return new FieldCandidate(offset, width, "payload/data (high entropy)", 0.55,
                    "bytes[" + width + "]",
                    rawVals.stream().limit(3).map(rv -> (Object) toHex(rv)).collect(Collectors.toList()),
                    entropy);
        }

        // ── Low entropy — flags/padding ────────────────────────────────────
        if (entropy < 0.5 && width <= 2) {
            return new FieldCandidate(offset, width, "flags/reserved", 0.60,
                    "uint" + (width * 8),
                    intVals.stream().limit(6).map(v -> (Object) v).collect(Collectors.toList()),
                    entropy);
        }

        // ── Default unknown ────────────────────────────────────────────────
        return new FieldCandidate(offset, width, "unknown", 0.35,
                "uint" + (width * 8),
                intVals.stream().limit(6).map(v -> (Object) v).collect(Collectors.toList()),
                entropy);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Grammar inference
    // ────────────────────────────────────────────────────────────────────────

    public static List<String> inferGrammar(List<byte[]> messages, List<FieldCandidate> fields) {
        List<String> notes = new ArrayList<>();

        // Find first enum / type field
        Optional<FieldCandidate> typeField = fields.stream()
                .filter(f -> f.label().contains("enum") || f.label().contains("type"))
                .findFirst();

        if (typeField.isEmpty()) {
            notes.add("No clear message-type discriminator found");
            return notes;
        }

        FieldCandidate tf = typeField.get();
        notes.add(String.format("Message type discriminator at offset 0x%02x", tf.offset()));

        // Count type values
        Map<Long, Long> typeCounts = new LinkedHashMap<>();
        for (byte[] msg : messages) {
            if (msg.length >= tf.offset() + tf.width()) {
                long val = readUint(msg, tf.offset(), tf.width(), true);
                typeCounts.merge(val, 1L, Long::sum);
            }
        }
        notes.add("Observed " + typeCounts.size() + " message types: " +
                typeCounts.entrySet().stream()
                        .sorted(Map.Entry.comparingByKey())
                        .map(e -> String.format("0x%x(%dx)", e.getKey(), e.getValue()))
                        .collect(Collectors.joining(", ")));

        // Request/response pairing
        if (typeCounts.size() >= 2) {
            List<Long> sorted = typeCounts.keySet().stream().sorted().collect(Collectors.toList());
            List<String> pairs = new ArrayList<>();
            for (int i = 0; i + 1 < sorted.size(); i += 2) {
                pairs.add(String.format("0x%x→0x%x", sorted.get(i), sorted.get(i + 1)));
            }
            notes.add("Possible request→response pairs: " + String.join(" | ", pairs));
        }

        // Alternating pattern
        List<Long> typeSeq = messages.stream()
                .filter(m -> m.length >= tf.offset() + tf.width())
                .map(m -> readUint(m, tf.offset(), tf.width(), true))
                .collect(Collectors.toList());
        if (typeSeq.size() >= 4) {
            boolean alternates = true;
            for (int i = 0; i < typeSeq.size() - 1; i++) {
                if (typeSeq.get(i).equals(typeSeq.get(i + 1))) { alternates = false; break; }
            }
            if (alternates) notes.add("Messages strictly alternate types — strong request/response pattern");
        }

        return notes;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Utilities
    // ────────────────────────────────────────────────────────────────────────

    private static int minLen(List<byte[]> messages) {
        return messages.stream().mapToInt(m -> m.length).min().orElse(0);
    }

    public static long readUint(byte[] data, int offset, int width, boolean bigEndian) {
        long val = 0;
        if (bigEndian) {
            for (int i = 0; i < width; i++) val = (val << 8) | (data[offset + i] & 0xFF);
        } else {
            for (int i = width - 1; i >= 0; i--) val = (val << 8) | (data[offset + i] & 0xFF);
        }
        return val;
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }

    private static String hexSlice(byte[] data, int offset, int width) {
        return toHex(Arrays.copyOfRange(data, offset, offset + width));
    }
}
