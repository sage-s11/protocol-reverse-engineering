package com.pre.core;
import java.util.List;
public record BoundaryResult(
        Strategy strategy, double confidence, byte[] magicBytes,
        int headerSize, Integer lengthFieldOffset, Integer lengthFieldWidth,
        List<String> notes
) {
    public enum Strategy {
        FIXED_MAGIC("fixed_magic"), LENGTH_PREFIX("length_prefix"),
        FIXED_SIZE("fixed_size"), UNKNOWN("unknown");
        public final String label;
        Strategy(String label) { this.label = label; }
    }
    public double weightedConfidence() {
        double boost = switch (strategy) {
            case FIXED_MAGIC -> 0.10; case LENGTH_PREFIX -> 0.05;
            case FIXED_SIZE -> 0.00; case UNKNOWN -> -0.10;
        };
        return Math.min(confidence + boost, 0.99);
    }
    public String magicHex() {
        if (magicBytes == null) return "none";
        StringBuilder sb = new StringBuilder();
        for (byte b : magicBytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
