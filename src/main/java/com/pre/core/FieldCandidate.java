package com.pre.core;
import java.util.List;
public record FieldCandidate(
        int offset, int width, String label, double confidence,
        String typeHint, List<Object> observedValues, double entropy
) {
    public String valuesPreview() {
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(observedValues.size(), 4);
        for (int i = 0; i < limit; i++) {
            if (i > 0) sb.append(", ");
            Object v = observedValues.get(i);
            if (v instanceof Long l) sb.append("0x").append(Long.toHexString(l));
            else sb.append(v);
        }
        if (observedValues.size() > limit)
            sb.append(" …(+").append(observedValues.size() - limit).append(")");
        return sb.toString();
    }
    @Override public String toString() {
        return String.format("  0x%02x  [%dB]  %-14s  %-28s  conf=%.0f%%  H=%.2f  [%s]",
                offset, width, typeHint, label, confidence * 100, entropy, valuesPreview());
    }
}
