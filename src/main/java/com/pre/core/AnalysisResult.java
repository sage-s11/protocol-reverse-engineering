package com.pre.core;

import java.util.List;
import java.util.Map;

public record AnalysisResult(
        String flowKey, int messageCount, int minSize, int maxSize, int medianSize,
        BoundaryResult boundary, List<FieldCandidate> fields,
        List<String> grammarNotes, List<byte[]> rawMessages,
        Map<Long, TypeAnalysis> perTypeAnalysis
) {
    /**
     * Backward-compatible constructor (no per-type analysis).
     */
    public AnalysisResult(
            String flowKey, int messageCount, int minSize, int maxSize, int medianSize,
            BoundaryResult boundary, List<FieldCandidate> fields,
            List<String> grammarNotes, List<byte[]> rawMessages) {
        this(flowKey, messageCount, minSize, maxSize, medianSize,
                boundary, fields, grammarNotes, rawMessages, Map.of());
    }

    /**
     * Per-type sub-analysis result.
     * Contains the fields found in the payload region for one message type.
     */
    public record TypeAnalysis(
            long typeValue,
            int messageCount,
            int payloadOffset,       // where the payload starts (after common header)
            List<FieldCandidate> payloadFields,  // fields within the payload
            int minSize,
            int maxSize
    ) {}
}
