package com.pre.core;
import java.util.List;
public record AnalysisResult(
        String flowKey, int messageCount, int minSize, int maxSize, int medianSize,
        BoundaryResult boundary, List<FieldCandidate> fields,
        List<String> grammarNotes, List<byte[]> rawMessages
) {}
