package com.pre.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a single TCP/UDP conversation (flow) extracted from a pcap.
 * Holds the raw payload bytes from every packet in that conversation.
 */
public class Flow {

    public enum Protocol { TCP, UDP, UNKNOWN }

    private final String key;          // human-readable flow identifier
    private final Protocol protocol;
    private final String srcIp;
    private final int srcPort;
    private final String dstIp;
    private final int dstPort;
    private final List<byte[]> payloads = new ArrayList<>();

    public Flow(Protocol protocol, String srcIp, int srcPort, String dstIp, int dstPort) {
        this.protocol = protocol;
        this.srcIp    = srcIp;
        this.srcPort  = srcPort;
        this.dstIp    = dstIp;
        this.dstPort  = dstPort;
        // Canonical key: alphabetically smaller endpoint first
        String a = srcIp + ":" + srcPort;
        String b = dstIp + ":" + dstPort;
        if (a.compareTo(b) <= 0) {
            this.key = protocol + "  " + a + " <-> " + b;
        } else {
            this.key = protocol + "  " + b + " <-> " + a;
        }
    }

    public void addPayload(byte[] payload) {
        if (payload != null && payload.length > 0) {
            payloads.add(payload);
        }
    }

    public List<byte[]> getPayloads() { return payloads; }
    public String getKey()            { return key; }
    public Protocol getProtocol()     { return protocol; }
    public String getSrcIp()          { return srcIp; }
    public int getSrcPort()           { return srcPort; }
    public String getDstIp()          { return dstIp; }
    public int getDstPort()           { return dstPort; }

    public int totalBytes() {
        return payloads.stream().mapToInt(p -> p.length).sum();
    }

    public int messageCount() { return payloads.size(); }

    @Override
    public String toString() {
        return String.format("%-6s %-45s pkts=%d bytes=%d",
                protocol, key, messageCount(), totalBytes());
    }
}
