package com.pre.core;

import org.pcap4j.core.*;
import java.util.concurrent.TimeoutException;
import org.pcap4j.packet.*;

import java.io.EOFException;
import java.nio.file.Path;
import java.util.*;

/**
 * Reads .pcap / .pcapng files and extracts flows with their raw payloads.
 * Uses pcap4j — no native libpcap needed for offline file reading.
 *
 * TCP flows are reassembled: raw segments are concatenated into a byte
 * stream, then split into application-layer messages using heuristic
 * boundary detection (length-prefix, line-delimited, or pattern-based).
 */
public class PcapLoader {

    /**
     * Load all flows from a pcap file.
     * Returns flows sorted by total bytes descending (most interesting first).
     * TCP flows are automatically reassembled into application-layer messages.
     */
    public static List<Flow> load(Path pcapPath) throws PcapNativeException, NotOpenException {
        Map<String, Flow> rawFlows = new LinkedHashMap<>();

        try (PcapHandle handle = Pcaps.openOffline(pcapPath.toString())) {
            while (true) {
                Packet packet;
                try {
                    packet = handle.getNextPacketEx();
                } catch (EOFException e) {
                    break;
                } catch (TimeoutException e) {
                    continue;
                } catch (PcapNativeException e) {
                    if (e.getMessage() != null && e.getMessage().contains("truncated")) {
                        System.err.println("  [!] Truncated pcap — read " +
                                rawFlows.values().stream().mapToInt(Flow::messageCount).sum() +
                                " packets before truncation");
                        break;
                    }
                    throw e;
                }

                if (packet == null) break;

                IpV4Packet ipv4 = packet.get(IpV4Packet.class);
                IpV6Packet ipv6 = packet.get(IpV6Packet.class);
                if (ipv4 == null && ipv6 == null) continue;

                String srcIp, dstIp;
                if (ipv4 != null) {
                    srcIp = ipv4.getHeader().getSrcAddr().getHostAddress();
                    dstIp = ipv4.getHeader().getDstAddr().getHostAddress();
                } else {
                    srcIp = ipv6.getHeader().getSrcAddr().getHostAddress();
                    dstIp = ipv6.getHeader().getDstAddr().getHostAddress();
                }

                // TCP
                TcpPacket tcp = packet.get(TcpPacket.class);
                if (tcp != null && tcp.getPayload() != null) {
                    byte[] payload = tcp.getPayload().getRawData();
                    if (payload.length > 0) {
                        String key = flowKey("TCP", srcIp, tcp.getHeader().getSrcPort().valueAsInt(),
                                dstIp, tcp.getHeader().getDstPort().valueAsInt());
                        Flow flow = rawFlows.computeIfAbsent(key, k -> new Flow(
                                Flow.Protocol.TCP, srcIp,
                                tcp.getHeader().getSrcPort().valueAsInt(),
                                dstIp,
                                tcp.getHeader().getDstPort().valueAsInt()
                        ));
                        flow.addPayload(payload);
                    }
                    continue;
                }

                // UDP — no reassembly needed
                UdpPacket udp = packet.get(UdpPacket.class);
                if (udp != null && udp.getPayload() != null) {
                    byte[] payload = udp.getPayload().getRawData();
                    if (payload.length > 0) {
                        String key = flowKey("UDP", srcIp, udp.getHeader().getSrcPort().valueAsInt(),
                                dstIp, udp.getHeader().getDstPort().valueAsInt());
                        rawFlows.computeIfAbsent(key, k -> new Flow(
                                Flow.Protocol.UDP, srcIp,
                                udp.getHeader().getSrcPort().valueAsInt(),
                                dstIp,
                                udp.getHeader().getDstPort().valueAsInt()
                        )).addPayload(payload);
                    }
                }
            }
        }

        // ── TCP Stream Reassembly ────────────────────────────────────────
        // For each TCP flow, reassemble segments into application messages
        List<Flow> result = new ArrayList<>();
        int reassembledCount = 0;

        for (Flow flow : rawFlows.values()) {
            if (flow.getProtocol() == Flow.Protocol.TCP && flow.messageCount() >= 2) {
                TcpReassembler.ReassemblyResult rr = TcpReassembler.reassemble(
                        flow.getPayloads(),
                        flow.getSrcIp(), flow.getSrcPort(),
                        flow.getDstIp(), flow.getDstPort()
                );

                if (!rr.framingMethod().equals("raw_segments") && rr.messages().size() >= 3) {
                    // Create a new flow with reassembled messages
                    Flow reassembled = new Flow(
                            Flow.Protocol.TCP, flow.getSrcIp(), flow.getSrcPort(),
                            flow.getDstIp(), flow.getDstPort());
                    reassembled.setReassemblyInfo(rr.framingMethod(), rr.streamBytes());
                    for (byte[] msg : rr.messages()) {
                        reassembled.addPayload(msg);
                    }
                    result.add(reassembled);
                    reassembledCount++;
                } else {
                    // Keep original segments
                    result.add(flow);
                }
            } else {
                result.add(flow);
            }
        }

        if (reassembledCount > 0) {
            System.err.printf("  [*] TCP reassembly: %d flow(s) reassembled%n", reassembledCount);
        }

        result.sort((a, b) -> Integer.compare(b.totalBytes(), a.totalBytes()));
        return result;
    }

    /**
     * Merge flows that share the same server-side endpoint.
     */
    public static List<Flow> mergeByService(List<Flow> flows) {
        Map<String, Flow> merged = new LinkedHashMap<>();

        for (Flow f : flows) {
            String serverIp;
            int serverPort;
            String clientIp;

            int srcP = f.getSrcPort();
            int dstP = f.getDstPort();

            if (dstP < 1024 && srcP >= 1024) {
                serverIp = f.getDstIp(); serverPort = dstP;
                clientIp = f.getSrcIp();
            } else if (srcP < 1024 && dstP >= 1024) {
                serverIp = f.getSrcIp(); serverPort = srcP;
                clientIp = f.getDstIp();
            } else {
                if (dstP <= srcP) {
                    serverIp = f.getDstIp(); serverPort = dstP;
                    clientIp = f.getSrcIp();
                } else {
                    serverIp = f.getSrcIp(); serverPort = srcP;
                    clientIp = f.getDstIp();
                }
            }

            String mergeKey = f.getProtocol() + "|" + serverIp + ":" + serverPort;

            Flow target = merged.computeIfAbsent(mergeKey, k ->
                    new Flow(f.getProtocol(), clientIp, 0, serverIp, serverPort));

            for (byte[] payload : f.getPayloads()) {
                target.addPayload(payload);
            }
        }

        List<Flow> result = new ArrayList<>(merged.values());
        result.sort((a, b) -> Integer.compare(b.totalBytes(), a.totalBytes()));
        return result;
    }

    /** Canonical bidirectional flow key */
    private static String flowKey(String proto, String srcIp, int srcPort, String dstIp, int dstPort) {
        String a = srcIp + ":" + srcPort;
        String b = dstIp + ":" + dstPort;
        if (a.compareTo(b) > 0) { String t = a; a = b; b = t; }
        return proto + "|" + a + "|" + b;
    }

    /** Summary with capped output — shows top 15 flows + count of remaining */
    public static String summarize(List<Flow> flows) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-6s %-45s %5s %8s%n", "Proto", "Flow", "Pkts", "Bytes"));
        sb.append("─".repeat(70)).append("\n");

        int limit = Math.min(flows.size(), 15);
        for (int i = 0; i < limit; i++) {
            Flow f = flows.get(i);
            String extra = "";
            if (f.getReassemblyInfo() != null) {
                extra = "  [reassembled: " + f.getReassemblyInfo() + "]";
            }
            sb.append(f).append(extra).append("\n");
        }

        if (flows.size() > limit) {
            sb.append(String.format("  … and %d more flow(s)%n", flows.size() - limit));
        }

        return sb.toString();
    }
}
