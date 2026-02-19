package com.pre.core;

import org.pcap4j.core.*;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeoutException;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

import java.io.EOFException;
import java.nio.file.Path;
import java.util.*;

/**
 * Reads .pcap / .pcapng files and extracts flows with their raw payloads.
 * Uses pcap4j — no native libpcap needed for offline file reading.
 */
public class PcapLoader {

    /**
     * Load all flows from a pcap file.
     * Returns flows sorted by total bytes descending (most interesting first).
     */
    public static List<Flow> load(Path pcapPath) throws PcapNativeException, NotOpenException {
        Map<String, Flow> flows = new LinkedHashMap<>();

        try (PcapHandle handle = Pcaps.openOffline(pcapPath.toString())) {
            while (true) {
                Packet packet;
                try {
                    packet = handle.getNextPacketEx();
                } catch (EOFException e) {
                    break;
                } catch (TimeoutException e) {
                    continue;
                }

                if (packet == null) break;

                // Extract IP layer
                IpV4Packet ipv4 = packet.get(IpV4Packet.class);
                IpV6Packet ipv6 = packet.get(IpV6Packet.class);

                if (ipv4 == null && ipv6 == null) continue;

                String srcIp, dstIp;
                IpNumber proto;

                if (ipv4 != null) {
                    srcIp = ipv4.getHeader().getSrcAddr().getHostAddress();
                    dstIp = ipv4.getHeader().getDstAddr().getHostAddress();
                    proto = ipv4.getHeader().getProtocol();
                } else {
                    srcIp = ipv6.getHeader().getSrcAddr().getHostAddress();
                    dstIp = ipv6.getHeader().getDstAddr().getHostAddress();
                    proto = ipv6.getHeader().getNextHeader();
                }

                // TCP
                TcpPacket tcp = packet.get(TcpPacket.class);
                if (tcp != null && tcp.getPayload() != null) {
                    byte[] payload = tcp.getPayload().getRawData();
                    if (payload.length > 0) {
                        String key = flowKey("TCP", srcIp, tcp.getHeader().getSrcPort().valueAsInt(),
                                dstIp, tcp.getHeader().getDstPort().valueAsInt());
                        flows.computeIfAbsent(key, k -> new Flow(
                                Flow.Protocol.TCP, srcIp,
                                tcp.getHeader().getSrcPort().valueAsInt(),
                                dstIp,
                                tcp.getHeader().getDstPort().valueAsInt()
                        )).addPayload(payload);
                    }
                    continue;
                }

                // UDP
                UdpPacket udp = packet.get(UdpPacket.class);
                if (udp != null && udp.getPayload() != null) {
                    byte[] payload = udp.getPayload().getRawData();
                    if (payload.length > 0) {
                        String key = flowKey("UDP", srcIp, udp.getHeader().getSrcPort().valueAsInt(),
                                dstIp, udp.getHeader().getDstPort().valueAsInt());
                        flows.computeIfAbsent(key, k -> new Flow(
                                Flow.Protocol.UDP, srcIp,
                                udp.getHeader().getSrcPort().valueAsInt(),
                                dstIp,
                                udp.getHeader().getDstPort().valueAsInt()
                        )).addPayload(payload);
                    }
                }
            }
        }

        // Sort by total bytes descending
        List<Flow> result = new ArrayList<>(flows.values());
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

    public static String summarize(List<Flow> flows) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-6s %-45s %5s %8s%n", "Proto", "Flow", "Pkts", "Bytes"));
        sb.append("─".repeat(70)).append("\n");
        for (Flow f : flows) {
            sb.append(f).append("\n");
        }
        return sb.toString();
    }
}
