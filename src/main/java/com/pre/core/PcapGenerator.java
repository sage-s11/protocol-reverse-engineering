package com.pre.core;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Generates synthetic .pcap files for Phase 1 (ground-truth) testing.
 * Zero external dependencies — writes raw pcap format manually.
 *
 * Run: java -cp target/pre-engine.jar com.pre.core.PcapGenerator
 */
public class PcapGenerator {

    private static final int PCAP_MAGIC       = 0xA1B2C3D4;
    private static final int LINKTYPE_ETHERNET = 1;

    // Ethernet + IP + UDP fixed headers
    private static final byte[] ETH_HEADER = {
        0x00,0x11,0x22,0x33,0x44,0x55, // dst mac
        0x66,0x77,(byte)0x88,(byte)0x99,(byte)0xaa,(byte)0xbb, // src mac
        0x08, 0x00  // IPv4
    };

    // ────────────────────────────────────────────────────────────────────────
    // Public API
    // ────────────────────────────────────────────────────────────────────────

    public static void generateAll(Path outputDir) throws IOException {
        Files.createDirectories(outputDir);
        System.out.println("  Generating test pcap files → " + outputDir + "/\n");

        genFixedMagicProtocol(outputDir.resolve("iot_device_sim.pcap"), 30);
        genLengthPrefixProtocol(outputDir.resolve("mgmt_proto_sim.pcap"), 25);
        genFixedSizeProtocol(outputDir.resolve("sensor_beacon_sim.pcap"), 20);
        genObfuscatedProtocol(outputDir.resolve("obfuscated_sim.pcap"), 15);
        genMdnsLike(outputDir.resolve("mdns_like_sim.pcap"), 20);

        System.out.println();
        System.out.println("  Files generated:");
        try (var stream = Files.list(outputDir)) {
            stream.filter(p -> p.toString().endsWith(".pcap"))
                  .sorted()
                  .forEach(p -> System.out.printf("    %-40s %6d bytes%n",
                          p.getFileName(), p.toFile().length()));
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Protocol simulators
    // ────────────────────────────────────────────────────────────────────────

    /**
     * IoT device with fixed magic header.
     * [0x00-0x01] Magic: 0xD3 0x4A
     * [0x02-0x03] Message type (uint16 LE, 4 values)
     * [0x04-0x05] Sequence (uint16 LE)
     * [0x06-0x09] Source IPv4
     * [0x0A-0x0B] Payload length (uint16 LE)
     * [0x0C+]     Variable payload
     */
    private static void genFixedMagicProtocol(Path out, int n) throws IOException {
        byte[][] ips = {
            {(byte)192,(byte)168,1,1},
            {(byte)192,(byte)168,1,100},
            {10,0,0,1},
            {(byte)172,16,0,5}
        };
        Random rnd = new Random(42);
        List<byte[]> payloads = new ArrayList<>();

        for (int i = 0; i < n; i++) {
            int mtype = (i % 4) + 1;
            byte[] body = new byte[4 + rnd.nextInt(12)];
            for (int j = 0; j < body.length; j++) body[j] = (byte)(0x20 + rnd.nextInt(0x5e));

            ByteBuffer buf = ByteBuffer.allocate(12 + body.length).order(ByteOrder.LITTLE_ENDIAN);
            buf.put((byte)0xD3).put((byte)0x4A);
            buf.putShort((short)mtype);
            buf.putShort((short)i);
            buf.put(ips[i % ips.length]);
            buf.putShort((short)body.length);
            buf.put(body);
            payloads.add(buf.array());
        }
        writePcap(out, payloads);
        System.out.printf("  [✓] %-40s %d packets%n", out.getFileName(), n);
    }

    /**
     * Management protocol with uint16 BE length prefix.
     * [0x00] Version (constant 0x02)
     * [0x01] Command (enum: 0x10=REQUEST, 0x20=RESPONSE, 0x30=HEARTBEAT)
     * [0x02-0x03] Total length (uint16 BE, includes header)
     * [0x04-0x07] Transaction ID (uint32 BE)
     * [0x08+] Variable payload
     */
    private static void genLengthPrefixProtocol(Path out, int n) throws IOException {
        int[] cmds = {0x10, 0x20, 0x10, 0x20, 0x30};
        Random rnd = new Random(43);
        List<byte[]> payloads = new ArrayList<>();
        int txid = 1000;

        for (int i = 0; i < n; i++) {
            int cmd = cmds[i % cmds.length];
            byte[] body = new byte[rnd.nextInt(20)];
            for (int j = 0; j < body.length; j++) body[j] = (byte)rnd.nextInt(256);
            int total = 8 + body.length;

            ByteBuffer buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
            buf.put((byte)0x02).put((byte)cmd);
            buf.putShort((short)total);
            buf.putInt(txid++);
            buf.put(body);
            payloads.add(buf.array());
        }
        writePcap(out, payloads);
        System.out.printf("  [✓] %-40s %d packets%n", out.getFileName(), n);
    }

    /**
     * Fixed-size 16-byte sensor beacons.
     * [0x00] Sensor ID (uint8, 1-8)
     * [0x01] Message type (0x01=data, 0x02=ack)
     * [0x02-0x03] Sequence (uint16 LE)
     * [0x04-0x07] Timestamp (uint32 LE)
     * [0x08-0x09] Sensor value (uint16 LE, 0-1023)
     * [0x0A-0x0F] Reserved (zeros)
     */
    private static void genFixedSizeProtocol(Path out, int n) throws IOException {
        Random rnd = new Random(44);
        List<byte[]> payloads = new ArrayList<>();
        long ts = System.currentTimeMillis() / 1000;

        for (int i = 0; i < n; i++) {
            ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
            buf.put((byte)((i % 8) + 1));
            buf.put((byte)(i % 3 == 2 ? 0x02 : 0x01));
            buf.putShort((short)i);
            buf.putInt((int)(ts + i));
            buf.putShort((short)rnd.nextInt(1024));
            buf.put(new byte[6]); // reserved
            payloads.add(buf.array());
        }
        writePcap(out, payloads);
        System.out.printf("  [✓] %-40s %d packets%n", out.getFileName(), n);
    }

    /**
     * Obfuscated protocol with rolling XOR cipher.
     * Magic 0xBEEF still visible, body is XOR'd.
     * [0x00-0x01] Magic: 0xBE 0xEF
     * [0x02-0x03] Body length (uint16 LE)
     * [0x04+]     XOR-obfuscated payload
     */
    private static void genObfuscatedProtocol(Path out, int n) throws IOException {
        Random rnd = new Random(45);
        List<byte[]> payloads = new ArrayList<>();
        int key = 0x42;

        for (int i = 0; i < n; i++) {
            int bodyLen = 8 + rnd.nextInt(16);
            byte[] body = new byte[bodyLen];
            for (int j = 0; j < bodyLen; j++) body[j] = (byte)(rnd.nextInt(256) ^ key);
            key = (key + 17) & 0xFF;

            ByteBuffer buf = ByteBuffer.allocate(4 + bodyLen).order(ByteOrder.LITTLE_ENDIAN);
            buf.put((byte)0xBE).put((byte)0xEF);
            buf.putShort((short)bodyLen);
            buf.put(body);
            payloads.add(buf.array());
        }
        writePcap(out, payloads);
        System.out.printf("  [✓] %-40s %d packets%n", out.getFileName(), n);
    }

    /**
     * mDNS-like structure (simplified, for ground-truth testing).
     * [0x00-0x01] Transaction ID (uint16 BE)
     * [0x02-0x03] Flags (uint16 BE: 0x0000=query, 0x8400=response)
     * [0x04-0x05] Question count
     * [0x06-0x07] Answer count
     * [0x08+]     Variable records
     */
    private static void genMdnsLike(Path out, int n) throws IOException {
        Random rnd = new Random(46);
        List<byte[]> payloads = new ArrayList<>();

        for (int i = 0; i < n; i++) {
            boolean isQuery = i % 2 == 0;
            int flags = isQuery ? 0x0000 : 0x8400;
            int qcount = isQuery ? 1 : 0;
            int acount = isQuery ? 0 : 1;
            byte[] records = new byte[4 + rnd.nextInt(8)];
            for (int j = 0; j < records.length; j++) records[j] = (byte)(0x20 + rnd.nextInt(0x5e));

            ByteBuffer buf = ByteBuffer.allocate(8 + records.length).order(ByteOrder.BIG_ENDIAN);
            buf.putShort((short)rnd.nextInt(65536));
            buf.putShort((short)flags);
            buf.putShort((short)qcount);
            buf.putShort((short)acount);
            buf.put(records);
            payloads.add(buf.array());
        }
        writePcap(out, payloads);
        System.out.printf("  [✓] %-40s %d packets%n", out.getFileName(), n);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Minimal pcap writer
    // ────────────────────────────────────────────────────────────────────────

    private static void writePcap(Path path, List<byte[]> payloads) throws IOException {
        try (DataOutputStream dos = new DataOutputStream(
                new BufferedOutputStream(Files.newOutputStream(path)))) {
            // Global header (little-endian)
            writeLE32(dos, PCAP_MAGIC);
            writeLE16(dos, 2); writeLE16(dos, 4); // version 2.4
            writeLE32(dos, 0);     // timezone
            writeLE32(dos, 0);     // timestamp accuracy
            writeLE32(dos, 65535); // snaplen
            writeLE32(dos, LINKTYPE_ETHERNET);

            long ts = System.currentTimeMillis() / 1000;
            for (byte[] payload : payloads) {
                byte[] frame = buildFrame(payload);
                writeLE32(dos, (int)ts);
                writeLE32(dos, 0);             // usec
                writeLE32(dos, frame.length);
                writeLE32(dos, frame.length);
                dos.write(frame);
                ts += 100; // 100ms spacing
            }
        }
    }

    private static byte[] buildFrame(byte[] appPayload) throws IOException {
        // UDP header
        ByteBuffer udp = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        udp.putShort((short)12345);                      // src port
        udp.putShort((short)9999);                       // dst port
        udp.putShort((short)(8 + appPayload.length));    // length
        udp.putShort((short)0);                          // checksum

        byte[] udpBytes = udp.array();
        int ipPayloadLen = udpBytes.length + appPayload.length;

        // IPv4 header (minimal, checksum=0)
        ByteBuffer ip = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
        ip.put((byte)0x45);                              // version + IHL
        ip.put((byte)0);                                 // DSCP
        ip.putShort((short)(20 + ipPayloadLen));         // total length
        ip.putShort((short)0);                           // ID
        ip.putShort((short)0);                           // flags + frag
        ip.put((byte)64);                                // TTL
        ip.put((byte)17);                                // protocol: UDP
        ip.putShort((short)0);                           // checksum
        ip.put(new byte[]{(byte)192,(byte)168,1,100});   // src IP
        ip.put(new byte[]{(byte)192,(byte)168,1,1});     // dst IP

        ByteArrayOutputStream frame = new ByteArrayOutputStream();
        frame.write(ETH_HEADER);
        frame.write(ip.array());
        frame.write(udpBytes);
        frame.write(appPayload);
        return frame.toByteArray();
    }

    private static void writeLE32(DataOutputStream dos, int v) throws IOException {
        dos.writeByte(v & 0xFF); dos.writeByte((v >> 8) & 0xFF);
        dos.writeByte((v >> 16) & 0xFF); dos.writeByte((v >> 24) & 0xFF);
    }

    private static void writeLE16(DataOutputStream dos, int v) throws IOException {
        dos.writeByte(v & 0xFF); dos.writeByte((v >> 8) & 0xFF);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Standalone runner
    // ────────────────────────────────────────────────────────────────────────

    public static void main(String[] args) throws IOException {
        Path outDir = Path.of(args.length > 0 ? args[0] : "tests/pcaps");
        generateAll(outDir);
    }
}
