package com.pre.core;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Generates synthetic .pcap files for testing and demonstration.
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
        genC2Beacon(outputDir.resolve("c2_beacon_sim.pcap"), 60);
        genScadaProtocol(outputDir.resolve("scada_modbus_sim.pcap"), 40);
        genVpnTunnel(outputDir.resolve("vpn_tunnel_sim.pcap"), 50);

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
    // Protocol simulators — original
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
    // Protocol simulators — new (C2, SCADA, VPN)
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Simulated malware C2 (Command & Control) beacon protocol.
     *
     * Realistic threat scenario: implant phones home periodically,
     * receives commands, exfiltrates data. Designed to exercise
     * every classifier in the engine.
     *
     * Fixed header (20 bytes):
     * [0x00-0x01]  Magic: 0xCA 0xFE
     * [0x02]       Version: 0x03
     * [0x03]       Message type (enum):
     *                0x01=BEACON (implant → C2)
     *                0x02=COMMAND (C2 → implant)
     *                0x03=EXFIL_DATA (implant → C2)
     *                0x04=EXFIL_ACK (C2 → implant)
     *                0x05=HEARTBEAT (implant → C2)
     *                0x06=HEARTBEAT_ACK (C2 → implant)
     * [0x04-0x07]  Session ID (uint32 BE, random per implant, constant within session)
     * [0x08-0x09]  Sequence number (uint16 BE, monotonically increasing)
     * [0x0A-0x0B]  Payload length (uint16 BE, bytes after header)
     * [0x0C-0x0F]  Implant IPv4 (source address of infected host)
     * [0x10-0x13]  Timestamp (uint32 BE, Unix epoch)
     * [0x14+]      Payload (variable, depends on message type)
     *
     * Payload structure by type:
     *   BEACON:        4B uptime + 2B OS_ID + variable hostname (XOR 0x5A)
     *   COMMAND:       1B cmd_code + variable args
     *   EXFIL_DATA:    2B chunk_id + variable encrypted data
     *   EXFIL_ACK:     2B chunk_id + 1B status
     *   HEARTBEAT:     empty (0 bytes)
     *   HEARTBEAT_ACK: empty (0 bytes)
     */
    private static void genC2Beacon(Path out, int n) throws IOException {
        Random rnd = new Random(100);
        List<byte[]> payloads = new ArrayList<>();

        // Simulate 3 infected hosts with different session IDs
        int[] sessionIds = {0xDEAD0001, 0xDEAD0002, 0xDEAD0003};
        byte[][] implantIps = {
            {10, 0, 1, 50},
            {10, 0, 1, 77},
            {(byte)172, 16, 5, 22}
        };
        // OS fingerprints: 0x0601=Win10, 0x0602=Win11, 0x1404=Ubuntu20
        int[] osIds = {0x0601, 0x0602, 0x1404};
        String[] hostnames = {"DESKTOP-A7K2M", "LAPTOP-R9X3P", "dev-srv-03"};
        int[] cmdCodes = {0x10, 0x20, 0x30, 0x40, 0x50};
        // 0x10=sleep, 0x20=screenshot, 0x30=keylog, 0x40=download, 0x50=shell

        long baseTimestamp = 1740000000L; // ~Feb 2025
        int globalSeq = 0;

        for (int i = 0; i < n; i++) {
            int implantIdx = i % 3;
            int sessionId = sessionIds[implantIdx];
            byte[] implantIp = implantIps[implantIdx];
            long timestamp = baseTimestamp + (i * 30); // 30-second beacon interval

            // Cycle through message types to create realistic C2 chatter
            // Pattern: BEACON → COMMAND → HEARTBEAT → HEARTBEAT_ACK → EXFIL → EXFIL_ACK
            int phase = (i / 3) % 6;
            int msgType;
            byte[] payload;

            switch (phase) {
                case 0 -> { // BEACON
                    msgType = 0x01;
                    int uptime = 3600 + i * 30;
                    byte[] hostnameBytes = hostnames[implantIdx].getBytes();
                    // XOR obfuscate the hostname
                    byte[] xorHostname = new byte[hostnameBytes.length];
                    for (int j = 0; j < hostnameBytes.length; j++)
                        xorHostname[j] = (byte)(hostnameBytes[j] ^ 0x5A);

                    ByteBuffer pb = ByteBuffer.allocate(6 + xorHostname.length).order(ByteOrder.BIG_ENDIAN);
                    pb.putInt(uptime);
                    pb.putShort((short)osIds[implantIdx]);
                    pb.put(xorHostname);
                    payload = pb.array();
                }
                case 1 -> { // COMMAND
                    msgType = 0x02;
                    int cmdCode = cmdCodes[rnd.nextInt(cmdCodes.length)];
                    byte[] cmdArgs = new byte[2 + rnd.nextInt(8)];
                    rnd.nextBytes(cmdArgs);
                    ByteBuffer pb = ByteBuffer.allocate(1 + cmdArgs.length);
                    pb.put((byte)cmdCode);
                    pb.put(cmdArgs);
                    payload = pb.array();
                }
                case 2 -> { // HEARTBEAT
                    msgType = 0x05;
                    payload = new byte[0];
                }
                case 3 -> { // HEARTBEAT_ACK
                    msgType = 0x06;
                    payload = new byte[0];
                }
                case 4 -> { // EXFIL_DATA
                    msgType = 0x03;
                    int chunkId = (i / 18) + 1; // chunk increments slowly
                    byte[] encryptedData = new byte[16 + rnd.nextInt(32)];
                    rnd.nextBytes(encryptedData); // simulate encrypted exfiltrated data
                    ByteBuffer pb = ByteBuffer.allocate(2 + encryptedData.length).order(ByteOrder.BIG_ENDIAN);
                    pb.putShort((short)chunkId);
                    pb.put(encryptedData);
                    payload = pb.array();
                }
                default -> { // EXFIL_ACK
                    msgType = 0x04;
                    int chunkId = (i / 18) + 1;
                    ByteBuffer pb = ByteBuffer.allocate(3).order(ByteOrder.BIG_ENDIAN);
                    pb.putShort((short)chunkId);
                    pb.put((byte)0x00); // status: OK
                    payload = pb.array();
                }
            }

            // Build the full message
            int totalLen = 20 + payload.length;
            ByteBuffer msg = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN);
            msg.put((byte)0xCA);          // magic[0]
            msg.put((byte)0xFE);          // magic[1]
            msg.put((byte)0x03);          // version
            msg.put((byte)msgType);       // message type
            msg.putInt(sessionId);        // session ID
            msg.putShort((short)(globalSeq++)); // sequence number
            msg.putShort((short)payload.length); // payload length
            msg.put(implantIp);           // implant IP
            msg.putInt((int)timestamp);   // timestamp
            msg.put(payload);             // payload

            payloads.add(msg.array());
        }
        writePcap(out, payloads);
        System.out.printf("  [✓] %-40s %d packets  (C2 beacon simulation)%n", out.getFileName(), n);
    }

    /**
     * Simulated SCADA/Modbus-like industrial control protocol.
     *
     * Models a simplified Modbus TCP variant for PLC register access.
     * Common in ICS/OT security analysis.
     *
     * Fixed header (12 bytes):
     * [0x00-0x01]  Transaction ID (uint16 BE, sequential)
     * [0x02-0x03]  Protocol ID (constant 0x0000 — Modbus standard)
     * [0x04-0x05]  Length (uint16 BE, remaining bytes after this field)
     * [0x06]       Unit ID (uint8, PLC address 1-4)
     * [0x07]       Function code (enum):
     *                0x03=READ_HOLDING_REGISTERS
     *                0x06=WRITE_SINGLE_REGISTER
     *                0x10=WRITE_MULTIPLE_REGISTERS
     *                0x83=READ_ERROR (exception response)
     *                0x86=WRITE_ERROR (exception response)
     * [0x08+]      Data (varies by function code)
     *
     * Data by function:
     *   READ request:    2B start_register + 2B register_count
     *   READ response:   1B byte_count + N×2B register_values
     *   WRITE_SINGLE:    2B register_addr + 2B value
     *   WRITE_MULTI req: 2B start_register + 2B count + 1B byte_count + N×2B values
     *   ERROR:           1B exception_code
     */
    private static void genScadaProtocol(Path out, int n) throws IOException {
        Random rnd = new Random(200);
        List<byte[]> payloads = new ArrayList<>();
        int txid = 1;

        for (int i = 0; i < n; i++) {
            int unitId = (i % 4) + 1; // PLCs 1-4
            int phase = (i / 4) % 5;  // cycle through operations
            byte[] data;
            int funcCode;

            switch (phase) {
                case 0 -> { // READ request
                    funcCode = 0x03;
                    int startReg = 100 + (i % 8) * 10;
                    int regCount = 1 + rnd.nextInt(4);
                    ByteBuffer db = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
                    db.putShort((short)startReg);
                    db.putShort((short)regCount);
                    data = db.array();
                }
                case 1 -> { // READ response
                    funcCode = 0x03;
                    int regCount = 1 + rnd.nextInt(4);
                    ByteBuffer db = ByteBuffer.allocate(1 + regCount * 2).order(ByteOrder.BIG_ENDIAN);
                    db.put((byte)(regCount * 2));
                    for (int r = 0; r < regCount; r++) {
                        db.putShort((short)(rnd.nextInt(4096))); // sensor values 0-4095
                    }
                    data = db.array();
                }
                case 2 -> { // WRITE_SINGLE
                    funcCode = 0x06;
                    int reg = 200 + (i % 5) * 10;
                    int val = rnd.nextInt(1024);
                    ByteBuffer db = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
                    db.putShort((short)reg);
                    db.putShort((short)val);
                    data = db.array();
                }
                case 3 -> { // WRITE_MULTI request
                    funcCode = 0x10;
                    int startReg = 300;
                    int count = 2 + rnd.nextInt(3);
                    ByteBuffer db = ByteBuffer.allocate(5 + count * 2).order(ByteOrder.BIG_ENDIAN);
                    db.putShort((short)startReg);
                    db.putShort((short)count);
                    db.put((byte)(count * 2));
                    for (int r = 0; r < count; r++) {
                        db.putShort((short)rnd.nextInt(2048));
                    }
                    data = db.array();
                }
                default -> { // ERROR response
                    funcCode = (i % 2 == 0) ? 0x83 : 0x86;
                    data = new byte[]{(byte)(1 + rnd.nextInt(4))}; // exception codes 1-4
                }
            }

            int remainingLen = 2 + data.length; // unitId + funcCode + data
            ByteBuffer msg = ByteBuffer.allocate(8 + data.length).order(ByteOrder.BIG_ENDIAN);
            msg.putShort((short)(txid++));    // transaction ID
            msg.putShort((short)0x0000);      // protocol ID (Modbus)
            msg.putShort((short)remainingLen); // length
            msg.put((byte)unitId);            // unit ID
            msg.put((byte)funcCode);          // function code
            msg.put(data);

            payloads.add(msg.array());
        }
        writePcap(out, payloads);
        System.out.printf("  [✓] %-40s %d packets  (SCADA/Modbus simulation)%n", out.getFileName(), n);
    }

    /**
     * Simulated VPN tunnel protocol (WireGuard-inspired).
     *
     * Models a custom tunnel with handshake + encrypted data transport.
     * Tests: magic bytes, message typing, fixed vs variable length,
     * counter fields, and high-entropy encrypted payloads.
     *
     * All messages share a common 4-byte header:
     * [0x00-0x01]  Magic: 0x57 0x47 ("WG")
     * [0x02]       Message type:
     *                0x01=HANDSHAKE_INIT    (fixed 64 bytes)
     *                0x02=HANDSHAKE_RESP    (fixed 64 bytes)
     *                0x03=DATA              (variable length)
     *                0x04=KEEPALIVE         (fixed 4 bytes, header only)
     * [0x03]       Reserved: 0x00
     *
     * HANDSHAKE_INIT/RESP (64 bytes total):
     *   [0x04-0x07]  Sender index (uint32 BE)
     *   [0x08-0x0B]  Receiver index (uint32 BE, 0 for INIT)
     *   [0x0C-0x2F]  Ephemeral public key (36 bytes, random)
     *   [0x30-0x3F]  MAC (16 bytes, random)
     *
     * DATA (variable):
     *   [0x04-0x07]  Receiver index (uint32 BE)
     *   [0x08-0x0F]  Counter (uint64 BE, monotonically increasing)
     *   [0x10+]      Encrypted payload (variable, random bytes)
     *
     * KEEPALIVE (4 bytes total): header only, no payload.
     */
    private static void genVpnTunnel(Path out, int n) throws IOException {
        Random rnd = new Random(300);
        List<byte[]> payloads = new ArrayList<>();

        int senderIdx = 0x00AABB01;
        int receiverIdx = 0x00CCDD02;
        long counter = 0;

        for (int i = 0; i < n; i++) {
            int phase = i % 10; // cycle through phases
            int msgType;
            byte[] body;

            if (phase == 0) {
                // HANDSHAKE_INIT
                msgType = 0x01;
                ByteBuffer bb = ByteBuffer.allocate(60).order(ByteOrder.BIG_ENDIAN);
                bb.putInt(senderIdx);
                bb.putInt(0x00000000); // receiver unknown during init
                byte[] ephKey = new byte[36]; rnd.nextBytes(ephKey);
                bb.put(ephKey);
                byte[] mac = new byte[16]; rnd.nextBytes(mac);
                bb.put(mac);
                body = bb.array();
            } else if (phase == 1) {
                // HANDSHAKE_RESP
                msgType = 0x02;
                ByteBuffer bb = ByteBuffer.allocate(60).order(ByteOrder.BIG_ENDIAN);
                bb.putInt(receiverIdx);
                bb.putInt(senderIdx);
                byte[] ephKey = new byte[36]; rnd.nextBytes(ephKey);
                bb.put(ephKey);
                byte[] mac = new byte[16]; rnd.nextBytes(mac);
                bb.put(mac);
                body = bb.array();
            } else if (phase == 9) {
                // KEEPALIVE — no body
                msgType = 0x04;
                body = new byte[0];
            } else {
                // DATA — encrypted payload
                msgType = 0x03;
                int payloadLen = 64 + rnd.nextInt(128);
                byte[] encrypted = new byte[payloadLen];
                rnd.nextBytes(encrypted);

                ByteBuffer bb = ByteBuffer.allocate(12 + payloadLen).order(ByteOrder.BIG_ENDIAN);
                bb.putInt(receiverIdx);
                bb.putLong(counter++);
                bb.put(encrypted);
                body = bb.array();
            }

            ByteBuffer msg = ByteBuffer.allocate(4 + body.length).order(ByteOrder.BIG_ENDIAN);
            msg.put((byte)0x57);       // 'W'
            msg.put((byte)0x47);       // 'G'
            msg.put((byte)msgType);
            msg.put((byte)0x00);       // reserved
            msg.put(body);

            payloads.add(msg.array());
        }
        writePcap(out, payloads);
        System.out.printf("  [✓] %-40s %d packets  (VPN tunnel simulation)%n", out.getFileName(), n);
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
