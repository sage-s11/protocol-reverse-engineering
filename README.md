# protocol-reverse-enginee=======
# Protocol Reverse Engineering Engine (Java)

> Feed it a `.pcap` of any binary protocol — it statistically infers message structure,
> field types, and protocol grammar, then auto-generates a working **Java parser** and
> human-readable **Markdown spec**. Completely offline, completely on-demand.

## Quick Start

```bash
# 1. Build fat JAR
mvn package -q

# 2. Generate synthetic test pcaps
java -jar target/pre-engine.jar --gen-pcaps tests/pcaps/

# 3. Run the engine on a test pcap
java -jar target/pre-engine.jar tests/pcaps/iot_device_sim.pcap --name IoTDevice

# 4. Run tests
mvn test
```

## Real capture (home WiFi)

```bash
sudo tcpdump -i any -w tests/pcaps/home_lan.pcap -G 60 -W 1
java -jar target/pre-engine.jar tests/pcaps/home_lan.pcap --name HomeLAN
```

## Project Structure

```
├── pom.xml
├── src/main/java/com/pre/
│   ├── core/        Analyzer, Flow, PcapLoader, PcapGenerator, result models
│   ├── output/      Generator (Java parser + Markdown spec)
│   └── cli/         Engine (CLI entry point)
├── src/test/        JUnit 5 test suite
├── protocols/       known/ and unknown/ capture notes
├── tests/pcaps/     synthetic + real capture files
└── output/          parsers/ and specs/
```

## Requirements

- Java 17+  |  Maven 3.8+
- `sudo apt install libpcap-dev`  (for real pcap reading via pcap4j)
>>>>>>> cf63d82 (Initial commit)
