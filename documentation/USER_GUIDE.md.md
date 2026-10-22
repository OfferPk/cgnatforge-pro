# CGNATForge Pro \- User Guide & Operations Manual

> **Step-by-step operational manual for telecom network architects, ISP engineers, and NetDevOps teams deploying Carrier-Grade NAT (CGNAT), Deterministic Port Batching, and Stateful NAT64.**

---

## 1\. Quickstart: Web Application Studio

The **CGNATForge Pro Web Studio** is completely self-contained with zero external dependencies. Open `source-code/index.html` directly in any modern web browser:

\# Optional local web server

cd product\_129/source-code

python3 \-m http.server 8080

\# Open http\://localhost:8080 in your browser

### Studio Interface Overview:

1. **Industry Presets**:  
   - **Tier-1 Carrier Deterministic CGNAT (Grade A+)**: Configured with RFC 6598 `100.64.0.0/10` subscriber space, RFC 7422 deterministic mapping (1024 ports/subscriber), EIM hairpinning, virtual reassembly, and 1412B MSS clamping.  
   - **Telco 5G Stateful NAT64 & DNS64 (Grade A+)**: Configured for 5G mobile operators with IPv6-only transition via Well-Known Prefix (`64:ff9b::/96`), 2048 ports/subscriber, and 1360B mobile MSS clamping.  
   - **Vulnerable Dynamic PAT Exhaustion (Grade F)**: Replicates unhardened dynamic NAT topologies with RFC 1918 address collisions, no deterministic mapping, and no port quotas.  
2. **Pool & Quota Parameters**: Configure subscriber prefix, public IP pool range, port block size, and target test IP.  
3. **Deterministic Mapping & Lawful Intercept**: Real-time forward allocation visualizer and instant \$\\mathcal{O}(1)\$ reverse lookup tool for subpoena responses without log storage.  
4. **Port Quota & Concurrency Sizing**: Models active socket concurrency vs allocated quota and calculates memory utilization.  
5. **10-Point Zero-Trust Scorecard**: Automated compliance grading against RFC 6888, RFC 6598, and CALEA standards (0–100%, Grades A+ to F).  
6. **Wireshark Hex Dissector**: Monospace byte-aligned hex dump with 1-click clipboard copy and binary `.pcap` capture file export.  
7. **Multi-Platform Synthesizer**: Instant configuration generation for Cisco IOS-XE (ASR 1k), Cisco IOS-XR (ASR 9k), Juniper Junos (MX), Linux (nftables/Jool), and A10 Networks Thunder CGN.

---

## 2\. DevSecOps Python CLI Tool Operations

The standalone Python CLI tool (`build/cgnatforge-cli.py`) operates in Linux, macOS, and Windows environments without installing external packages:

### 2.1 Packet Dissection & Wireshark Hex Dump

./build/cgnatforge-cli.py \--dissect

### 2.2 Computing Deterministic Forward Mapping

./build/cgnatforge-cli.py \--preset build/presets/tier1-carrier-deterministic-cgnat.json \--map

### 2.3 Instant Reverse Lawful Intercept Lookup (Subpoena Response)

Identify the internal subscriber responsible for an incident using only the observed public IP and port:

\# Query: Which subscriber was using 198.51.100.5 port 11500?

./build/cgnatforge-cli.py \\

  \--preset build/presets/tier1-carrier-deterministic-cgnat.json \\

  \--reverse 198.51.100.5 11500

*Output: Identified Subscriber: `100.64.1.6` (Calculated in \$\\mathcal{O}(1)\$ time without log queries).*

### 2.4 Simulating Port Quota Exhaustion

./build/cgnatforge-cli.py \--preset build/presets/tier1-carrier-deterministic-cgnat.json \--exhaustion

### 2.5 Running 10-Point Zero-Trust CGNAT Audits

\# Audit Tier-1 Carrier Deterministic preset

./build/cgnatforge-cli.py \--preset build/presets/tier1-carrier-deterministic-cgnat.json \--audit

\# Audit Vulnerable Dynamic preset

./build/cgnatforge-cli.py \--preset build/presets/vulnerable-dynamic-pat-exhaustion.json \--audit

### 2.6 Generating Binary PCAP Capture Files

Generate standard `.pcap` files for testing packet decoders or validating with Wireshark:

./build/cgnatforge-cli.py \--preset build/presets/tier1-carrier-deterministic-cgnat.json \--pcap cgnat-translated.pcap

\# Inspect with tcpdump or Wireshark

tcpdump \-n \-r cgnat-translated.pcap

### 2.7 Automated CI/CD Pipeline Gating (`--strict`)

Integrate CGNATForge Pro into CI/CD pipelines to validate infrastructure-as-code repository commits:

\- name: Audit Carrier-Grade NAT & NAT64 Architecture

  run: |

    python3 build/cgnatforge-cli.py \\

      \--preset build/presets/carrier-cgnat-config.json \\

      \--strict

*Exit Code 0: Audit Score \$\\ge 80\$ (Grade A/A+) and zero critical CGNAT vulnerabilities. Pipeline proceeds.* *Exit Code 1: Audit Score \$\< 80\$ (Grade B/C/F) or critical flaw detected. Pipeline halts.*

---

## 3\. Production Configuration Examples

### 3.1 Cisco ASR 1000 / Catalyst 8000 Deterministic CGNAT Configuration

ip nat settings mode cgn

ip nat translation max-entries all-host 1024

ip nat translation timeout 1800

ip nat translation udp-timeout 120

ip nat translation tcp-timeout 1800

ip nat translation finrst-timeout 30

ip access-list standard CGN-SUBSCRIBERS

 permit 100.64.0.0 0.63.255.255

ip nat pool CGN-PUBLIC-POOL 198.51.100.1 198.51.100.64 prefix-length 24

ip nat inside source list CGN-SUBSCRIBERS pool CGN-PUBLIC-POOL overload

interface TenGigabitEthernet0/0/0

 description SUBSCRIBER-ACCESS

 ip address 100.64.0.1 255.192.0.0

 ip nat inside

 ip virtual-reassembly in

 ip tcp adjust-mss 1412

 ip verify unicast source reachable-via rx

 no shutdown

interface TenGigabitEthernet0/0/1

 description TRANSIT-UPLINK

 ip address 198.51.100.1 255.255.255.192

 ip nat outside

 ip virtual-reassembly in

 no shutdown

---

## 4\. Troubleshooting Carrier NAT Outages

1. **Subscriber Connection Hangs / Webpages Fail to Load**:  
   - *Cause*: Subscriber reached their port quota (e.g. BitTorrent or multiple browser tabs opened 1024+ concurrent sockets). Subsequent SYN packets are dropped.  
   - *Resolution*: Lower TCP idle timeout (`ip nat translation tcp-timeout 1800`), reduce TCP close wait, or configure dynamic port block expansion.  
2. **Broken Video Calling (Zoom, WebRTC) & Online Gaming (Xbox/PS5)**:  
   - *Cause*: Symmetric NAT without Endpoint-Independent Mapping (EIM) and Hairpinning. Internal subscribers cannot route packets to fellow subscribers sharing the same public IP.  
   - *Resolution*: Enable EIM and Hairpinning on the translation profile (`ip nat settings support-mapping-protocol`).  
3. **Subpoena Logging Storage Saturated**:  
   - *Cause*: Using dynamic PAT overload, generating millions of syslog messages per hour.  
   - *Resolution*: Migrate to RFC 7422 Deterministic CGNAT. The public IP \+ port block is tied algorithmically to the subscriber, eliminating 100% of session logging.  
4. **Packets Dropped Across Mobile / Broadband Tunnels**:  
   - *Cause*: PMTU blackhole caused by GTP-U or IPsec tunnel encapsulation overhead.  
   - *Resolution*: Enforce TCP MSS Clamping on subscriber ingress (`ip tcp adjust-mss 1412` or `1360`).