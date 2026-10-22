# CGNATForge Pro \- Architecture & Technical Specification

> **IETF RFC 6888 (Carrier-Grade NAT \- CGN), RFC 6598 (Shared Address Space 100.64.0.0/10), RFC 7422 (Deterministic CGN), and RFC 6146 (Stateful NAT64) Architecture Specification**

---

## 1\. Executive Summary & Standards Baseline

As the global pool of available IPv4 addresses reached complete exhaustion, telecommunications carriers, mobile network operators (4G LTE / 5G Standalone), broadband Internet Service Providers (ISPs), and large-scale cloud providers deployed **Carrier-Grade NAT (CGNAT)** (also designated Large Scale NAT or LSN).

Traditional customer-premises NAT (NAT44) operates at the subscriber edge. In contrast, CGNAT multiplexes hundreds of thousands of residential and mobile subscribers across a centralized carrier routing fabric using a two-tier translation model:

1. **Subscriber Edge**: Customer premises equipment (CPE) assigns RFC 1918 private addresses (`192.168.1.0/24`) locally, and receives a WAN address from the carrier's **RFC 6598 Shared Address Space** (`100.64.0.0/10`).  
2. **Carrier Edge**: Carrier-Grade NAT gateways (Cisco ASR 1000/9000, Juniper MX MS-MPC, A10 Thunder CGN) translate `100.64.0.0/10` subscriber IPs to a consolidated pool of public IPv4 addresses before routing to the global Internet.

\+-----------------------------------------------------------------------------------------+

|                                  CGNAT & NAT64 PROTOCOL SUMMARY                         |

\+--------------------------+---------------------------------------+----------------------+

| Layer / Domain           | Standard / Mechanism                  | Operational Purpose  |

\+--------------------------+---------------------------------------+----------------------+

| Carrier Address Space    | IETF RFC 6598 (100.64.0.0/10)         | Dedicated 4.19M IP   |

|                          | Shared Address Space Prefix           | non-routable prefix  |

\+--------------------------+---------------------------------------+----------------------+

| Large-Scale NAT Core     | IETF RFC 6888 (CGN Requirements)      | Standardizes carrier |

|                          | High-availability, session failover   | NAT behavioral rules |

\+--------------------------+---------------------------------------+----------------------+

| Deterministic Mapping    | IETF RFC 7422 (Port Batching)         | O(1) Lawful Intercept|

|                          | Fixed algorithmic port blocks         | without syslog bloat |

\+--------------------------+---------------------------------------+----------------------+

| IPv6-to-IPv4 Transition  | IETF RFC 6146 (Stateful NAT64)        | Bridges IPv6 mobile  |

|                          | IETF RFC 6052 (64:ff9b::/96 prefix)   | clients to IPv4 net  |

\+--------------------------+---------------------------------------+----------------------+

| P2P & Hairpinning        | IETF RFC 4787 / RFC 5382              | Internal subscriber  |

|                          | Endpoint-Independent Mapping (EIM)    | direct loopback NAT  |

\+--------------------------+---------------------------------------+----------------------+

---

## 2\. Mathematical Formalization: RFC 7422 Deterministic CGNAT

### 2.1 The Lawful Intercept & Logging Dilemma

Under standard Dynamic Port Address Translation (Dynamic PAT / Overload), every new outbound TCP connection or UDP flow creates a dynamic entry in the translation table. To comply with legal mandates (e.g. CALEA in the US, EU Data Retention Directives, UAE Telecommunications and Digital Government Regulatory Authority regulations), ISPs must log every single translation:

\$\$\\text{Daily Log Volume} \= N\_{\\text{subscribers}} \\times \\text{Sessions/Day} \\times \\text{Bytes/Log Entry}\$\$

For a tier-1 provider with 2,000,000 broadband subscribers averaging 5,000 daily connections: \$\$2{,}000{,}000 \\times 5{,}000 \\times 128\\text{ Bytes} \\approx \\mathbf{1.28\\text{ Terabytes / Day (467 TB / Year)}}\$\$

Storing, indexing, and querying petabytes of syslog records creates massive storage overhead, risks dropped UDP syslog packets during traffic bursts, and causes regulatory compliance failures during subpoena inquiries.

### 2.2 RFC 7422 Deterministic Mapping Algorithm

**RFC 7422** eliminates 100% of per-session translation logging by replacing dynamic port allocation with an algorithmic, bidirectional mapping function:

Let:

- \$N\$ \= Number of internal subscriber IPv4 addresses in the subscriber prefix (e.g. `100.64.0.0/10` or assigned pool).  
- \$M\$ \= Number of public external IPv4 addresses in the public pool (\$\[\\text{Pub}*{\\text{start}}, \\text{Pub}*{\\text{end}}\]\$).  
- \$B\$ \= Port block size allocated per subscriber (standard: 1024 or 2048 ports).  
- \$P\_{\\text{start}}\$ \= Minimum allocatable port (typically 1024 to preserve well-known system ports 0–1023).  
- \$P\_{\\text{end}}\$ \= Maximum allocatable port (65535).  
- \$P\_{\\text{avail}}\$ \= Available ports per public IP \= \$P\_{\\text{end}} \- P\_{\\text{start}} \+ 1 \= 65536 \- 1024 \= 64512\$.  
- \$K\$ \= Subscribers supported per public IP: \$\$K \= \\left\\lfloor \\frac{P\_{\\text{avail}}}{B} \\right\\rfloor \= \\left\\lfloor \\frac{64512}{1024} \\right\\rfloor \= 63\\text{ subscribers / IP}\$\$

#### Forward Mapping (Subscriber \-\> Public IP \+ Port Range):

Given subscriber IP \$S\$:

1. \$\\text{Index}(S) \= S \- \\text{Sub}\_{\\text{base}}\$  
2. \$\\text{PublicIPOffset} \= \\left\\lfloor \\frac{\\text{Index}(S)}{K} \\right\\rfloor\$  
3. \$\\text{AssignedPublicIP} \= \\text{Pub}\_{\\text{start}} \+ \\text{PublicIPOffset}\$  
4. \$\\text{BlockIndex} \= \\text{Index}(S) \\pmod K\$  
5. \$\\text{PortRange} \= \\left\[ P\_{\\text{start}} \+ (\\text{BlockIndex} \\times B), ; P\_{\\text{start}} \+ ((\\text{BlockIndex} \+ 1\) \\times B) \- 1 \\right\]\$

#### Reverse Mapping (Lawful Intercept / Subpoena Query):

Given an external IP \$\\text{IP}\_{\\text{ext}}\$ and port \$P\$ observed committing a cyber incident at timestamp \$T\$:

1. \$\\text{PublicIPOffset} \= \\text{IP}*{\\text{ext}} \- \\text{Pub}*{\\text{start}}\$  
2. \$\\text{BlockIndex} \= \\left\\lfloor \\frac{P \- P\_{\\text{start}}}{B} \\right\\rfloor\$  
3. \$\\text{Index}(S) \= (\\text{PublicIPOffset} \\times K) \+ \\text{BlockIndex}\$  
4. \$\\text{SubscriberIP} \= \\text{Sub}\_{\\text{base}} \+ \\text{Index}(S)\$

*Computational Complexity*: \$\\mathcal{O}(1)\$ time and \$\\mathcal{O}(1)\$ memory space. The ISP identifies the exact offending subscriber in microseconds with mathematical certainty and zero database lookups\!

---

## 3\. RFC 6146 & RFC 6052 Stateful NAT64 Architecture

As mobile operators transition 5G cores to IPv6-only architectures, handsets receive only an IPv6 address (`2001:db8:1::/64`). To reach legacy IPv4-only Internet services (e.g. streaming servers, cloud APIs), the carrier deploys **Stateful NAT64** and **DNS64**:

IPv6-Only Handset                  NAT64 Gateway (ASR 1k)                  IPv4 Public Server

2001:db8:1::10                       Translates Headers                       8.8.8.8

      |                                       |                                    |

      |-- IPv6 Packet \-----------------------\>|                                    |

      |   Src: 2001:db8:1::10                 |-- IPv4 Translated Packet \---------\>|

      |   Dst: 64:ff9b::0808:0808             |   Src: 198.51.100.1 (Port 1050\)    |

      |   (Embedded 8.8.8.8)                  |   Dst: 8.8.8.8 (Port 443\)          |

1. **DNS64 Synthetic AAAA Record**:  
   - The handset queries DNS for `api.example.com`.  
   - The authoritative DNS server only has an IPv4 `A` record (`93.184.216.34`).  
   - The carrier DNS64 synthesizes an `AAAA` record by prefixing the IPv4 address with the Well-Known Prefix: `64:ff9b::5db8:d822`.  
2. **Stateful NAT64 Header Translation (RFC 7915 / RFC 6145 SIIT)**:  
   - The 40-byte IPv6 header is replaced with a 20-byte IPv4 header.  
   - The IPv6 source address is mapped to a public IPv4 address from the carrier pool.  
   - TCP/UDP pseudo-header checksums are incrementally updated to account for IPv6 (320-bit pseudo-header) to IPv4 (96-bit pseudo-header) length changes.

---

## 4\. Port Quota Sizing & Path MTU Clamping

### 4.1 Subscriber Session Quota Sizing

- **Default Browsing**: Modern web browsers open 6 to 15 concurrent TCP connections per domain (HTTP/2 and HTTP/3 reduce socket counts, but third-party trackers and ads open 60–120 sockets per page).  
- **P2P & Gaming**: BitTorrent clients, Steam updates, and voice channels (Discord WebRTC) easily burst to 500–800 concurrent UDP/TCP sessions.  
- **Quota Recommendation**: 1024 ports per residential subscriber provides headroom for 850 active sockets while supporting 63 subscribers per public IPv4 address (63:1 consolidation ratio). Setting quota \$\< 512\$ causes socket drops; setting quota \$\> 4096\$ wastes public IPv4 addresses.

### 4.2 TCP MSS Clamping

- Standard Ethernet MTU: 1500 bytes.  
- Mobile encapsulation overhead (GTP-U tunnels: 40 bytes; IPv6 transport: 40 bytes; IPsec: 50–70 bytes).  
- Without clamping, 1500-byte packets exceed PMTU and are silently dropped when Don't Fragment (DF=1) is set.  
- *Remediation*: Enforce `ip tcp adjust-mss 1412` (or `1360` for 5G mobile) on subscriber ingress.

---

## 5\. 10-Point Zero-Trust CGNAT & NAT64 Security Audit Rubric

| Control ID | Evaluation Domain | Weight | Standards Baseline |
| :---- | :---- | :---: | :---- |
| **CGN-SEC-01** | RFC 6598 Shared Address Allocation | 15 pts | Subnet strictly in `100.64.0.0/10` to avoid RFC 1918 collisions. |
| **CGN-SEC-02** | RFC 7422 Deterministic Port Batching | 15 pts | Algorithmic port allocation for instant O(1) Lawful Intercept. |
| **CGN-SEC-03** | Subscriber Port Quota Enforcement | 12 pts | Limits per-subscriber ports to 1024–2048 to prevent DoS pool exhaustion. |
| **CGN-SEC-04** | EIM & Hairpinning per RFC 4787/5382 | 12 pts | Endpoint-independent mapping enables internal P2P and WebRTC. |
| **CGN-SEC-05** | State Timeout Tuning | 10 pts | Reclaims dead TCP/UDP sockets (TCP \<= 1800s, UDP \<= 120s). |
| **CGN-SEC-06** | IP Virtual Packet Reassembly (VPR) | 10 pts | Reassembles fragments before translation; prevents fragment evasion. |
| **CGN-SEC-07** | Stateful NAT64 & DNS64 Integration | 8 pts | Translates IPv6-only traffic using `64:ff9b::/96`. |
| **CGN-SEC-08** | TCP MSS Clamping Protection | 8 pts | Caps TCP MSS at 1360–1412 bytes against PMTU blackholes. |
| **CGN-SEC-09** | Anti-Spoofing uRPF Ingress | 5 pts | Discards spoofed packets entering subscriber ingress. |
| **CGN-SEC-10** | High-Speed Logging (HSL) / IPFIX | 5 pts | Offloads translation logging to NetFlow/IPFIX hardware collectors. |

