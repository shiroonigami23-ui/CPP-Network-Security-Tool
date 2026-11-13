---
title: "ExtremeSniffer: A Lightweight Multithreaded Packet Inspector with Threshold-Based Anomaly Detection"
subtitle: "Technical Whitepaper — CPP-Network-Security-Tool v0.1"
author: "Aryan Singh Chandel (shiroonigami23-ui)"
date: "November 2026"
---

# Abstract

ExtremeSniffer is a C++ network monitor built on **libpcap**. It captures live TCP/UDP traffic and inspects HTTP and DNS payloads. It flags three classic signs of hostile behaviour (**port scans**, **connection floods** and **packet floods**) and emits machine-readable JSON alerts that carry **Geo-IP** context. The design separates capture from analysis with a producer–consumer queue, so a slow analysis step does not stall the kernel capture buffer. This paper describes the architecture, the detection logic and its thresholds, and how the tool is deployed. It also gives an honest account of the current limitations and the planned roadmap.

# 1. Motivation

Small labs, student networks and home setups rarely run a full IDS such as Snort, Suricata or Zeek. These systems are powerful but heavy to configure. The goal of ExtremeSniffer is a **single, readable C++ program** that:

- shows *what is on the wire right now* (who talks to whom, over which protocol, from where);
- raises a structured alert when a host behaves like a scanner or a flooder;
- is small enough to read end-to-end in an afternoon, so it doubles as a teaching artefact for packet parsing, BPF and concurrent C++.

# 2. System overview

```
 NIC ──► libpcap (BPF: "tcp or udp") ──► capture thread
                                             │  copies packet (PacketData)
                                             ▼
                                   std::queue + mutex + condvar
                                             │
                     ┌───────────────────────┴───────────────────────┐
                     ▼                                               ▼
           processing thread 1                             processing thread 2
   parse IPv4 → TCP/UDP → HTTP / DNS DPI-lite        (same pipeline)
   update flow / port / connection tables
   threshold checks ──► JSON alert (stdout)
   every 10th packet ──► flow summary + Geo-IP (MaxMind GeoLite2)
```

| Layer | Component |
|---|---|
| Capture | `pcap_open_live` in promiscuous mode, kernel-side BPF filter `tcp or udp` |
| Hand-off | `PacketData` (deep copy of header + bytes, move-only) in a `std::queue` guarded by a pthread mutex and condition variable |
| Analysis | `NUM_PROCESSING_THREADS = 2` worker threads |
| Enrichment | MaxMind DB (`libmaxminddb`, memory-mapped) behind its own mutex |
| Output | JSON alerts and human-readable summaries on stdout |

## 2.1 Why producer–consumer?

libpcap delivers packets through a callback on the capture thread. If that callback did DNS parsing, map updates and Geo-IP lookups inline, a burst of traffic would overflow the kernel ring buffer and packets would be **dropped silently**. Copying each packet into an owned `PacketData` and queueing it keeps the callback to a `memcpy` plus a lock. That makes it O(packet size) and bounded, while the expensive work runs on worker threads.

`PacketData` disables copying and implements move semantics, so ownership of each heap buffer is unambiguous: exactly one owner frees it, and moving through the queue never double-frees.

# 3. Packet parsing ("DPI-lite")

1. **Ethernet**: the 14-byte header is skipped.
2. **IPv4**: source and destination addresses come from `struct ip`, and the header length from `ip_hl × 4`.
3. **TCP**: ports and `th_off × 4` header length. On ports 80/8080 the first ≤200 payload bytes are checked for an HTTP method (`GET/POST/PUT/DELETE/HEAD`) and the `User-Agent` header.
4. **UDP**: ports, with a fixed 8-byte header. On port 53 the DNS `QR` bit is checked. For queries, the QNAME labels are decoded with a bounds check on every label so a malformed packet cannot read past the payload.

# 4. Detection model

Three per-source-IP tables are maintained:

| Table | Key → value | Detects |
|---|---|---|
| `port_scan_monitor` | src IP → set of destination ports | **Port scan**: ≥ `PORT_SCAN_THRESHOLD` (5) distinct ports |
| `connection_flood_monitor` | src IP → set of (dst IP, dst port) | **Connection flood**: ≥ 15 distinct endpoints |
| `flow_monitor` | src IP → {packets, bytes} | **Packet flood**: ≥ 50 packets |

When a threshold is crossed, an alert like the following is printed:

```json
{
  "anomaly_type": "Port Scan",
  "source_ip": "10.0.0.23",
  "destination_ip": "N/A",
  "detected_value": 7,
  "threshold": 5
}
```

The JSON shape is deliberately flat so it can be piped straight into `jq`, a log shipper, or a SIEM ingestion endpoint.

**Design rationale.** Set cardinality is a cheap, explainable signal. A host touching many *distinct* ports is the defining trait of a vertical scan, and many distinct endpoints in a short window points to horizontal scanning or a connection-exhaustion attempt. Raw packet counts catch volumetric floods. Every alert carries the measured value *and* the threshold, so an analyst can see why it fired.

# 5. Geo-IP enrichment

Every tenth packet from a source triggers a flow summary that resolves both endpoints to *City, Country* with MaxMind GeoLite2. The database is opened once with `MMDB_MODE_MMAP`, and lookups are serialised behind a dedicated mutex. Sampling one packet in ten keeps lookup cost negligible while still giving location context for active flows.

# 6. Deployment

- **Docker**: `docker build -t extremesniffer . && docker run --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN extremesniffer`. Raw capture needs these capabilities, not full root.
- **Native**: `g++ -std=c++17 ExtremeSniffer.cpp -o ExtremeSniffer -lpcap -pthread -lmaxminddb`.
- **Codespaces/devcontainer** for reading and building the code. Live capture needs a host with a real interface.
- A simpler single-threaded `NetworkSniffer.cpp` is kept as the minimal reference implementation.

# 7. Known limitations (honest assessment)

| # | Limitation | Impact | Planned fix |
|---|---|---|---|
| L1 | The three monitor maps are updated by two worker threads **without a lock** | Data race and possible corrupted map state under load | Shard the tables by source IP to a fixed worker, or guard them with a mutex |
| L2 | Thresholds are cumulative, with **no time window** | Long-lived busy hosts eventually alert, and alerts repeat every packet once over threshold | Sliding windows (e.g. 10 s) and per-source alert cooldown |
| L3 | Payload length is computed with unsigned arithmetic from `header->len` | Truncated or very short packets could underflow the length | Validate `caplen` against the cumulative header offsets before use |
| L4 | Assumes Ethernet + IPv4 | IPv6, VLAN-tagged frames and non-Ethernet link types are mis-parsed | Dispatch on `pcap_datalink()` and the EtherType, and add IPv6 |
| L5 | MaxMind DB path is hard-coded to a Colab Drive location | Fails outside the original notebook setup | CLI flag or env var, with graceful degradation when absent |
| L6 | `pcap_lookupdev` is deprecated, and capture stops after 100 packets (demo limit) | Not suitable for continuous monitoring as-is | `pcap_findalldevs`, an interface flag, and an unlimited loop with signal-based shutdown |
| L7 | HTTP inspection works only on plaintext ports 80/8080 | TLS traffic is opaque, as expected | Add TLS SNI and JA3 fingerprinting from the ClientHello |

# 8. Evaluation plan

No benchmark numbers are claimed in this version. The intended evaluation is:

1. **Correctness**: replay labelled PCAPs (e.g. CIC-IDS2017 port-scan and DoS days) with `pcap_open_offline` and report detection rate and false positives per threshold setting.
2. **Throughput**: tcpreplay at increasing rates and measure the kernel drop counter (`pcap_stats`) against the number of worker threads.
3. **Overhead**: CPU and RSS against Zeek on the same trace.

# 9. Roadmap

- Fix the concurrency issue (L1) and add time-windowed detection (L2), which are the highest priority.
- Add offline PCAP mode and a `--json-only` output mode for pipelines.
- Support IPv6 and VLAN.
- Add TLS metadata (SNI and JA3).
- Export Prometheus metrics, with a small web dashboard.
- Add a companion academic write-up; a LaTeX draft lives in `paper.tex` and `Papers/`.

# 10. Conclusion

ExtremeSniffer shows that a few hundred lines of C++ are enough for a useful, explainable network monitor. It combines kernel-side BPF filtering, a clean producer–consumer hand-off, lightweight protocol parsing and threshold-based anomaly alerts with Geo-IP context. Its main value today is clarity, as both a working tool and a teaching artefact. The limitations above form a concrete path to a production-grade lightweight IDS.

# References

1. McCanne, S. and Jacobson, V. *The BSD Packet Filter: A New Architecture for User-level Packet Capture.* USENIX Winter 1993.
2. The Tcpdump Group. *libpcap documentation.* https://www.tcpdump.org/
3. MaxMind. *libmaxminddb and GeoLite2 databases.* https://dev.maxmind.com/
4. Sharafaldin, I., Lashkari, A. H. and Ghorbani, A. A. *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization* (CIC-IDS2017). ICISSP 2018.
5. Paxson, V. *Bro: A System for Detecting Network Intruders in Real-Time.* Computer Networks, 1999.
