# 🗺 Roadmap — ExtremeSniffer — C++ Network Security Tool

> Back to the [README](../README.md).

## Where the project stands

Status: **prototype**.

## Milestones

### v1.0 — Prototype (done)

- [x] libpcap capture with BPF filtering
- [x] Producer–consumer multithreading
- [x] Port-scan, connection-flood and packet-flood heuristics with JSON alerts
- [x] Geo-IP enrichment
- [x] Security analysis and LaTeX white-paper

### v1.1 — Production hardening

*Goal:* Make the tool configurable and safe to run long-term.

- [ ] CLI flags for interface, BPF filter, thresholds, thread count and MMDB path (no recompiling)
- [ ] Sliding time windows so counters decay instead of growing forever
- [ ] Lock-free ring buffer to replace the mutex-protected `std::queue`
- [ ] CMake build + GitHub Actions CI with unit tests on pcap fixtures

### v2.0 — Smarter detection

- [ ] SYN-flood, DNS-tunnelling and ARP-spoofing detectors
- [ ] Statistical / ML anomaly scoring (EWMA baselines, isolation forest)
- [ ] Output sinks — syslog, Elasticsearch, Kafka
- [ ] Live terminal dashboard (ncurses) with top talkers and alert feed

## 🔭 Long-term Vision

Evolve ExtremeSniffer into a lightweight, embeddable IDS sensor: drop it on a Raspberry Pi or a cloud VM, point it at an
interface, and stream enriched, de-duplicated alerts into any SIEM.

## 💡 Ideas Backlog (unscheduled)

- PCAP replay mode for offline forensics
- eBPF/XDP capture backend for 10 Gbps+ links

## How to help

Pick any unchecked item, open an issue to discuss the approach, then send a PR. Items in the earliest unfinished milestone are the highest priority.


---
*Last updated: 2026-11-14*
