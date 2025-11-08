# Lab 01 — Network Scan Forensics Investigation
> *Hands-on network forensics exercise demonstrating SYN scan detection using Wireshark and tshark.*

**Tools:** Wireshark, tshark  
**PCAP source:** [Wireshark SampleCaptures](https://wiki.wireshark.org/samplecaptures) — `NMap Captures.zip`  
**File used:** [`sample_pcaps/nmap_standard_scan.pcap`](sample_pcaps/nmap_standard_scan.pcap)

---

## Objective

Detect and characterize network reconnaissance using packet capture analysis.  
Isolate attacker ↔ victim traffic and validate scan type via protocol-level analysis.

---

## Methods

1. Opened [`nmap_standard_scan.pcap`](sample_pcaps/nmap_standard_scan.pcap) in Wireshark.

2. Applied SYN-only filter:  `tcp.flags.syn == 1 && tcp.flags.ack == 0`  

    *Screenshot:* [`screenshots/syn-filter.png`](screenshots/syn-filter.png)

4. Identified attacker IP (`192.168.100.103`) and victim IP (`192.168.100.102`).

5. Isolated conversation:   `ip.addr == 192.168.100.103 && ip.addr == 192.168.100.102`  

   *Screenshot:* [`screenshots/attacker-victim-filter.png`](screenshots/attacker-victim-filter.png)

6. Verified scan activity using tshark commands:  
   ```bash
   tshark -r sample_pcaps/nmap_standard_scan.pcap \
     -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
     -T fields -e ip.src | sort | uniq -c | sort -rn
   ```
   The output confirmed `192.168.100.103` as the **sole source of SYN packets (2000 packets total)**.

   *Screenshot:* [`screenshots/tshark-syn-counts.png`](screenshots/tshark-syn-counts.png)

7. Counted destination ports to identify scan breadth:

   ```bash
   tshark -r sample_pcaps/nmap_standard_scan.pcap \
     -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
     -T fields -e tcp.dstport | sort | uniq -c | sort -n
   ```

   The results showed sequential SYNs to many TCP ports (e.g., 23, 25, 80, 135, 143, 1723, 8888, etc.).

   *Screenshot:* [`screenshots/tshark-port-counts.png`](screenshots/tshark-port-counts.png)

9. Listed SYN packets with frame number, source, destination, and MSS values to validate packet characteristics.

   *Screenshot:* [`screenshots/tshark-syn-list.png`](screenshots/tshark-syn-list.png)

11. Validated fingerprint by inspecting TCP flags and TCP options (`MSS=1460`, `Window=1024`).
   Observed sequential SYN packets to multiple destination ports, confirming an automated scanning pattern.

    *Screenshot:* [`screenshots/syn-packet-details.png`](screenshots/syn-packet-details.png)

12. Followed a TCP stream (`tcp.stream eq 5`) — the Follow Stream window was empty, confirming no completed handshake or        payload exchange.

    *Screenshot:* [`screenshots/follow-stream.png`](screenshots/follow-stream.png)

---

## Findings

* **Attacker:** `192.168.100.103`
* **Victim:** `192.168.100.102`
* **Behavior:** Rapid sequence of TCP SYN packets to multiple ports (23, 25, 80, 135, 143, 1723, 8888, etc.).
  Most ports show no SYN/ACK responses, indicating closed or filtered ports.
* **Analysis:** Pattern consistent with **Nmap TCP SYN (half-open)** or **connect scan**.
  No evidence of full TCP sessions or payload delivery was observed.
* **Conclusion:** The target host was under **reconnaissance**, not compromise.
  No post-scan exploitation activity detected within the capture window.

---

## Evidence & Reproducibility

* [`scripts/extract_syns.sh`](scripts/extract_syns.sh) — lists all SYN packets and counts per source.

   **Run:** `./scripts/extract_syns.sh sample_pcaps/nmap_standard_scan.pcap`

* [`scripts/export_attacker_pcap.sh`](scripts/export_attacker_pcap.sh) — exports attacker-only traffic.

  **Run:** `./scripts/export_attacker_pcap.sh sample_pcaps/nmap_standard_scan.pcap 192.168.100.103 attacker_streams.pcap`

* Screenshots:

  * [`screenshots/syn-filter.png`](screenshots/syn-filter.png)
  * [`screenshots/attacker-victim-filter.png`](screenshots/attacker-victim-filter.png)
  * [`screenshots/syn-packet-details.png`](screenshots/syn-packet-details.png)
  * [`screenshots/tshark-syn-counts.png`](screenshots/tshark-syn-counts.png)
  * [`screenshots/tshark-port-counts.png`](screenshots/tshark-port-counts.png)
  * [`screenshots/tshark-syn-list.png`](screenshots/tshark-syn-list.png)
  * [`screenshots/follow-stream.png`](screenshots/follow-stream.png)

---

## Conclusion & Recommendations

The capture demonstrates **network reconnaissance** consistent with automated scanning tools such as Nmap.
While no payload transfer or post-exploitation occurred, reconnaissance traffic indicates **potential targeting**.

**Recommended actions:**

* Correlate timestamps with IDS/firewall logs for the same source IP (`192.168.100.103`).
* Review endpoint telemetry for connection attempts from that address.
* If repeated scans occur, add the IP to monitoring or block lists.
* Continue observing for escalation or exploitation attempts.

---

**Author:** Abdinoor Ahmed

*Wireshark Packet Analysis — Cybersecurity Portfolio Lab*
