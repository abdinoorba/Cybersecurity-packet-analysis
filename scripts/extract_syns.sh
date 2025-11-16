#!/usr/bin/env bash
PCAP="$1"
if [ -z "$PCAP" ]; then
  echo "Usage: $0 <pcap>"
  exit 1
fi

echo "=== SYN packets (frame, src, dst, dstport, mss) ==="
tshark -r "$PCAP" \
  -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport -e tcp.options.mss

echo
echo "=== SYN counts per source IP ==="
tshark -r "$PCAP" \
  -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.src | sort | uniq -c | sort -rn

echo
echo "=== Destination ports scanned (count) ==="
tshark -r "$PCAP" \
  -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e tcp.dstport | sort | uniq -c | sort -n

echo
echo "=== Top TCP conversations ==="
tshark -r "$PCAP" -q -z conv,tcp | sed -n '1,80p'
