#!/usr/bin/env bash
PCAP="$1"
ATT="$2"
OUT="${3:-attacker_streams.pcap}"

if [ -z "$PCAP" ] || [ -z "$ATT" ]; then
  echo "Usage: $0 <pcap> <attacker_ip> [out.pcap]"
  exit 1
fi

echo "Exporting packets that contain IP $ATT from $PCAP -> $OUT"
tshark -r "$PCAP" -Y "ip.addr == $ATT" -w "$OUT"
echo "Done: $OUT"
