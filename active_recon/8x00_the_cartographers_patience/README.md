# 8x00 - The Cartographer's Patience

Scanning phase of the authorised penetration test against Berent Industrial
(10.10.10.0/24), Ridgeline Security engagement.

## Contents

| File | Task | Technique |
| --- | --- | --- |
| `1-discovery.sh` | Live hosts in a defended subnet | TCP SYN + UDP host discovery |
| `2-portstate.sh` | Accurate port state | UDP with version probe on 161/udp |
| `3-firewall.sh` | Firewall ruleset mapping | TCP ACK scan |
| `4-versions.sh` | Service version detection | `-sV --version-all` on known open ports |
| `5-banner.sh` | Manual banner grabbing | `openssl s_client -starttls smtp` |
| `6-timing.sh` | Timing below the detection threshold | `--max-rate 1` |
| `7-evasion.sh` | Source-port and fragmentation evasion | `-g 53 -f` |
| `8-decoy.sh` | Decoy scanning | `-D` with live hosts, real address mid-list |
| `9-idlescan.sh` | Blind idle scan | `-sI` through 10.10.10.50 |
| `10-osdetect.sh` | OS detection | `-O` |
| `11-scan_report.md` | Scan report | Full engagement report |

## Usage

Each script is a single command line after `#!/bin/bash`, executable, and is
run through the lab runner:

```bash
scanlab ./1-discovery.sh
```

## Method

Discovery is TCP and UDP first, never ICMP-only: two hosts on this subnet are
invisible to an ICMP sweep, one answering only on a single TCP port, the other
only on UDP. Port states are verified with a second technique before they are
recorded. Timing is capped explicitly with `--max-rate`, because the perimeter
reactively isolates hosts that are scanned fast.
