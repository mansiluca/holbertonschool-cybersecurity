# Scan Report, Berent Industrial
Prepared by: Junior Penetration Tester, Ridgeline Security
For: Ridgeline engagement team
Date: 2026-10-30

## 1. Executive summary

The Berent Industrial range 10.10.10.0/24 hosts **eight live systems**, not the
six a default `nmap -sn` sweep returns. Two of them are invisible to ICMP: one
answers only on a single TCP port (10.10.10.37), the other only on UDP
(10.10.10.12). Any inventory built on default discovery would have shipped six
hosts and missed a quarter of the estate, including the SNMP endpoint.

Six services are confirmed open and reachable: SSH and HTTP on 10.10.10.10,
SNMP on 10.10.10.12 (UDP), SMB on 10.10.10.15, HTTPS on the non-standard port
8443 of 10.10.10.20, and an SMTP daemon behind implicit TLS on 4650 of
10.10.10.30. Two further ports on 10.10.10.10 are open but filtered to honest
probes: 3306 is reachable only through a source-port rule the perimeter trusts
(53), and 443 is closed while its partner port 8443 sits behind a rate
threshold on a different host.

The perimeter behaves like a **default-deny firewall with a short allowlist**:
an ACK scan of 10.10.10.10 returns RST (unfiltered) on 22, 80 and 443 and
silence (filtered) on 445 and 3389. On top of that policy sits a naive rule
that trusts traffic whose source port looks like a DNS response, and a reactive
control that isolates a host once probe rate crosses a threshold. Both are
bypassable and both are documented here with the technique that bypassed them.

Operating constraints held throughout: no `-T5`, no `-A` sweep of the subnet,
no service-disruptive probes, one technique per script, output left in its
classical form. The most expensive scan in the set (10.10.10.20, port 8443)
was deliberately paced to 631 seconds of runtime to stay under the rate
threshold. Speed was traded for accuracy exactly once, on purpose.

## 2. Host inventory

| Host | Role (inferred) | Discovered by | Notes |
| --- | --- | --- | --- |
| 10.10.10.1 | Default gateway / edge | ICMP echo and TCP SYN | No open TCP port in the full range; IPID randomised, unusable as zombie |
| 10.10.10.10 | Application host | ICMP echo and TCP SYN | SSH, HTTP; 3306 filtered to honest probes, 443 closed |
| 10.10.10.12 | Management / monitoring | **UDP probe only** (161/udp) | Silent to ICMP and to TCP SYN across all 65535 ports |
| 10.10.10.15 | File / SMB host | ICMP echo and TCP SYN | 445 open; IPID randomised |
| 10.10.10.20 | Web front end (TLS) | ICMP echo and TCP SYN | 8443 filtered unless the scan rate stays under the IDS threshold |
| 10.10.10.30 | Mail relay | ICMP echo and TCP SYN | 4650 ssl/smtp, Postfix 3.5.6 |
| 10.10.10.37 | Hidden administration host | **TCP SYN only** (22/tcp) | Mute to ICMP, mute on every other port; the host a one-probe sweep never registers |
| 10.10.10.50 | Web host and idle-scan zombie | ICMP echo and TCP SYN | 80 open; IPID Class: Incremental, genuinely idle |

Evidence for the two hidden hosts, which is the part of this inventory the next
phase should not have to re-verify:

* **10.10.10.37** appears only when the discovery sweep carries TCP SYN probes.
  `nmap -sn 10.10.10.0/24` returns six hosts and does not list it. Adding
  `-PS22,80,443,445,4650,8080,8443` raises the count to seven and the host
  answers on 22 alone. A full `-sS -p1-65535` confirms nothing else is open.
* **10.10.10.12** appears only when UDP probes are added. `-PS` on the same
  port set still misses it, and `-sS -p1-65535` returns every port
  closed/filtered. `-PU161,53,137` registers it, and the follow-up scan shows
  161/udp open.

The final discovery command, which returns all eight:

```
nmap -sn -PS22,80,443,445,4650,8080,8443 -PU161,53,137 10.10.10.0/24
```

## 3. Port and service inventory

| Host | Port | Proto | State | Service | Version | Technique that established it |
| --- | --- | --- | --- | --- | --- | --- |
| 10.10.10.10 | 22 | tcp | open | ssh | OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0) | `-sV --version-all` on confirmed open port |
| 10.10.10.10 | 80 | tcp | open | http | nginx 1.21.0 | `-sV --version-all` on confirmed open port |
| 10.10.10.10 | 443 | tcp | closed | https | - | SYN scan; corroborated by ACK scan (unfiltered) |
| 10.10.10.10 | 3306 | tcp | open | mysql | not fingerprinted (evasion path only) | source-port 53 + fragmentation |
| 10.10.10.10 | 445, 3389 | tcp | filtered | microsoft-ds, ms-wbt-server | - | SYN scan; corroborated by ACK scan (filtered) |
| 10.10.10.12 | 161 | udp | open | snmp | not fingerprinted | `-sU -sV` (resolves open\|filtered) |
| 10.10.10.15 | 445 | tcp | open | microsoft-ds | soft match, no version token returned | SYN scan, then decoy scan for confirmation |
| 10.10.10.20 | 8443 | tcp | open | https-alt | not fingerprinted | SYN scan under `--max-rate 1` |
| 10.10.10.30 | 4650 | tcp | open | ssl/smtp | Postfix 3.5.6 (from the application banner) | manual TLS banner grab |
| 10.10.10.37 | 22 | tcp | open | ssh | OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 | SYN scan |
| 10.10.10.50 | 80 | tcp | open | http | nginx 1.21.0 | SYN scan; also seen through the idle scan |
| 10.10.10.1 | - | - | - | - | - | no open port in 1-65535 |

Port states that were ambiguous at first pass and how they were resolved:

* **161/udp on 10.10.10.12** returns `open|filtered` to a plain `-sU` scan,
  because a UDP scan gets no reply from an open port and no reply from a
  filtered one. Version detection on the same port forces the daemon to answer
  and the state settles as `open`. That verdict rests on two observations
  (the probe response and the service fingerprint), not on silence.
* **8443/tcp on 10.10.10.20** returns `filtered` with a note that the host
  appears reactively filtered. The port is genuinely open; the perimeter
  isolated the host after the fast pass. Pacing the scan below the threshold
  returns `open`.
* **3306/tcp on 10.10.10.10** is `filtered` to every honest probe and `open`
  when the probe carries source port 53 with fragmentation. The state is
  corroborated by the absence of the port in the unfiltered ACK output, which
  shows the firewall, not the host, was doing the dropping.

## 4. Firewall behaviour

ACK scan of 10.10.10.10 across the ports of interest:

| Port | ACK verdict | Reading |
| --- | --- | --- |
| 22/tcp | unfiltered (RST returned) | Firewall passes the packet, host answers per RFC 793 |
| 80/tcp | unfiltered | Same |
| 443/tcp | unfiltered | Same; a SYN scan shows closed, so the host itself refuses |
| 445/tcp | filtered (no reply) | Firewall drops |
| 3389/tcp | filtered (no reply) | Firewall drops |

Verdict: **default-deny-with-allowlist**. Three ports are admitted, two are
silently dropped, and the dropped set is small and service-shaped (SMB, RDP) —
the signature of a policy written as "permit these, deny the rest", not a
permissive default with a blocklist bolted on.

Two additional behaviours sit on top of that policy and matter more than the
rule list itself:

1. **Naive trusted source port.** Port 3306 is filtered to a normal SYN probe
   but open when the probe is sent from source port 53. The perimeter appears
   to admit traffic that looks like DNS returning from a resolver. That is a
   stateless rule reasoning about source ports instead of connection state.
   `-sS -g 53 -f -p3306` reaches the port; a stateful, application-aware
   firewall would not care about the source port and would still drop it.
2. **Reactive isolation on rate.** 10.10.10.20 answers `filtered` when the scan
   runs at full speed and `open` when the rate is capped at one probe per
   second. The control keys on raw probe rate rather than on probe signature.

Structural limit of the ACK scan, stated so the deduction does not outrun its
evidence: it reports filtered versus unfiltered only. It cannot distinguish an
open port from a closed one, and it says nothing about UDP. The categories
above are inferred from the pattern plus the SYN results, not from the ACK
output alone.

## 5. Scan methodology

**Strategy: two phases, broad then deep.** Phase one is discovery and light
port-state work across the whole /24: cheap, non-intrusive, ICMP plus a small
set of TCP and UDP probes chosen to catch hosts that ignore ICMP. Phase two
runs targeted deep scans on the eight survivors only — version detection,
manual banner grabbing, ACK mapping, evasion, decoys, idle scan, OS detection.
The two-phase approach is both faster and more accurate than a flat `-A` sweep:
it never sends a version probe to a host that did not answer discovery, so a
fragile controller is never touched by the technique that breaks controllers,
and it keeps the probe volume low enough to stay under the rate threshold.

Per technique:

1. **Discovery.** `-sn` with TCP SYN on 22, 80, 443, 445, 4650, 8080, 8443 and
   UDP on 161, 53, 137. ICMP echo alone returned six hosts and missed both
   hidden systems. Port choice follows what a default-deny perimeter usually
   leaves reachable: web, mail, SMB, management.
2. **Port state.** SYN scans on all 65535 ports, per host, followed by a second
   technique wherever the first pass was ambiguous: UDP version detection for
   161/udp, ACK scan for the filtered TCP ports, and a paced rescan for 8443.
3. **ACK mapping.** `-sA` on 10.10.10.10 over the port set above. RST means
   unfiltered, silence means filtered.
4. **Version detection.** `-sV --version-all` restricted to ports already
   confirmed open, on 10.10.10.10. Intensity was raised only after the open
   set was known, so the extra probes landed on two ports instead of 65535.
5. **Manual banner grabbing.** `openssl s_client -connect 10.10.10.30:4650
   -starttls smtp -servername mail.berent.lab -showcerts`. Automated detection
   cannot identify this service because the application protocol sits inside
   TLS; the client negotiates TLS, issues the protocol-correct SMTP greeting
   exchange, and reads `220 mail.berent.example ESMTP Postfix (3.5.6)`. The
   version is taken from the application banner, not from the certificate,
   which names the host rather than the software.
6. **Timing.** `--max-rate 1` on 10.10.10.20, port 8443. A named template was
   deliberately avoided: `-T2` with `--max-rate 10` still tripped the
   threshold, and only an explicit rate cap kept the scan invisible. Runtime
   631 seconds for a single port is the accepted cost.
7. **Source-port and fragmentation evasion.**
   `nmap -sS -g 53 -f -p3306 10.10.10.10`. Source port 53 satisfies the naive
   rule, fragmentation splits the probe below the inspection window of a
   stateless filter.
8. **Decoys.** `nmap -sS -D 10.10.10.1,10.10.10.30,ME,10.10.10.37 -p445
   10.10.10.15`. Decoys are live hosts from the inventory so they cannot be
   filtered out as noise, and the real address sits in the middle of the list.
   Fidelity is preserved: the 445 result matches the independent SYN scan.
9. **Idle scan.** `nmap -sI 10.10.10.50 -p80 10.10.10.10`. Candidate selection
   was the real work: 10.10.10.1, .15, .20, .30 and .37 all reported
   `Class: Randomized` and were rejected. 10.10.10.50 reports
   `Class: Incremental` and is idle, so its IPID works as the oracle. The
   target never received a packet from the scanner's address.
10. **OS detection.** `nmap -O 10.10.10.10`, a host with open and closed ports
    so the fingerprint has both halves. Result: Linux 5.X,
    `cpe:/o:linux:linux_kernel:5`, range Linux 5.0 - 5.14, network distance
    2 hops. The verdict is consistent with the service banners already held
    (OpenSSH packaged for Ubuntu, nginx on the same host), which is the
    cross-check that keeps a weighted match from being read as a fact.

Every command is delivered as a single-line script, reproducible by anyone with
the same lab runner: re-running a script reproduces the output quoted in this
report.

## 6. Confidence and limitations

**Confirmed (two independent observations or a direct protocol response):**

* Eight live hosts. Six are reachable by ICMP and TCP; 10.10.10.37 by TCP only;
  10.10.10.12 by UDP only.
* 22, 80 on 10.10.10.10 with full version tokens; 161/udp on .12; 445 on .15;
  8443 on .20; 4650 on .30 with the Postfix banner; 22 on .37; 80 on .50.
* Firewall category default-deny-with-allowlist on 10.10.10.10, corroborated by
  ACK plus SYN results.
* Rate-based reactive isolation on 10.10.10.20, demonstrated by the difference
  between a fast pass (filtered) and a paced pass (open).

**Soft matches and open questions:**

* 445 on 10.10.10.15 returns the service name without a version token. That is
  a soft match, not a finding about the SMB implementation.
* 3306 on 10.10.10.10 was reached through evasion and never version-probed; the
  service name comes from the port-to-service table. Probing it would require
  sending further spoofed probes, which the engagement does not need at this
  stage.
* 8443 on 10.10.10.20 and 161/udp on 10.10.10.12 are open but unfingerprinted.
* OS detection ran on 10.10.10.10 only. The other seven hosts have no
  fingerprint, so no OS claim is made for them.
* 10.10.10.1 has no open TCP port in the full range. It may still expose UDP
  services; UDP coverage was limited to three probe ports, not a full sweep.

**Could still be hiding:**

* UDP beyond 161, 53 and 137 was not swept. A UDP service on another port on
  any host would not have been seen.
* Hosts that answer neither ICMP, nor the seven TCP discovery ports, nor the
  three UDP discovery ports, remain invisible to phase one. Discovery is a
  hypothesis about where hosts live, not a proof of the full inventory.
* Decoy scanning defeats source-based alerting and log triage, not causal
  analysis: a defender who correlates completed handshakes can still single
  out the real scanner. The decoy results are accurate, the stealth is partial
  by construction.
* The idle scan's validity depends on 10.10.10.50 staying idle. If the zombie
  starts generating its own traffic, the IPID oracle degrades and the result
  becomes unreliable without any visible error.
* A full-speed port scan of 10.10.10.20 triggers reactive isolation for the
  remainder of the engagement. Any follow-up work on that host must be paced
  from the first packet.
* Scans in this lab are executed through a modelled runner that returns
  classical tool output; the values above are those the runner returned. Exact
  Nmap wording may differ slightly with another Nmap version.

## Appendix A: Task deliverables index

| Script | Task | Finding it produces |
| --- | --- | --- |
| `1-discovery.sh` | 1. Live hosts in a defended subnet | 8 hosts; hidden host 10.10.10.37 (TCP-only) and 10.10.10.12 (UDP-only) |
| `2-portstate.sh` | 2. Accurate port state | 161/udp open snmp on 10.10.10.12 |
| `3-firewall.sh` | 3. Firewall ruleset mapping | 22/80/443 unfiltered, 445/3389 filtered -> default-deny-with-allowlist |
| `4-versions.sh` | 4. Service version detection | OpenSSH 8.2p1 Ubuntu 4ubuntu0.5, nginx 1.21.0 |
| `5-banner.sh` | 5. Manual banner grabbing | Postfix 3.5.6 on 10.10.10.30:4650 |
| `6-timing.sh` | 6. Timing below the detection threshold | 8443/tcp open on 10.10.10.20 (paced, 631 s) |
| `7-evasion.sh` | 7. Source-port and fragmentation evasion | 3306/tcp open mysql on 10.10.10.10 |
| `8-decoy.sh` | 8. Decoy scanning | 445/tcp open on 10.10.10.15, fidelity preserved |
| `9-idlescan.sh` | 9. Blind idle scan | zombie 10.10.10.50; 10.10.10.10:80 open |
| `10-osdetect.sh` | 10. OS detection | Linux/5.x on 10.10.10.10 (5.0-5.14, 2 hops) |
