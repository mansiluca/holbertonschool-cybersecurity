#!/bin/bash
mkdir -p results
community=$(sed -n '1p' results/2-snmp_ldap_unauth.txt 2>/dev/null)
[ -z "$community" ] && { echo "no community from task 2" >&2; exit 1; }
ip=$(getent hosts monitor.carmichael.lab | awk 'NF {print $1; exit}')
tcpConnLocalPort=$(snmpwalk -v2c -c "$community" "$ip" 1.3.6.1.2.1.6 2>/dev/null)
udpLocalAddress=$(snmpwalk -v2c -c "$community" "$ip" 1.3.6.1.2.1.7 2>/dev/null)
services=$(snmpwalk -v2c -c "$community" "$ip" 1.3.6.1.4.1.8072.1.3.2 2>/dev/null)
line=$(printf '%s\n%s\n%s\n' "$tcpConnLocalPort" "$udpLocalAddress" "$services" |
  grep 'LISTEN' | grep -E '127\.0\.0\.1:[0-9]+' | head -n 1)
port=$(printf '%s\n' "$line" | grep -oE '127\.0\.0\.1:[0-9]+' | cut -d: -f2)
service=$(printf '%s\n' "$line" | awk '{print $NF}')
printf '%s/%s\n' "$service" "$port" | tee results/7-snmp_internal_ports.txt
