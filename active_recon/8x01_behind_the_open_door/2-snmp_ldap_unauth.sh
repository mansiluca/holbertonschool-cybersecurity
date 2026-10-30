#!/bin/bash
mkdir -p results
ip=$(getent hosts monitor.carmichael.lab | awk 'NF {print $1; exit}')
community=$(onesixtyone -c reference/communities.txt "$ip" 2>/dev/null |
  grep -o '\[[^]]*\]' | tr -d '[]' | head -n 1)
basedn=$(ldapsearch -x -LLL -H ldap://directory.carmichael.lab -s base namingContexts 2>/dev/null |
  awk -F': ' '/^namingContexts/ {print $2; exit}' | sed 's/dc=/DC=/g')
printf '%s\n%s\n' "$community" "$basedn" | tee results/2-snmp_ldap_unauth.txt
