#!/bin/bash
mkdir -p results tmp_ldap
basedn=$(sed -n '2p' results/2-snmp_ldap_unauth.txt 2>/dev/null)
[ -z "$basedn" ] && { echo "no base DN from task 2" >&2; exit 1; }
ldapsearch -x -LLL -H ldap://directory.carmichael.lab -b "$basedn" "(objectClass=*)" > tmp_ldap/dump.ldif 2>/dev/null
computers=$(grep -c 'dn: cn=.*ou=computers' tmp_ldap/dump.ldif)
organizationalUnit=$(grep -c '^objectClass: organizationalUnit' tmp_ldap/dump.ldif)
users=$(grep -c '^objectClass: inetOrgPerson' tmp_ldap/dump.ldif)

awk '
  /^dn: uid=/ { sub(/^dn: uid=/, "", $0); split($0, a, ","); uid = a[1]; next }
  /^employeeType: / && uid != "" { print uid "\t" $2 }
' tmp_ldap/dump.ldif > tmp_ldap/status.tsv

awk '
  /^dn: cn=/ && /ou=groups/ { sub(/^dn: cn=/, "", $0); split($0, b, ","); cn = b[1] }
  /^member: / { split($0, m, "uid="); if (m[2] != "") { split(m[2], c, ","); print cn "\t" c[1] } }
' tmp_ldap/dump.ldif > tmp_ldap/members.tsv

account=$(sed -n '1p' results/4-smb_rid_cycle.txt 2>/dev/null | sed 's/.*\\//')
[ -z "$account" ] && account=$(awk -F'\t' '$2 ~ /^svc_/ && $1 != "" {print $2; exit}' tmp_ldap/status.tsv)

group=""
for candidate in $(awk -F'\t' -v a="$account" '$2 == a {print $1}' tmp_ldap/members.tsv); do
  status=$(awk -F'\t' -v a="$account" '$1 == a {print $2}' tmp_ldap/status.tsv)
  if [ "$status" != "disabled" ]; then group="$candidate"; break; fi
done
[ -z "$group" ] && group=$(awk -F'\t' '{print $1}' tmp_ldap/members.tsv | sort -u | head -n 1)

printf '%s\n%s\n' "$users" "$group" | tee results/8-ldap_dump.txt
