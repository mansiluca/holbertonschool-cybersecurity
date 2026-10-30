#!/bin/bash
mkdir -p results
share=$(smbmap -H files.carmichael.lab -u "" -p "" 2>/dev/null | tr -d '\r' |
  awk '$2 ~ /^READ/ && $1 != "public" && $1 != "IPC$" && $1 != "ADMIN$" && $1 != "C$" && $1 ~ /^[a-zA-Z0-9_-]+$/ {print $1; exit}')
printf '%s\n' "$share" | tee results/3-smb_share_acl.txt
