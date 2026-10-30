#!/bin/bash
mkdir -p results
shares=$(smbclient -L files.carmichael.lab -N 2>/dev/null)
rpcclient -N -U "" files.carmichael.lab -c "enumdomusers" > results/1-user_list_refused.txt 2>/dev/null
server=$(rpcclient -N -U "" files.carmichael.lab -c srvinfo 2>/dev/null)
domain=$(printf '%s\n' "$server" | grep -E 'Domain|Workgroup|CARMICHAEL' | awk 'NF {print $1; exit}')
share=$(printf '%s\n' "$shares" | grep 'Disk' |
  awk '$1 != "IPC$" && $1 != "ADMIN$" && $1 != "C$" {print $1; exit}')
printf '%s\n%s\n' "$share" "$domain" | tee results/1-smb_null_session.txt
