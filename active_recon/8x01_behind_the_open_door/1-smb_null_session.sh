#!/bin/bash
mkdir -p results
shares=$(smbclient -L files.carmichael.lab -N 2>/dev/null)
domain=$(rpcclient -N -U "" files.carmichael.lab -c srvinfo 2>/dev/null | awk 'NF {print $1; exit}')
share=$(printf '%s\n' "$shares" | awk '$2 == "Disk" && $1 != "IPC$" {print $1; exit}')
printf '%s\n%s\n' "$share" "$domain" | tee results/1-smb_null_session.txt
