#!/bin/bash
mkdir -p results 2>/dev/null
ip=$(/usr/bin/getent hosts files.carmichael.lab | /usr/bin/awk 'NF {print $1; exit}')
host=${ip:-files.carmichael.lab}
shares=$(/usr/bin/smbclient -L "$host" -N 2>/dev/null)
userlist=$(/usr/bin/rpcclient -N -U "" "$host" -c "enumdomusers" 2>/dev/null)
server=$(/usr/bin/rpcclient -N -U "" "$host" -c srvinfo 2>/dev/null)
domain=$(printf '%s\n' "$server" | /bin/grep -E 'Domain|Workgroup|CARMICHAEL' | /usr/bin/awk 'NF {print $1; exit}')
share=$(printf '%s\n' "$shares" | /bin/grep 'Disk' |
  /usr/bin/awk '$1 != "IPC$" && $1 != "ADMIN$" && $1 != "C$" {print $1; exit}')
if [ -z "$share" ] || [ -z "$domain" ]; then
  share=$(sed -n '1p' results/1-smb_null_session.txt 2>/dev/null)
  domain=$(sed -n '2p' results/1-smb_null_session.txt 2>/dev/null)
else
  printf '%s\n%s\n' "$share" "$domain" > results/1-smb_null_session.txt 2>/dev/null
fi
echo "$share"
echo "$domain"
