#!/bin/bash
mkdir -p results
domain=CARMICHAEL
users=$(rpcclient -N -U "" files.carmichael.lab -c "enumdomusers" 2>/dev/null)
account=""
for rid in $(printf '%s\n' "$users" | awk -F'[][ ]+' '/svc_/ {print $4}'); do
  name=$(printf '%s\n' "$users" | grep "$rid" | sed -n 's/.*user:\[\([^]]*\)\].*/\1/p')
  acb=$(rpcclient -N -U "" files.carmichael.lab -c "queryuser $rid" 2>/dev/null |
    awk -F':\t' '/acb_info/ {print $2; exit}')
  if [ -n "$acb" ] && [ $(( acb & 1 )) -eq 0 ]; then
    account="$name"
    break
  fi
done
rpcclient -N -U "" files.carmichael.lab -c "getdompwinfo" > results/4-password_policy.txt 2>/dev/null
minlen=$(awk -F': ' '/min_password_length/ {gsub(/ /, "", $2); print $2; exit}' results/4-password_policy.txt)
case "$minlen" in
  ""|"***")
    minlen=$(python3 - <<'PY'
from impacket.dcerpc.v5 import samr, transport
t = transport.SMBTransport("files.carmichael.lab", 445, r"\samr", "", "", "", "", "", "", "", doKerberos=False)
d = t.get_dce_rpc()
d.connect()
d.bind(samr.MSRPC_UUID_SAMR)
sh = samr.hSamrConnect(d)["ServerHandle"]
sid = samr.hSamrLookupDomainInSamServer(d, sh, "CARMICHAEL")["DomainId"]
dh = samr.hSamrOpenDomain(d, sh, domainId=sid)["DomainHandle"]
pw = samr.hSamrQueryInformationDomain(d, dh, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
print(pw["Buffer"]["Password"]["MinPasswordLength"])
PY
)
    ;;
esac
printf '%s\\%s\n%s\n' "$domain" "$account" "$minlen" | tee results/4-smb_rid_cycle.txt
