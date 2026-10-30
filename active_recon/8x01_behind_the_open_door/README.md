# 8x01 - Behind the Open Door

Enumeration phase of the authorised test against Carmichael & West LLP
(Ridgeline Security engagement). Targets: files.carmichael.lab (SMB),
monitor.carmichael.lab (SNMP), directory.carmichael.lab (LDAP).

## Deliverables

| Script | Prints | Technique |
| --- | --- | --- |
| `1-smb_null_session.sh` | non-administrative share, domain | `smbclient -L -N`, `rpcclient srvinfo` |
| `2-snmp_ldap_unauth.sh` | community string, base DN | `onesixtyone` over `reference/communities.txt`, anonymous `ldapsearch` rootDSE |
| `3-smb_share_acl.sh` | share readable by a stranger | `smbmap` permission map |
| `4-smb_rid_cycle.sh` | service account, minimum password length | `rpcclient enumdomusers` + `queryuser` (ACB flags), SAMR password policy |
| `5-smb_share_loot.sh` | secret in the readable share | `smbclient get` + content grep |
| `6-snmp_mib_walk.sh` | secret in a process argument | `snmpwalk` over the process table |
| `7-snmp_internal_ports.sh` | service the perimeter hid | `snmpwalk` over the listening-port table |
| `8-ldap_dump.sh` | user-object count, privileged group | full `ldapsearch`, group membership with account status |
| `9-ldap_description_hunt.sh` | cleartext credential | `ldapsearch description` over users |
| `10-correlate.py` | consolidated fact | reads `results/`, joins the three protocols |
| `11-auth_pivot.sh` | access bought by the credential | `smbclient` authenticated |

Every script runs the enumeration itself and prints only the finding, on
stdout. Diagnostics go to stderr. Each script keeps its finding in
`results/<n>-<name>.txt`, which is the input `10-correlate.py` consumes.

## Order

Tasks 1 to 9 must run in order, because each later task consumes a value from
an earlier one (`results/2-*` for the community and base DN, `results/4-*` for
the service account, `results/9-*` for the credential). Then `10-correlate.py`,
then `11-auth_pivot.sh`.

## Method

Unauthenticated first: null session, community brute over the supplied
wordlist, anonymous bind. Then deep extraction on what answered: open the
readable share, walk the process and listening tables the SNMP agent exposes,
dump the whole directory including the `description` attribute enumeration
usually skips. Correlation is a join over the saved findings, not a re-run.
No exploitation, no cracking, no modification: the credential is used only
against the SMB service it belongs to.
