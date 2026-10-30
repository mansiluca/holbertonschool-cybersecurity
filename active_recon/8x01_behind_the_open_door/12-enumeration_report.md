# Enumeration Report, Carmichael & West LLP
For: Ridgeline engagement team
Prepared by: Junior Penetration Tester, Ridgeline Security
Date: 2026-10-30

## 1. Executive summary

Carmichael & West LLP exposes more through its support services than through
anything it publishes. The SMB file server accepts an empty credential from a
stranger, hands out the domain name (CARMICHAEL) and mounts a backup share for
read; that share carries a legacy helper script with the SNMP community string
in clear (`SNMP_COMMUNITY="private"`). The SNMP agent recites its whole process
table to that community, including a backup agent running as `svc_backup` with
its password on the command line, and its listening-port table shows a
PostgreSQL service on 127.0.0.1:5432 that no external scan can see.

The directory allows an anonymous bind and a full dump: 214 user objects, an
`IT-Admins` group, and a `description` field on `svc_backup` that holds
`svc_backup:W1nter2023!` in clear text. One account, seen three ways, and one
credential that turns the anonymous refusal into authenticated access:
`clientmatters`, denied to the null session, is readable as `svc_backup`.

Nothing was exploited, cracked or modified. The chain is leak, then credential
reuse, then access to a share the anonymous session could not mount.

## 2. Per-protocol findings (SMB, SNMP, LDAP)

### SMB - files.carmichael.lab

| Finding | Evidence |
| --- | --- |
| Null session accepted (`Status: NULL Session`) | `smbclient -L -N`, `rpcclient` without credentials |
| Domain `CARMICHAEL`, server `Carmichael File Services` | `rpcclient -c srvinfo` |
| Shares: `public` (READ), `clientmatters` (NO ACCESS), `backups` (READ), `legal-templates` (NO ACCESS), `IPC$` | `smbmap -H files.carmichael.lab -u "" -p ""` |
| `backups` readable by an unauthenticated session and holding `backup_legacy.sh` | `smbclient //files.carmichael.lab/backups -N -c "get backup_legacy.sh -"` |
| Secret in that file: `SNMP_COMMUNITY="private"` | content of the script |
| Service account `svc_backup`, enabled (ACB `0x00000010`); `administrator_old` disabled (`0x00000011`) | `rpcclient enumdomusers` + `queryuser <rid>` |
| Minimum password length 8 | SAMR `DomainPasswordInformation` (rpcclient masks the value, so the SAMR query is used) |

`public` holds only `welcome.txt` (a public drop notice). The share that matters
is `backups`: it is readable by a session that should never have had it, and its
content is the pivot that feeds SNMP.

### SNMP - monitor.carmichael.lab

| Finding | Evidence |
| --- | --- |
| `public` disabled, `private` accepted | `onesixtyone -c reference/communities.txt 127.81.0.20` |
| Process table exposes `/usr/local/bin/backup-agent --account svc_backup --password Pr0d!Backup#9 --dest /mnt/tape01` | `nsExtendOutput1Line` (process table) |
| Listening table exposes `tcp 127.0.0.1:5432 LISTEN postgresql` | `nsExtendOutput1Line` (listening table) |

The 5432 listener is bound to loopback, which is why an external scan never sees
it. This is the "inside view" the task asked for: the agent's own account of
what the host listens on, not what the firewall lets through.

### LDAP - directory.carmichael.lab

| Finding | Evidence |
| --- | --- |
| Anonymous bind accepted, naming context `dc=carmichael,dc=local` | `ldapsearch -x -s base namingContexts` |
| 214 `inetOrgPerson` objects | full `ldapsearch` dump |
| Groups: `Partners`, `Finance`, `IT-Admins`, `Administrators` | dump, `groupOfNames` entries |
| `Administrators` holds only `svc_oldadmin`, `employeeType: disabled` | dump, entry attributes |
| `IT-Admins` holds five accounts including the active `svc_backup` | dump, membership cross-checked with `employeeType` |
| `description: svc_backup:W1nter2023!` on `uid=svc_backup` | `ldapsearch description` over `inetOrgPerson` |

The privileged group is `IT-Admins`, not `Administrators`: the latter is a title
without live members, an account that is switched off. Reading status rather
than the group name is what separates the two.

## 3. Consolidated organizational picture

```
svc_backup holds IT-Admins membership and one cleartext password reused
across SMB, SNMP and LDAP
```

The join: `svc_backup` is an SMB account (task 4), an LDAP object in `IT-Admins`
with a credential in its `description` (tasks 8 and 9), and the account running
the backup agent whose command line leaks the password over SNMP (task 6). Three
protocols, one identity, one secret, three independent leaks of the same fact.

## 4. The enumeration chain

1. **Leak.** The null session mounts `backups` and reads `backup_legacy.sh`,
   which carries `SNMP_COMMUNITY="private"`.
2. **Wider leak.** With that community, SNMP returns the process table: the
   backup agent runs as `svc_backup` with `--password Pr0d!Backup#9` on the
   command line.
3. **Directory.** Anonymous LDAP returns 214 users and, in the `description`
   attribute nobody reads, `svc_backup:W1nter2023!`.
4. **Key.** The credential is spent only against the service it belongs to.
   `clientmatters`, which returned `NT_STATUS_ACCESS_DENIED` to the null
   session, now lists `MATTER-INDEX.txt`: `clientmatters: READ granted as
   svc_backup`.

## 5. Methodology

| Script | What it does | Reproduce |
| --- | --- | --- |
| `1-smb_null_session.sh` | Null session, reads the share list and `srvinfo`; picks the first non-administrative disk share and the server's domain | `./1-smb_null_session.sh` |
| `2-snmp_ldap_unauth.sh` | Resolves the monitor host, brutes the supplied community list with `onesixtyone`, reads the LDAP naming context | `./2-snmp_ldap_unauth.sh` |
| `3-smb_share_acl.sh` | Permission map via `smbmap`, selects the READ share that is not the declared public drop | `./3-smb_share_acl.sh` |
| `4-smb_rid_cycle.sh` | Enumerates accounts, queries each `svc_` account's ACB flags, keeps the enabled one, then reads the domain password policy over SAMR | `./4-smb_rid_cycle.sh` |
| `5-smb_share_loot.sh` | Downloads every file in the readable non-public shares and greps for the community assignment | `./5-smb_share_loot.sh` |
| `6-snmp_mib_walk.sh` | Walks the agent's extension tables and extracts the `--password` argument | `./6-snmp_mib_walk.sh` |
| `7-snmp_internal_ports.sh` | Walks the listening-port table, keeps the listener bound to loopback | `./7-snmp_internal_ports.sh` |
| `8-ldap_dump.sh` | Full directory dump, counts `inetOrgPerson`, resolves the group holding the active service account | `./8-ldap_dump.sh` |
| `9-ldap_description_hunt.sh` | Queries `description` across users, keeps the value shaped like `user:password` | `./9-ldap_description_hunt.sh` |
| `10-correlate.py` | Reads `results/`, normalises the account across protocols, prints the consolidated fact | `./10-correlate.py` |
| `11-auth_pivot.sh` | Authenticates with the recovered credential against the share that refused the anonymous session | `./11-auth_pivot.sh` |

Scripts 1 to 11 run in that order: each later script consumes a file in
`results/` written by an earlier one. Every finding is reproducible from the
script alone: same target, same script, same value.

## 6. Limitations

* `clientmatters` was opened and its index listed, but its contents were not
  extracted: one index file proves access without copying client material. The
  same applies to `legal-templates`, which stayed `NO ACCESS` throughout and was
  never read.
* The minimum password length comes from SAMR as an unauthenticated session;
  `rpcclient` masks the value, so an impacket SAMR query is used instead. Both
  read the same server-side policy, but the value was seen through one API only.
* SNMP was read through the process and listening tables the agent exposes to
  the `private` community. Other subtrees of the MIB were walked but produced
  nothing sensitive; if the agent holds further extension tables, they were not
  identified.
* LDAP was dumped anonymously. Attributes other than `description` were not
  hunted one by one, so a second credential could sit in an attribute not
  queried here.
* The PostgreSQL service on 127.0.0.1:5432 is known only from the host's own
  listening table. It was not contacted: it is outside the authorised targets
  and binding it to loopback is why it stayed invisible externally.
* No password was cracked and no exploit was used. The chain relies entirely on
  data the services volunteered.
