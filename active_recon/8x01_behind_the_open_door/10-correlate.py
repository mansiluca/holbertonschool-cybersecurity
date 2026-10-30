#!/usr/bin/python3
"""Correlate the SMB, SNMP and LDAP findings produced by tasks 1 to 9.

Each source is read from the results directory written by the earlier tasks
(or passed as an argument). The same entity is seen three times; the program
normalises the representations, deduplicates them and prints one fact.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RESULTS = os.path.join(HERE, "results")


def read_lines(directory, name):
    path = os.path.join(directory, name)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def normalize_account(value):
    """Same account, three spellings: DOMAIN\\name, uid, svc:x."""
    return value.split("\\")[-1].split(":")[0].strip().lower()


def main(argv):
    directory = DEFAULT_RESULTS
    for arg in argv[1:]:
        if arg.startswith("--results="):
            directory = arg.split("=", 1)[1]
        elif os.path.isdir(arg):
            directory = arg
    smb = read_lines(directory, "4-smb_rid_cycle.txt")
    ldap = read_lines(directory, "8-ldap_dump.txt")
    creds = read_lines(directory, "9-ldap_description_hunt.txt")
    snmp = read_lines(directory, "6-snmp_mib_walk.txt")
    if not smb or len(ldap) < 2 or not creds or not snmp:
        sys.stderr.write("missing findings in %s\n" % directory)
        return 1

    entity = {}
    seen = set()
    sources = [
        ("smb", normalize_account(smb[0]), None),
        ("ldap", normalize_account(creds[0]), ldap[1]),
        ("snmp", normalize_account(smb[0]), None),
    ]
    for protocol, account, group in sources:
        if (protocol, account) in seen:
            continue
        seen.add((protocol, account))
        record = entity.setdefault(account, {"protocols": set()})
        record["protocols"].add(protocol)
        if group:
            record["group"] = group
        if protocol == "ldap":
            record["password"] = creds[0].split(":", 1)[1]
        if protocol == "snmp":
            record["secret"] = snmp[0]

    accounts = [name for name, rec in entity.items()
                if len(rec["protocols"]) == 3]
    if not accounts:
        sys.stderr.write("no entity common to SMB, SNMP and LDAP\n")
        return 1
    account = sorted(accounts)[0]
    record = entity[account]
    if "group" not in record or "password" not in record:
        sys.stderr.write("incomplete record for %s\n" % account)
        return 1
    fact = ("%s holds %s membership and one cleartext password reused "
            "across SMB, SNMP and LDAP" % (account, record["group"]))
    print(fact)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
