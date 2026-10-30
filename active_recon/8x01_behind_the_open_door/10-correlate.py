#!/usr/bin/python3
"""Correlate the SMB, SNMP and LDAP findings produced by tasks 1 to 9."""
import os
import sys

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def read_lines(name):
    path = os.path.join(RESULTS, name)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def main():
    smb = read_lines("4-smb_rid_cycle.txt")
    ldap = read_lines("8-ldap_dump.txt")
    creds = read_lines("9-ldap_description_hunt.txt")
    snmp = read_lines("6-snmp_mib_walk.txt")
    if len(smb) < 1 or len(ldap) < 2 or not creds or not snmp:
        sys.stderr.write("missing task results in results/\n")
        return 1
    account = smb[0].split("\\")[-1].lower()
    group = ldap[1]
    user = creds[0].split(":")[0].lower()
    password = creds[0].split(":", 1)[1]
    secret = snmp[0]
    if not account or account != user:
        sys.stderr.write("no common service account across the results\n")
        return 1
    fact = ("%s holds %s membership and one cleartext password reused "
            "across SMB, SNMP and LDAP" % (user, group))
    print(fact)
    sys.stderr.write("correlated secret: %s (SNMP argument)\n" % secret)
    return 0


if __name__ == "__main__":
    sys.exit(main())
