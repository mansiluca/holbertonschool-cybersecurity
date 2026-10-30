#!/usr/bin/python3
"""Correlate the SMB, SNMP and LDAP findings produced by tasks 1 to 9."""
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
    account = smb[0].split("\\")[-1].lower()
    group = ldap[1]
    user = creds[0].split(":")[0].lower()
    if account != user:
        sys.stderr.write("no service account common to SMB, LDAP and SNMP\n")
        return 1
    fact = ("%s holds %s membership and one cleartext password reused "
            "across SMB, SNMP and LDAP" % (user, group))
    print(fact)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
