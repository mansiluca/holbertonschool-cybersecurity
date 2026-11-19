# CVSS version notes (neutral)

A v3.1 vector starts `CVSS:3.1/` and uses AV/AC/PR/UI/S/C/I/A plus environmental
CR/IR/AR and modified-base metrics (MAV, MC, MI, MA, ...). A v4.0 vector starts
`CVSS:4.0/`, retires Scope, splits impact into VC/VI/VA (vulnerable system) and
SC/SI/SA (subsequent system), and adds AT. Environmental metrics include CR/IR/AR
and modified-base metrics (MAV, MAC, MAT, MVC, ...).

Detect the version from the prefix and branch; do NOT parse v4.0 as v3.1 or strip
its fields. `cvss_helper.py` does the parsing/scoring for both. YOUR job is to map
the asset model to environmental metrics, e.g. security_requirements -> CR/IR/AR
and network_position / lifecycle -> a modified attack vector and blast radius.
Preserve the base score; compute environmental alongside it.
