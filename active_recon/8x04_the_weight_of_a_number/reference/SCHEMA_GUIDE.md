# Unified schema guide (neutral)

Every normalised finding shares one schema (see `unified_schema.json`). Required
fields: id, asset, source, severity, confidence, description. Useful optional
fields: asset_ip, port, protocol, service, source_id, title, cve (list),
location (a path/endpoint a verifier could probe), cvss {version, vector,
base_score}, references.

Design the schema to fit all three scanners, not Nikto alone. Carry source
attribution so correlation can treat three sources as one comparable set. The
schema holds NO correlation, triage, verification or priority answer.
