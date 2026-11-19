# Output shape examples (neutral, illustrative)

These show SHAPE only - not the answers for this estate.

normalized (one finding):
  {"id":"F-XXX-001","asset":"host.example","source":"nessus","severity":
   "medium","confidence":0.9,"cve":["CVE-0000-0000"],
   "cvss":{"version":"4.0","vector":"CVSS:4.0/...","base_score":6.5}}

correlated (one merged finding):
  {"merged_id":"V-0001","asset":"host.example","sources":["openvas","nessus"],
   "classification":"agreed","cve":["CVE-0000-0000"]}

priority.csv header:
  rank,merged_id,asset,base,environmental,kev,epss,confidence,verification,
  priority,justification
