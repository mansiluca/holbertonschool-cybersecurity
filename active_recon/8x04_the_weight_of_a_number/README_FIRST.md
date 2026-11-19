# 8x04 - The Weight of a Number

Three scanners already ran against Aurum Pay. Their reports are in `reports/`.
You do NOT run or wrap the scanners. You build the analysis layer after them:
normalise, correlate, triage, verify, re-score and prioritise.

## What you build (your own scripts, emitting structured output)
  1-normalizer.py   Tasks 1-3: Nikto + OpenVAS + Nessus -> one schema
  4-correlate.py    Tasks 4-5: merge the same flaw across scanners + classify
  6-triage.py       Task 6: trusted / suspected_false_positive / needs_verification
  7-verify.py       Task 7: confirm/refute contested findings on the LIVE target
  8-rescore.py      Task 8: CVSS v3.1 AND v4.0 base -> environmental, per asset
  9-prioritize.py   Task 9: business-risk order (JSON + CSV) integrating KEV/EPSS
  10-vulnerability_assessment_report.md   Task 10: the client report
  README.md

Tasks 2-3 extend 1-normalizer.py; Task 5 extends 4-correlate.py.

## Inputs (read-only)
  reports/   nikto.xml  openvas.xml  scan.nessus
  context/   asset_model.json  threat_context.json  kev.json  epss.csv
  reference/ unified_schema.json  cvss_helper.py  *_NOTES.md  SCHEMA_GUIDE.md
             OUTPUT_CONTRACTS.md  output_examples.md
  outputs/   put your generated normalized.json / correlated.json / ... here

## The live verification target (Task 7), mapped inside this container
  http://shop.aurumpay.example:8080
  http://db.aurumpay.example:8080
  http://internal-api.aurumpay.example:8080
  http://decom-07.aurumpay.example:8080
Use SAFE methods only (GET/HEAD/OPTIONS). Confirm on real signal; never exploit.

## CVSS scoring
`reference/cvss_helper.py` turns a vector string into a base or environmental
score for BOTH v3.1 and v4.0. It does NOT know the asset model - YOUR 8-rescore.py
decides how criticality becomes environmental metrics. Example:
  python3 reference/cvss_helper.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

Tasks 0 and 11-14 are completed on the intranet, not here.
