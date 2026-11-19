# 8x04 - The Weight of a Number

Assessment of the Aurum Pay estate from three scanner reports: normalise,
correlate, triage, verify, re-score, prioritise.

## Pipeline

    ./1-normalizer.py reports/nikto.xml reports/openvas.xml reports/scan.nessus --write
    ./4-correlate.py outputs/normalized.json --write
    ./6-triage.py outputs/correlated.json --write
    ./7-verify.py outputs/triaged.json --target=db.aurumpay.example --write
    ./8-rescore.py outputs/verified.json context/asset_model.json --write
    ./9-prioritize.py outputs/rescored.json context/threat_context.json --write

Outputs land in `outputs/`: `normalized.json`, `correlated.json`, `triaged.json`,
`verified.json`, `rescored.json`, `priority.json`, `priority.csv`.

## What each script does

| script | role |
|---|---|
| `1-normalizer.py` | one schema, three adapters (Nikto XML/JSON, OpenVAS XML, Nessus .nessus), confidence tagging of noisy check classes |
| `4-correlate.py` | merge the same flaw across scanners on shared CVE or asset+service+flaw class, classify agreed/contested/unique, flag coverage gaps |
| `6-triage.py` | trusted / suspected_false_positive / needs_verification on contradiction, low confidence and single-source signals |
| `7-verify.py` | GET the resource a contested finding names, confirm or refute on the live answer |
| `8-rescore.py` | asset model to CVSS environmental metrics, both v3.1 and v4.0, base preserved alongside |
| `9-prioritize.py` | environmental + KEV + EPSS + business criticality to an action order, with the inversions versus base order made explicit |

`reference/` holds the provided schema, CVSS helper and format notes; `context/` the
asset model and threat data; `reports/` the three provided reports.

## Key results

- all three scanners agree on Log4Shell on the shop: `V-0032`
- coverage gap, Nessus alone: the internal API debug endpoint, `V-0010`
- false positive cleared: POODLE `V-0031`, cross-scanner contradiction
- first to fix: `V-0003`, CVE-2022-0778 on the payment database, base 6.5 to
  environmental 7.7, KEV-listed
- last: `V-0004`, MS15-034 on the decommissioned host, base 9.8 to environmental 3.4

## Scope

Parsing, analysis and SAFE live verification of contested findings are authorised by
the signed Rules of Engagement. No scanner is run or wrapped, nothing is exploited,
no data is modified.
