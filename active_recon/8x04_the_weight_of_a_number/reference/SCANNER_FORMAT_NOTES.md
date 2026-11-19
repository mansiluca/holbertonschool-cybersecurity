# Scanner format notes (neutral)

Nikto (XML): `<niktoscan><scandetails><item osvdbid=.. method=..>` with
`<description>` and `<uri>`. No native CVSS or severity - infer severity and
confidence from the check class. Some OSVDB ids (generic directory-guess /
indexing) and header/cookie/ETag/method checks are noisy and false-positive
prone: tag them low-confidence.

OpenVAS / GVM (XML): `<report><results><result>` with `<host>`, `<port>`,
`<threat>`, `<severity>`, and an `<nvt>` carrying `<cvss_base>`, a `tags` string
containing `cvss_base_vector=...` and `qod=...`, and `<refs><ref type="cve">`.

Nessus (.nessus XML): `NessusClientData_v2 > Report > ReportHost > ReportItem`,
with HostProperties tags (host-ip, host-fqdn), a numeric `severity` (0-4),
`pluginID`, `pluginName`, `<cve>`, `<cvss3_vector>` or `<cvss4_vector>`,
`<cvss3_base_score>` and `<plugin_output>`.

Different scanners name one asset differently (hostname vs IP). The asset model
gives both - use it to recognise one asset across reports.
