local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local http = require "http"

description = [[
Honest state reporting for the backport gateway. The version string matches a
published advisory, so the finding is a suspicion and is reported as
LIKELY_VULN. The behavioural probe is then run: a backported build fails it,
and the gateway is cleared rather than accused. VULN is only ever assigned on
behavioural confirmation, EXPLOIT is never written.
]]
author = "Luca Mansi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(8443, "https", {"tcp"})

local ADVISORY_VERSION = "4.2.0"

local function fetch(host, port, path)
  local resp = http.get(host, port, path, {scheme = "https", no_cache = true})
  if not resp or not resp.body then
    return nil
  end
  return resp.body
end

local function gateway_version(host, port)
  local body = fetch(host, port, "/version")
  if not body then
    return nil
  end
  return body:match("Talvi Gateway%s+([%d%.]+)")
end

local function behavioral_probe(host, port)
  local body = fetch(host, port, "/admin")
  if not body then
    return false
  end
  body = body:lower()
  return body:match("admin panel") ~= nil or body:match("unauthorised%-admin") ~= nil
end

action = function(host, port)
  local vuln = {
    title = "Version matches published advisory",
    state = vulns.STATE.NOT_VULN,
    description = [[The gateway version string matches the advisory range for
the Talvi Gateway administrative interface flaw.]],
    references = {"TALVI-ADV-2023-02"},
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local version = gateway_version(host, port)
  nmap.registry.talvi = nmap.registry.talvi or {}
  nmap.registry.talvi.gateway_version = version

  if not version then
    return stdnse.format_output(false, "could not read the gateway version")
  end
  if version ~= ADVISORY_VERSION then
    return stdnse.format_output(false, string.format("gateway %s outside the advisory range", version))
  end

  if behavioral_probe(host, port) then
    vuln.state = vulns.STATE.VULN
    vuln.description = string.format([[Version Talvi Gateway %s matches the
advisory and the behavioural probe confirmed the flaw. State: VULNERABLE
(confirmed)]], version)
    report:add_vulns(vuln)
    return report:make_output()
  end

  vuln.state = vulns.STATE.LIKELY_VULN
  vuln.description = string.format([[Version Talvi Gateway %s matches the
published advisory, but the behavioural probe was negative: the gateway is
patched by backport and must not be reported as VULN. State: LIKELY VULNERABLE
Version matched but behavioral probe negative (backport suspected)]], version)
  report:add_vulns(vuln)
  return report:make_output()
end
