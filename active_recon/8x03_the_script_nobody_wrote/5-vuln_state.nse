local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local comm = require "comm"

description = [[
Honest state reporting for the backport gateway. The version string matches a
published advisory, so the version alone is never enough: the script probes the
behaviour first and only then assigns a state. A backported build fails the
probe, so the finding is downgraded to LIKELY_VULN instead of being accused.
]]
author = "Luca Mansi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(8443, "https", {"tcp"})

local ADVISORY_VERSION = "4.2.0"

local function fetch_version(host, port)
  local status, response = comm.tryssl(host, port,
    "GET /version HTTP/1.0\r\nHost: talvi.example\r\nConnection: close\r\n\r\n", {})
  if not status or not response then
    return nil
  end
  return response:match("Talvi Gateway%s+([%d%.]+)")
end

local function behavioral_probe(host, port)
  local status, response = comm.tryssl(host, port,
    "GET /admin HTTP/1.0\r\nHost: talvi.example\r\nConnection: close\r\n\r\n", {})
  if not status or not response then
    return false
  end
  return response:lower():match("admin panel") ~= nil
end

action = function(host, port)
  local version = fetch_version(host, port)
  if not version then
    return stdnse.format_output(false, "could not read the gateway version")
  end
  nmap.registry.talvi = nmap.registry.talvi or {}
  nmap.registry.talvi.gateway_version = version

  if version ~= ADVISORY_VERSION then
    return stdnse.format_output(false, string.format("gateway %s outside the advisory range", version))
  end

  local vuln = {
    title = "Version matches published advisory",
    references = {"TALVI-ADV-2023-02"},
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- behaviour is probed before any state is assigned
  local probe_hit = behavioral_probe(host, port)
  if probe_hit then
    vuln.state = vulns.STATE.VULN
    vuln.description = string.format([[Version Talvi Gateway %s matches the
advisory and the behavioural probe confirmed the flaw. State: VULNERABLE
(confirmed)]], version)
  else
    -- the negative probe clears the accusation: downgrade, do not accuse
    vuln.state = vulns.STATE.LIKELY_VULN
    vuln.description = string.format([[Version Talvi Gateway %s matches the
published advisory, but the behavioural probe was negative: the gateway is
patched by backport and must not be reported as VULN. State: LIKELY VULNERABLE
Version matched but behavioral probe negative (backport suspected)]], version)
  end
  report:add_vulns(vuln)
  return report:make_output()
end
