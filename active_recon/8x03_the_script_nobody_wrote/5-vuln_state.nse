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

local FIRST_REQUEST = "GET /version HTTP/1.0\r\nHost: talvi.example\r\n\r\n"
local PROBE_REQUEST = "GET /admin HTTP/1.0\r\nHost: talvi.example\r\nConnection: close\r\n\r\n"

local function read_all(sock)
  local chunks = {}
  while true do
    local status, chunk = sock:receive_buf("", true)
    if not status or not chunk or chunk == "" then
      break
    end
    chunks[#chunks + 1] = chunk
  end
  return table.concat(chunks)
end

local function probe_gateway(host, port)
  local sock, response = comm.tryssl(host, port, FIRST_REQUEST, {})
  if not sock then
    return nil
  end
  local body = response or ""
  local version = body:match("Talvi Gateway%s+([%d%.]+)")

  -- second request on the same session: the behaviour probe
  local sent = sock:send(PROBE_REQUEST)
  local probe_body = sent and read_all(sock) or ""
  sock:close()
  return version, probe_body
end

action = function(host, port)
  local version, probe_body = probe_gateway(host, port)
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
  local probe_hit = probe_body:lower():match("admin panel") ~= nil
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
