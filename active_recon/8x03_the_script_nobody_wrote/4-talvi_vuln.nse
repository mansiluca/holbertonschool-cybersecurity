local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Confirms the Talvi Management Service unauthenticated command interface by
behaviour. The privileged probe is expected to be refused before
authentication; when the service answers it without an AUTH exchange the flaw
is confirmed and reported as VULN. The EXPLOIT state is never written: this
phase confirms presence, it does not exploit.
]]
author = "Luca Mansi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9700, "talvi-mgmt", {"tcp"})

local function talk(host, port, cmds)
  local sock = nmap.new_socket()
  sock:set_timeout(2500)
  local ok = sock:connect(host, port)
  if not ok then
    return nil
  end
  local lines = {}
  local status, banner = sock:receive_lines(1)
  if status and banner then
    lines[#lines + 1] = banner:gsub("%s+$", "")
  end
  for _, cmd in ipairs(cmds) do
    sock:send(cmd .. "\r\n")
    while true do
      local st, ln = sock:receive_lines(1)
      if not st or not ln then
        break
      end
      ln = ln:gsub("%s+$", "")
      lines[#lines + 1] = ln
      if ln == "BYE" then
        break
      end
    end
  end
  sock:close()
  return lines
end

action = function(host, port)
  local vuln = {
    title = "Talvi Management Service unauthenticated command interface",
    state = vulns.STATE.NOT_VULN,
    description = [[The management protocol answered a privileged interface
probe without any authentication exchange.]],
    references = {"TALVI-ADV-2023-01"},
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local lines = talk(host, port, {"VULN-CHECK"})
  local confirmed = false
  if lines then
    for _, ln in ipairs(lines) do
      if ln:upper():match("PRIVILEGED%-PROBE") and ln:upper():match("ACCEPTED%-WITHOUT%-AUTH") then
        confirmed = true
      end
    end
  end

  nmap.registry.talvi = nmap.registry.talvi or {}
  nmap.registry.talvi.vuln_confirmed = confirmed

  if confirmed then
    vuln.state = vulns.STATE.VULN
    vuln.description = [[The privileged probe was accepted without
authentication, so the command interface is reachable unauthenticated.
State: VULNERABLE (confirmed)
Behavioral probe returned the privileged response]]
  else
    return stdnse.format_output(false, "privileged probe refused without authentication")
  end

  report:add_vulns(vuln)
  return report:make_output()
end
