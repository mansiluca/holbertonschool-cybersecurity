local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Reads the entries the suite left in the Nmap registry and surfaces the finding
that only appears when the scripts run together as one workflow: the confirmed
command interface plus a valid credential on the fingerprinted service is a
full management access path.
]]
author = "Luca Mansi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

postrule = function ()
  return nmap.registry.talvi ~= nil
end

action = function ()
  local state = nmap.registry.talvi
  if not state or not state.version then
    return nil
  end
  if not state.vuln_confirmed or not state.creds then
    return stdnse.format_output(false, "suite incomplete: run the version, vulnerability and credential scripts together")
  end
  return stdnse.format_output(true, string.format(
    "Talvi-MGMT %s on %s: confirmed command interface + valid %s creds = full management access path",
    state.version, tostring(state.port), state.creds))
end
