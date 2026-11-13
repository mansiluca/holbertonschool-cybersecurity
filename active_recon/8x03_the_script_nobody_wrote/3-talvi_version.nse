local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Version detection for the bespoke Talvi management service on 9700. Speaks
enough of the custom line protocol to pull the product and version, prints them
and sets the port version so nmap names the service.
]]
author = "Luca Mansi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version", "safe"}

portrule = shortport.port_or_service(9700, "talvi-mgmt", {"tcp"})

local function fetch_version(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(4000)
  local ok = sock:connect(host, port)
  if not ok then
    return nil
  end
  local lines = {}
  local status, line = sock:receive_lines(1)
  if status and line then
    lines[#lines + 1] = line
  end
  sock:send("VERSION\r\n")
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
  sock:send("QUIT\r\n")
  sock:close()
  return lines
end

action = function(host, port)
  local lines = fetch_version(host, port)
  if not lines then
    return stdnse.format_output(false, "could not speak the Talvi protocol")
  end
  local product, version
  for _, ln in ipairs(lines) do
    product = product or ln:match("^PRODUCT%s+(.+)$")
    version = version or ln:match("^VERSION%s+(.+)$")
  end
  if not version then
    return stdnse.format_output(false, "no version line in the reply")
  end
  product = product or "Talvi Management Service"

  port.version = port.version or {}
  port.version.name = "talvi-mgmt"
  port.version.product = product
  port.version.version = version
  port.version.confidence = 85
  nmap.set_port_version(host, port)

  nmap.registry.talvi = nmap.registry.talvi or {}
  nmap.registry.talvi.product = product
  nmap.registry.talvi.version = version
  nmap.registry.talvi.port = port.number
  nmap.registry.talvi.host = host.ip

  return stdnse.format_output(true, string.format("%s %s", product, version))
end
