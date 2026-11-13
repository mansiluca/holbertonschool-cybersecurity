local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Discovery probe for the bespoke Talvi management protocol. Connects, reads the
greeting the service sends unprompted and reports it.
]]
author = "Luca Mansi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9700, "talvi-mgmt", {"tcp"})

action = function(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local ok, err = sock:connect(host, port)
  if not ok then
    return stdnse.format_output(false, "connect failed: " .. tostring(err))
  end
  local status, banner = sock:receive_lines(1)
  sock:close()
  if not status or not banner then
    return stdnse.format_output(false, "no greeting from service")
  end
  banner = banner:gsub("%s+$", "")

  -- parse the identifying detail out of the greeting before reporting it
  local detail = banner
  local _, _, name, state = banner:find("^(%S+)%s+(.+)$")
  if name then
    detail = name .. " " .. state
  end

  local out = stdnse.output_table()
  out["service banner"] = detail
  return out
end
