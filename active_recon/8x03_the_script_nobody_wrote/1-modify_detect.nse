local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Modified HTTP header probe. Derived from the built-in http-headers script, but
the action surfaces the management console build tag instead of the full header
set. The rule is unchanged in spirit: only fire on the web console port.
]]
author = "Luca Mansi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(8080, "http", {"tcp"})

action = function(host, port)
  local response = http.get(host, port, "/")
  if not response or not response.status then
    return nil
  end
  local tag = response.header["x-talvi-build"]
  if not tag and response.body then
    tag = response.body:match('name="talvi%-build" content="([^"]+)"')
  end
  if not tag then
    return stdnse.format_output(false, "management console build tag: not disclosed")
  end
  stdnse.debug(1, "management console build tag: %s", tag)
  return stdnse.format_output(true, "management console build tag: " .. tag)
end
