local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local brute = require "brute"
local creds = require "creds"
local unpwdb = require "unpwdb"

description = [[
Credential auditing for the Talvi management protocol, implemented to the
brute library Driver contract: a Driver class with connect, login and
disconnect, where login returns a creds.Account on success and a brute.Error
on failure. Candidates are pulled through unpwdb and hits are stored in creds.
]]
author = "Luca Mansi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}

portrule = shortport.port_or_service(9700, "talvi-mgmt", {"tcp"})

local WORKSPACE = "/home/student/active_recon/8x03_the_script_nobody_wrote"

Driver = {
  new = function (self, host, port, options)
    local o = {
      host = host,
      port = port,
      options = options,
      attempts = 0,
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function (self)
    self.sock = nmap.new_socket()
    self.sock:set_timeout(5000)
    local ok, err = self.sock:connect(self.host, self.port)
    if not ok then
      return false, brute.Error:new("connect failed: " .. tostring(err))
    end
    local status = self.sock:receive_lines(1)
    if not status then
      self.sock:close()
      return false, brute.Error:new("no greeting from the management service")
    end
    return true
  end,

  login = function (self, username, password)
    self.sock:send("AUTH " .. username .. " " .. password .. "\r\n")
    local status, line = self.sock:receive_lines(1)
    if not status or not line then
      return false, brute.Error:new("no reply to AUTH")
    end
    line = line:gsub("%s+$", "")
    self.attempts = self.attempts + 1
    if line:match("^AUTH%-OK") then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end
    if line:match("^AUTH%-LOCKED") then
      local e = brute.Error:new("account locked")
      e:setAbort(true)
      return false, e
    end
    return false, brute.Error:new("Incorrect password")
  end,

  disconnect = function (self)
    if self.sock then
      self.sock:close()
      self.sock = nil
    end
  end,
}

action = function (host, port)
  local users_path = stdnse.get_script_args("userdb") or (WORKSPACE .. "/wordlists/task6-users.txt")
  local pass_path = stdnse.get_script_args("passdb") or (WORKSPACE .. "/wordlists/task6-passwords.txt")

  nmap.registry.args = nmap.registry.args or {}
  nmap.registry.args.userdb = nmap.registry.args.userdb or users_path
  nmap.registry.args.passdb = nmap.registry.args.passdb or pass_path

  local options = { timeout = 5000 }
  local engine = brute.Engine:new(Driver, host, port, options)
  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  engine.options.useraspass = false
  engine.options.emptypass = false
  engine.options.max_retries = 0
  engine.options.killstagnated = true
  engine.options.delay = 0

  local status, result = engine:start()
  if type(result) ~= "table" or not result["Accounts"] then
    return stdnse.format_output(false, "no valid credentials found")
  end

  -- every hit is already stored through creds; surface it and record it in the registry
  nmap.registry.creds = nmap.registry.creds or {}
  nmap.registry.talvi = nmap.registry.talvi or {}
  local hits = {}
  for _, line in ipairs(result["Accounts"]) do
    line = tostring(line)
    hits[#hits + 1] = line
    local user, password = line:match("^([^:]+):([^ ]+)")
    if user and password then
      nmap.registry.creds[user] = password
      nmap.registry.talvi.creds = user
      nmap.registry.talvi.creds_pair = string.format("%s:%s", user, password)
    end
  end
  nmap.registry.talvi.accounts = hits

  local out = stdnse.output_table()
  out["Accounts"] = hits
  return out
end
