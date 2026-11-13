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

  local status, usernames = unpwdb.usernames()
  if not status then
    return stdnse.format_output(false, "username list unusable: " .. tostring(users_path))
  end
  local passwords
  status, passwords = unpwdb.passwords()
  if not status then
    return stdnse.format_output(false, "password list unusable: " .. tostring(pass_path))
  end

  local driver = Driver:new(host, port, {})
  local connected, err = driver:connect()
  if not connected then
    return stdnse.format_output(false, tostring(err))
  end

  local found = creds.Credentials:new(SCRIPT_NAME, host, port)
  local hits = {}
  for username in usernames do
    for password in passwords do
      local ok, account = driver:login(username, password)
      if ok then
        found:add(account.username, account.password, account.state)
        hits[#hits + 1] = string.format("%s:%s - %s", account.username, account.password,
          creds.StateMsg[account.state] or "Valid credentials")
        break
      end
      if type(account) == "table" and account.abort then
        break
      end
    end
    passwords("reset")
    if #hits > 0 then
      break
    end
  end
  driver:disconnect()

  if #hits == 0 then
    return stdnse.format_output(false, "no valid credentials found")
  end

  nmap.registry.talvi = nmap.registry.talvi or {}
  nmap.registry.talvi.creds = hits[1]:match("^([^:]+)")
  nmap.registry.talvi.creds_pair = hits[1]:match("^([^ ]+)")
  nmap.registry.talvi.accounts = hits

  local out = stdnse.output_table()
  out["Accounts"] = hits
  return out
end
