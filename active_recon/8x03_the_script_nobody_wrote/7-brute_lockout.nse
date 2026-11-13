local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local brute = require "brute"
local creds = require "creds"
local unpwdb = require "unpwdb"

description = [[
Lockout-aware credential audit. The Driver reads the service lockout policy,
caps every account at threshold minus one attempt, throttles between attempts
and honours an AUTH-LOCKED reply instead of hammering the client's accounts.
]]
author = "Luca Mansi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}

portrule = shortport.port_or_service(9700, "talvi-mgmt", {"tcp"})

local WORKSPACE = "/home/student/active_recon/8x03_the_script_nobody_wrote"

local function lockout_policy(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(4000)
  if not sock:connect(host, port) then
    return nil
  end
  sock:receive_lines(1)
  sock:send("LOCKOUT\r\n")
  local threshold, window
  while true do
    local status, line = sock:receive_lines(1)
    if not status or not line then
      break
    end
    line = line:gsub("%s+$", "")
    threshold = threshold or tonumber(line:match("^THRESHOLD%s+(%d+)"))
    window = window or tonumber(line:match("^WINDOW%s+(%d+)"))
    if line == "BYE" then
      break
    end
  end
  sock:send("QUIT\r\n")
  sock:close()
  return threshold, window
end

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
  local threshold, window = lockout_policy(host, port)
  if not threshold then
    return stdnse.format_output(false, "could not read the lockout policy")
  end
  local budget = threshold - 1
  if budget < 1 then
    budget = 1
  end

  local users_path = stdnse.get_script_args("userdb") or (WORKSPACE .. "/wordlists/task7-users.txt")
  local pass_path = stdnse.get_script_args("passdb") or (WORKSPACE .. "/wordlists/task7-passwords.txt")

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
  local locked = false
  for username in usernames do
    local tries = 0
    for password in passwords do
      if tries >= budget then
        break
      end
      local ok, account = driver:login(username, password)
      tries = tries + 1
      if ok then
        found:add(account.username, account.password, account.state)
        hits[#hits + 1] = string.format("%s:%s - %s (no lockout triggered)",
          account.username, account.password, creds.StateMsg[account.state] or "Valid credentials")
        break
      end
      if type(account) == "table" and account.abort then
        locked = true
        break
      end
      if tries < budget then
        stdnse.sleep(1)
      end
    end
    passwords("reset")
    if #hits > 0 or locked then
      break
    end
  end
  driver:disconnect()

  if #hits == 0 then
    return stdnse.format_output(false, "no valid credentials found within the lockout budget")
  end

  local out = stdnse.output_table()
  out["Lockout policy"] = string.format("Lockout threshold detected at %d attempts, throttling", threshold)
  out["Window"] = string.format("%d seconds", window or 0)
  out["Accounts"] = hits
  return out
end
