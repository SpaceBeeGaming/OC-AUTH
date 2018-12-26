local component = require("component")
local data = component.data
local modem = component.modem
local event = require("event")
local serialization = require("serialization")

local ttf = require("tableToFile")
local crypto = require("crypto")
local hexer = require("hexer")
--Config
local settingsLocation = "/auth/data/AUTH_SETTINGS.cfg"
local requests = {"TRANSFER", "CHAECKBAL", "LOGOUT"}
--endConfig

local settings = ttf.load(settingsLocation)

local internal = {}

function internal.login(name, password)
  --print(name)
  local ident, err = crypto.checkPass(name, password)
  if not ident then
    return false, err
  else
    return true
  end
end

function internal.transfer(name, eData)
  --{d=aes(seriaslize({targ=xxx,amt=000}),iv}
  --eData = serialization.unserialize(eData)
  ttf.save(eData, "/home/eData.lua")
  --print(eData.d)
  local auth_keys = crypto.loadKeys(name)
  ttf.save(auth_keys, "/home/authkeys.lua")
  local details = data.decrypt(hexer.fromHex(eData.d), hexer.fromHex(auth_keys.aesKey), hexer.fromHex(eData.iv))
  details = serialization.unserialize(details)
  print(details.re, details.amt)
  local success, reas = crypto.changeBalance(name, -details.amt)
  if (success) then
    crypto.changeBalance(details.re, details.amt)
    return true, reas
  else
    return false, reas
  end
end

function internal.main(e)
  local result, reason
  if (e.request == requests[1]) then
    e.data = serialization.unserialize(e.data)
    --print(e.data["pl"])
    local authed, err = internal.login(e.name, e.data["pw"])
    if (authed) then
      result, reason = internal.transfer(e.name, e.data["pl"])
    else
      result, reason = false, err
    end
  else
    result, reason = false, "UNKNOWN_REQUEST"
  end
  modem.send(e.requester, e.port, e.service, e.request, result, reason)
end

local eventHandler = {}

function eventHandler.tableEvent(rAddr, port, _, service, request, name, eData) -- packs the event arguments.
  return {
    requester = rAddr,
    port = port,
    service = service,
    request = request,
    name = name,
    data = eData
  }
end

function eventHandler.processEvent(_, _, ...) --_type,_to,...(from,port,dist,serv,req,name,data)
  local e = eventHandler.tableEvent(...)
  if (e.service == "BANK") then
    internal.main(e)
  end
end

function start()
  modem.open(settings.port)
  --event.listen("modem_message", eventHandler.processEvent)
  print("Started!")
  while true do
    eventHandler.processEvent(event.pull("modem_message"))
  end
end

function stop()
  event.ignore("modem_message", eventHandler.processEvent)
  modem.close(settings.port)
end

--Shutup luacheck.
local debug = true
if (debug) then
  start()
--stop()
end
