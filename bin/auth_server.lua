local component = require("component")
local data = component.data
local modem = component.modem
local event = require("event")
local serialization = require("serialization")
local ttf = require("tableToFile")
local fs = require("filesystem")

local settingsLocation = "/auth/data/AUTH_SETTINGS.cfg"
local settings = ttf.load(settingsLocation)

local requests = {"AUTHENTICATE", "GETKEY", "SETKEY"}

local internal = {}
internal.eventHandler = {}

function internal.writeFile(name, fileData, override)
  if (type(fileData) == "Table") then
    fileData = serialization.serialize(fileData)
  end

  path = settings.SEC_PATH .. name .. ".key"
  if (fs.exists(path) and not override) then
    io.stderr:write("authServer: file <" .. name .. "> already exists.")
    return false, "FILE_EXISTS"
  end

  local file = assert(io.open(path, "wb"))
  file:write(fileData):close()
  return true
end

function internal.readFile(name)
  local path = settings.SEC_PATH .. name .. ".key"
  if not fs.exists(path) then
    io.stderr:write("authServer: file for name <" .. name .. "> found.")

    return false, "NO_RECORD"
  end

  local file = assert(io.open(path, "rb"))
  local fileData = file:read("*a")
  file:close()
  return fileData
end

function internal.serializeKey(key)
  assert(key.type == "userdata")
  local keyT = {t = key.keyType(), d = key.serialize()}
  local keyS = serialization.serialize(keyT)
  return keyS
end

function internal.deserializeKey(keyS)
  local keyT = serialization.unserialize(keyS)
  local key = data.deserialize(keyT.d, keyT.t)
  return key
end

function internal.eventHandler.tableEvent(rAddr, port, _, service, request, name, eData)
  local e = {
    requester = rAddr,
    port = port,
    service = service,
    request = request,
    name = name,
    data = eData or nil
  }
  return e
end

function internal.eventHandler.processEvent(type, _, ...) --type,to,from,port,dist,serv,req,name,data
  local e
  if (type == "modem_message") then
    e = internal.eventHandler.tableEvent(...)
  end
  if (e.service == "AUTH") then
    if (e.request == requests[1]) then --AUTHENTICATE
      io.stdout:write("Not Implemented")
    elseif (e.request == requests[2]) then --GETKEY
      local pub, priv = data.generateKeyPair()
      local sPub = internal.serializeKey(pub)
      local sPriv = internal.serializeKey(priv)
      internal.writeFile(e.name, sPriv)

      modem.send(e.requester, e.port, e.service, e.request, sPub)
    elseif (e.request == requests[3]) then --SETKEY
      local userPub = internal.deserializeKey(e.data)

      if not (userPub.type == "userdata") then
        io.stderr:write("Key deserialization failed.")
        modem.send(e.requester, e.port, e.service, e.request, false, "KEY_NOT_VALID")
        return false
      end

      local sPriv, err = internal.readFile(e.name)
      if not sPriv then
        io.stderr:write("authServer: reading of keyFile failed.")
        io.stderr:write("authServer: reason was: " .. err)
        modem.send(e.requester, e.port, e.service, e.request, false, "NO_RECORD")
        return false
      end

      local priv = internal.deserializeKey(sPriv)
      local aesKey = data.md5(data.ecdh(userPub, priv))
      internal.writeFile(e.name, {priv = internal.serializeKey(priv), aesKey = aesKey}, true)
      modem.send(e.requester, e.port, e.service, e.request, true)
      return true
    else
      io.stderr:write("Unknown Request")
    end
  end
end

function start()
  modem.open(settings.port)
  event.listen("modem_message", internal.eventHandler.processEvent)
end

function stop()
  event.ignore("modem_message", internal.eventHandler.processEvent)
  modem.close(settings.port)
end

--Shutup luacheck.
local debug = false
if debug then
  start()
  stop()
end
