local component = require("component")
local data = component.data
local modem = component.modem
local event = require("event")
local serialization = require("serialization")
local ttf = require("tableToFile")
local fs = require("filesystem")

local settingsLocation = "/auth/data/AUTH_SETTINGS.cfg"
local settings = ttf.load(settingsLocation)

local requests = {"AUTHENTICATE", "GETKEY", "SETKEY", "VERIFY"}

local internal = {}
internal.eventHandler = {}

function internal.toHex(cdata)
  return (cdata:gsub(
    ".",
    function(c)
      return string.format("%02X", string.byte(c))
    end
  ))
end

function internal.fromHex(hex, call)
  print(call)
  return (hex:gsub(
    "..",
    function(cc)
      return string.char(tonumber(cc, 16))
    end
  ))
end

function internal.writeFile(name, fileData, override)
  repeat
    fileData = serialization.serialize(fileData)
  until type(fileData) ~= "Table"

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
  local keyT = {t = key.keyType(), d = internal.toHex(key.serialize())}
  --local keyS = serialization.serialize(keyT)
  return keyT
end

function internal.deserialize(keyT)
  print("Key is: ", type(keyT), "and: ", keyT)
  print("assert condition: ", type(keyT) == "table" and keyT ~= nil)
  assert(type(keyT) == "table" and keyT ~= nil, "Key not string or empty")
  --local keyT = serialization.unserialize(keyS)
  --print(keyT, err)
  print(keyT.d, keyT.t)
  local key = data.deserializeKey(internal.fromHex(keyT.d, "1"), keyT.t)
  print(key.keyType())
  return key
end

function internal.eventHandler.tableEvent(rAddr, port, _, service, request, name, eData)
  local e = {
    requester = rAddr,
    port = port,
    service = service,
    request = request,
    name = name,
    data = eData or "data?"
  }
  return e
end

function internal.eventHandler.processEvent(type, _, ...) --type,to,from,port,dist,serv,req,name,data
  if (type == "modem_message") then
    local e = internal.eventHandler.tableEvent(...)
    if (e.service == "AUTH") then
      --print(e.request)
      if (e.request == requests[1]) then --AUTHENTICATE, not done
        io.stdout:write("Not Implemented")
      elseif (e.request == requests[2]) then --GETKEY, works
        local tPub
        if fs.exists("/auth/data/auth_keys/" .. e.name .. ".key") then
          --print(true)
          local tKey = serialization.unserialize(internal.readFile(e.name))
          if not tKey then
            modem.send(e.requester, e.port, e.service, e.request, false, "Key Reading failed.")
            return false
          end
          tPub = tKey.pub
        else
          local pub, priv = data.generateKeyPair()
          tPub = internal.serializeKey(pub)
          local tPriv = internal.serializeKey(priv)
          internal.writeFile(e.name, {priv = tPriv, pub = tPub})
        end

        modem.send(e.requester, e.port, e.service, e.request, serialization.serialize(tPub))
        return true
      elseif (e.request == requests[3]) then --SETKEY, works !!!
        print("SETKEY")
        --print(internal.toHex(serialization.unserialize(e.data).d), serialization.unserialize(e.data).t)
        local userPub = internal.deserialize(serialization.unserialize(e.data))

        if not (userPub.type == "userdata") then
          io.stderr:write("Key deserialization failed.")
          modem.send(e.requester, e.port, e.service, e.request, false, "KEY_NOT_VALID")
          return false
        end

        local tKeyS, err = internal.readFile(e.name)
        if not tKeyS then
          io.stderr:write("authServer: reading of keyFile failed.")
          io.stderr:write("authServer: reason was: " .. err)
          modem.send(e.requester, e.port, e.service, e.request, false, "NO_RECORD")
          return false
        end
        local tKey = serialization.unserialize(tKeyS)
        print(tKey.priv.d, tKey.priv.t)
        local priv = internal.deserialize(tKey["priv"])
        print(priv.type, priv.keyType())
        --print(internal.fromHex(priv, "2"))
        tKey.aesKey = internal.toHex(data.md5(data.ecdh(priv, userPub)))
        internal.writeFile(e.name, tKey, true)

        modem.send(e.requester, e.port, e.service, e.request, true)
        return true
      elseif (e.request == requests[4]) then --VERIFY, not tested
        local tKeyS, err = internal.readFile(e.name)
        if not tKeyS then
          io.stderr:write("authServer: reading of keyFile failed.")
          io.stderr:write("authServer: reason was: " .. err)
          modem.send(e.requester, e.port, e.service, e.request, false, "NO_RECORD")
          return false
        end
        local tKey = serialization.unserialize(tKeyS)
        print(tKey.aesKey)

        local tEnc = serialization.unserialize(e.data)
        print(tEnc.iv)
        local files = data.decrypt(tEnc.d, internal.fromHex(tKey.aesKey), internal.fromHex(tEnc.iv))
        local sha = data.sha256(files)
        internal.writeFile(e.name, tKey, true)
        modem.send(e.requester, e.port, e.service, e.request, sha)
      else
        io.stderr:write("Unknown Request")
      end
    end
  end
end

function start()
  print("Started!")
  modem.open(settings.port)
  event.listen("modem_message", internal.eventHandler.processEvent)
end

function stop()
  event.ignore("modem_message", internal.eventHandler.processEvent)
  modem.close(settings.port)
end

--Shutup luacheck.
local debug, debug2 = true, false
if debug then
  start()
end
if debug2 then
  stop()
end
