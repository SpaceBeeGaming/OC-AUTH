--Require
local component = require("component")
local data = component.data
local modem = component.modem
local event = require("event")
local serialization = require("serialization")
local fs = require("filesystem")

local ttf = require("tableToFile")
local hexer = require("hexer")
--endRequire

--Config
local settingsLocation = "/auth/data/AUTH_SETTINGS.cfg"
local requests = {"AUTHENTICATE", "GETKEY", "SETKEY", "VERIFY"}
--endConfig

local settings = ttf.load(settingsLocation)

local internal = {}

function internal.writeFile(name, fileData, override) --Write key files.
  local path = settings.SEC_PATH .. name .. ".key"
  if (fs.exists(path) and not override) then
    return false, "FILE_EXISTS"
  end

  ttf.save(fileData, path)
  return true
end

function internal.readFile(name) --read key files.
  local path = settings.SEC_PATH .. name .. ".key"
  if not fs.exists(path) then
    return false, "NO_RECORD"
  end

  return ttf.load(path)
end

function internal.serializeKey(key) --Converts keys to hex format.
  if (key.type ~= "userdata") then
    return false, "KEY_NOT_VALID_SER"
  end

  return {t = key.keyType(), d = hexer.toHex(key.serialize())}
end

function internal.deserialize(keyT) -- Reverse of previous function.
  if (type(keyT) ~= "table" or keyT == nil) then
    return false, "KEY_NOT_VALID_DESER"
  end

  return data.deserializeKey(hexer.fromHex(keyT.d), keyT.t)
end

function internal.authenticate() --TODO
end

function internal.getKey(e) -- Generates or looksup public/private key pairs.
  -- Outputs the public key on success.
  local table_pub
  if fs.exists(settings.SEC_PATH .. e.name .. ".key") then
    local key_table, err = internal.readFile(e.name)
    if not key_table then
      return false, err
    end

    table_pub = key_table.pub
  else
    local pub, priv = data.generateKeyPair()
    table_pub = internal.serializeKey(pub)
    internal.writeFile(e.name, {priv = internal.serializeKey(priv), pub = table_pub})
  end

  return serialization.serialize(table_pub)
end

function internal.setKey(e) -- Stores the public key sent by user. Also generates the AES key.
  -- Returns the AES key on success.
  local userPub, err1 = internal.deserialize(serialization.unserialize(e.data))
  if not (userPub) then
    return false, err1
  end

  local key_table, err2 = internal.readFile(e.name)
  if not key_table then
    return false, err2
  end

  key_table.aesKey = hexer.toHex(data.md5(data.ecdh(internal.deserialize(key_table["priv"]), userPub)))
  internal.writeFile(e.name, key_table, true)
  return true
end

function internal.verify(e) -- Verifies that both parties have the same AES key.
  -- Decrypts the data sent by user with local AES key, returns sha256 hash of data sent by user os success.
  local key_table, err = internal.readFile(e.name)
  if not key_table then
    modem.send(e.requester, e.port, e.service, e.request, false, err)
    return false, err
  end

  local encString = serialization.unserialize(e.data)
  return data.sha256(data.decrypt(encString.d, hexer.fromHex(key_table.aesKey), hexer.fromHex(encString.iv)))
end

function internal.main(e)
  local result, reason
  if (e.request == requests[1]) then --AUTHENTICATE, not done
    result, reason = internal.authenticate()
  elseif (e.request == requests[2]) then --GETKEY
    result, reason = internal.getKey(e)
  elseif (e.request == requests[3]) then --SETKEY
    result, reason = internal.setKey(e)
  elseif (e.request == requests[4]) then --VERIFY
    result, reason = internal.verify(e)
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
  if (e.service == "AUTH") then
    internal.main(e)
  end
end

function start()
  print("Started!")
  modem.open(settings.port)
  event.listen("modem_message", eventHandler.processEvent)
end

function stop()
  print("Stopped!")
  event.ignore("modem_message", internal.eventHandler.processEvent)
  modem.close(settings.port)
end

--Shutup luacheck.
local debug = false
if debug then
  start()
  stop()
end
