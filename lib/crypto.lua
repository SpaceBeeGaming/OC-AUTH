--Require
local component = require("component")
local data = component.data
local modem = component.modem
local fs = require("filesystem")
local serilization = require("serilization")
local dns = require("dns_client")

local ttf = require("tableToFile")
local hexer = require("hexer")
--endRequire

--Config
local settingsLocation = "/auth/data/AUTH_SETTINGS.cfg"
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

function internal.deserializeKey(keyT) -- Reverse of previous function.
  if (type(keyT) ~= "table" or keyT == nil) then
    return false, "KEY_NOT_VALID_DESER"
  end

  return data.deserializeKey(hexer.fromHex(keyT.d), keyT.t)
end

local crypto = {}

function crypto.loadKeys(args)
  --args: name
  return internal.readFile(args.name)
end

function crypto.generateKeys()
  local pub, priv = data.generateKeyPair()
  return {pub = internal.serializeKey(pub), priv = internal.serializeKey(priv)}
end

function crypto.generateAesKey(args)
  --args: name, keyTable, userPub
  args.key_table["aesKey"] =
    hexer.toHex(data.md5(data.ecdh(internal.deserializeKey(args.key_table["priv"]), args.userPub)))
  internal.writeFile(args.name, args.key_table, true)
  return args.key_table["aesKey"]
end

function crypto.sendKey(args)
  --args: key
  if (args.key["t"] ~= "ec-public") then
    return false, "Public Key expected."
  end

  local keyString = serilization.serialize(args.key)
  dns.start()
  local addr, reason = dns.lookup(args.name)
  if not addr then
    return false, "DNS_" .. reason
  end
  modem.send(addr, settings.port, "CRYPTO", "SEND_KEY", keyString)
end

function crypto.crypt(args)
  --=> {name, iv, text, decrypt}
  --<= false, error/ {encrypted text,iv}
  local keyTable, err = internal.readFile(args.name)
  if not keyTable then
    return false, err
  end

  if args.decrypt then
    return data.decrypt(args.text, hexer.fromHex(keyTable.aesKey), hexer.fromHex(args.iv))
  else
    local ivr = data.random(16)
    encString = data.encrypt(args.text, hexer.fromHex(keyTable.aesKey), ivr)
    return {cText = hexer.toHex(encString), iv = hexer.toHex(ivr)}
  end
end

function crypto.storePub(args)
  --args: name, key
  local userPub, err1 = internal.deserializeKey(args.key)
  if not (userPub) then
    return false, err1
  end

  local key_table, err2 = internal.readFile(args.name)
  if not key_table then
    return false, err2
  end
  key_table.userPub = userPub
  internal.writeFile(args.name, key_table, true)
end

return crypto
