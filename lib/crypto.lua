--Require
local component = require("component")
local data = component.data
local modem = component.modem
local fs = require("filesystem")
local serialization = require("serialization")
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
  assert(key.type ~= "userdata", "KEY_NOT_VALID_SER")
  return {t = key.keyType(), d = hexer.toHex(key.serialize())}
end

function internal.deserializeKey(keyT) -- Reverse of previous function.
  assert(type(keyT) ~= "table" or keyT == nil, "KEY_NOT_VALID_DESER")
  return data.deserializeKey(hexer.fromHex(keyT.d), keyT.t)
end

local crypto = {}

function crypto.loadKeys(name)
  return internal.readFile(name)
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

function crypto.sendKey(key, name)
  assert(key["t"] ~= "ec-public", "Public Key expected.")

  local keyString = serialization.serialize(key)
  dns.start()
  local addr, reason = dns.lookup(name)
  if not addr then
    return false, "DNS_" .. reason
  end
  modem.send(addr, settings.port, "CRYPTO", "SEND_KEY", keyString)
end

function crypto.crypt(args)
  --=> {name, iv, text, decrypt}
  --<= false, error/ {encrypted text,iv}
  local keyTable, err = internal.readFile(args.name)
  assert(keyTable, err)

  if args.decrypt then
    return data.decrypt(args.text, hexer.fromHex(keyTable.aesKey), hexer.fromHex(args.iv))
  else
    local ivr = data.random(16)
    encString = data.encrypt(args.text, hexer.fromHex(keyTable.aesKey), ivr)
    return {cText = hexer.toHex(encString), iv = hexer.toHex(ivr)}
  end
end

function crypto.storePub(name, key)
  local userPub, err1 = internal.deserializeKey(key)
  assert(userPub, err1)

  local key_table, err2 = internal.readFile(name)
  if not key_table then
    return false, err2
  end
  key_table.userPub = userPub
  internal.writeFile(name, key_table, true)
end

function crypto.storePass(name, pw)
  local key_table, err = internal.readFile(name)
  if not key_table then
    return false, err
  end

  local pass = hexer.toHex(data.sha256(pw))
  key_table.pass = pass
  internal.writeFile(name, key_table, true)
end

function crypto.checkPass(name, pw)
  --print(name)
  local key_table, err = internal.readFile(name)
  if not key_table then
    return false, err
  end
  if (key_table.pass == hexer.toHex(data.sha256(pw))) then
    return true
  else
    return false, "INCORRECT_PW_OR_USERNAME"
  end
end

function crypto.checkBalance(name)
  local key_table, err = internal.readFile(name)
  if not key_table then
    return false, err
  end
  return key_table.bal
end

function crypto.changeBalance(name, amt)
  local key_table, err = internal.readFile(name)
  if not key_table then
    return false, err
  end
  if key_table.bal == nil then
    key_table.bal = 0
  end
  if amt < 0 then
    if (key_table.bal >= math.abs(amt)) then
      key_table.bal = key_table.bal + amt
      internal.writeFile(name, key_table, true)
      return true, key_table.bal
    else
      return false, "INSUFF_BALANCE"
    end
  elseif amt == 0 then
    return false, "ZERO_TRANSFER"
  else
    key_table.bal = key_table.bal + amt
    internal.writeFile(name, key_table, true)
    return true, key_table.bal
  end
end

return crypto
