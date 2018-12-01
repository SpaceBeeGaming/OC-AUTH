-- From the "data card software" floppy; separeted into its own library
local hexer = {}

function hexer.toHex(cdata)
  return (cdata:gsub(
    ".",
    function(c)
      return string.format("%02X", string.byte(c))
    end
  ))
end

function hexer.fromHex(hex)
  return (hex:gsub(
    "..",
    function(cc)
      return string.char(tonumber(cc, 16))
    end
  ))
end

return hexer
