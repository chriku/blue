local sha3 = require "blue.tor.sha3"
local struct = require "blue.struct"
return function(message, key)
  return sha3(struct.pack(">L", key:len()) .. key .. message)
end
