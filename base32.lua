local basexx = require "basexx"
local base32 = {}
function base32.decode(data)
  return basexx.from_base32(data)
end
function base32.encode(data)
  return basexx.to_base32(data)
end
return base32
