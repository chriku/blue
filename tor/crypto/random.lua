local lib = require "blue.tor.crypto.openssl"
local ffi = require "ffi"
return function(len)
  if len > 0 then
    local out = ffi.new("unsigned char[?]", len)
    lib.RAND_bytes(out, len)
    return ffi.string(out, len)
  else
    return ""
  end
end
