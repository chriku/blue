local ffi = require "ffi"
local tor = ffi.load("tor/tor.so")
ffi.cdef [[
  void init_logging(int disable_startup_queue);
  int ed25519_public_blind(uint8_t *out,const uint8_t *inp,const uint8_t *param);
]]
tor.init_logging(0)

local key_blinding = {}
function key_blinding.blind_public_key(key, h)
  local out = ffi.new("char[32]")
  tor.ed25519_public_blind(out, ffi.new("char[32]", key), ffi.new("char[?]", h:len(), h))
  return ffi.string(out, 32)
end
return key_blinding
