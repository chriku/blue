local lib = require "blue.tor.crypto.openssl"
local ffi = require "ffi"
return function(message, key)
  local ctx = ffi.gc(lib.HMAC_CTX_new(), lib.HMAC_CTX_free)
  assert(lib.HMAC_Init_ex(ctx, key, key:len(), lib.EVP_sha256(), nil) == 1)
  assert(lib.HMAC_Update(ctx, message, message:len()) == 1)
  local out = ffi.new("unsigned char[256]")
  local outlen = ffi.new("unsigned int[1]", 256)
  assert(lib.HMAC_Final(ctx, out, outlen) == 1)
  return ffi.string(out, outlen[0])
end
