local lib = require "blue.tor.openssl"
return function(data, size)
  local ctx = ffi.gc(lib.EVP_MD_CTX_new(), lib.EVP_MD_CTX_free)
  lib.EVP_DigestInit_ex(ctx, lib.EVP_shake256(), nil)
  lib.EVP_DigestUpdate(ctx, data, data:len())
  local out = ffi.new("unsigned char[?]", size)
  local outlen = ffi.new("unsigned int[1]", size)
  lib.EVP_DigestFinalXOF(ctx, out, size)
  return ffi.string(out, outlen[0])
end
