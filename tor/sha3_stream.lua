local ffi = require "ffi"
require "blue.tor.sha1"
require "blue.tor.sha3"
local lib = ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")
return function()
  local ctx = ffi.gc(lib.EVP_MD_CTX_new(), lib.EVP_MD_CTX_free)
  lib.EVP_DigestInit_ex(ctx, lib.EVP_sha3_256(), nil)
  return function(data)
    lib.EVP_DigestUpdate(ctx, data, data:len())
    local ctx2 = ffi.gc(lib.EVP_MD_CTX_new(), lib.EVP_MD_CTX_free)
    lib.EVP_MD_CTX_copy_ex(ctx2, ctx)
    local out = ffi.new("unsigned char[256]")
    local outlen = ffi.new("unsigned int[1]", 256)
    lib.EVP_DigestFinal_ex(ctx2, out, outlen)
    return ffi.string(out, outlen[0])
  end
end
