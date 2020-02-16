local lib = require "blue.tor.crypto.openssl"
local ffi = require "ffi"

return function(algo)
  return function()
    local ctx = ffi.gc(lib.EVP_MD_CTX_new(), lib.EVP_MD_CTX_free)
    lib.EVP_DigestInit_ex(ctx, lib[algo](), nil)
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
end
