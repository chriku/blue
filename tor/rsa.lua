local sha1 = require "blue.sha1"
local lib = require "blue.tor.openssl"
local rsa = {}
ffi.metatype("struct X509", {
  __index = {
    verify = function(self, string)
      local pubkey = lib.X509_get_pubkey(self)
      return pubkey:verify(string)
    end,
    digest = function(self, string)
      local pubkey = lib.X509_get_pubkey(self)
      return pubkey:digest(string)
    end
  },
  __gc = lib.X509_free
})
ffi.metatype("struct EVP_PKEY", {
  __index = {
    verify = function(self, string)
      local ctx = ffi.gc(lib.EVP_PKEY_CTX_new(self, nil), lib.EVP_PKEY_CTX_free)
      assert(lib.EVP_PKEY_verify_recover_init(ctx) == 1)
      local out = ffi.new("unsigned char[?]", 65536)
      local outlen = ffi.new("size_t[1]", 65536)
      assert(lib.EVP_PKEY_verify_recover(ctx, out, outlen, ffi.cast("const unsigned char *", string), string:len()) == 1)
      return ffi.string(out, outlen[0])
    end,
    digest = function(self)
      local out = ffi.new("unsigned char[?]", 65536)
      local optr = ffi.new("unsigned char*[1]", out)
      local outlen = ffi.new("size_t[1]", 65536)

      local key = lib.EVP_PKEY_get1_RSA(self)
      assert(lib.i2d_RSAPublicKey(key, optr) > 0)
      local str = ffi.string(out, optr[0] - out)
      return sha1.binary(str)
    end
  },
  __gc = lib.EVP_PKEY_free
})
function rsa.load_cert(cert)
  local data = ffi.new("unsigned char*[1]", ffi.cast("unsigned char*", cert))
  local ret = lib.d2i_X509(nil, data, cert:len())
  return ret
end
return rsa
