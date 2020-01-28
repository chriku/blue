local ffi = require "ffi"
local sha1 = require "blue.sha1"
ffi.cdef [[
typedef struct X509 {} X509;
typedef struct EVP_PKEY {} EVP_PKEY;
typedef struct EVP_PKEY_CTX {} EVP_PKEY_CTX;
typedef struct ENGINE {} ENGINE;
typedef struct RSA {} RSA;

int i2d_RSAPublicKey(RSA *a, unsigned char **pp);
RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
X509 *d2i_X509(X509 **a, unsigned char **ppin, long length);
void X509_free(X509 *a);
EVP_PKEY *X509_get_pubkey(X509 *x);
void EVP_PKEY_free(EVP_PKEY *key);
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx,unsigned char *rout, size_t *routlen,const unsigned char *sig, size_t siglen);
int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub,size_t *len);]]
local lib = ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")
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
