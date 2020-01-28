local ffi = require "ffi"
ffi.cdef [[
typedef struct HMAC_CTX {} HMAC_CTX;
typedef struct EVP_MD {} EVP_MD;
HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,const EVP_MD *md, ENGINE *impl);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
const EVP_MD *EVP_sha256(void);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len);]]
local lib = ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")
return function(message, key)
  local ctx = ffi.gc(lib.HMAC_CTX_new(), lib.HMAC_CTX_free)
  assert(lib.HMAC_Init_ex(ctx, key, key:len(), lib.EVP_sha256(), nil) == 1)
  assert(lib.HMAC_Update(ctx, message, message:len()) == 1)
  local out = ffi.new("unsigned char[256]")
  local outlen = ffi.new("unsigned int[1]", 256)
  assert(lib.HMAC_Final(ctx, out, outlen) == 1)
  return ffi.string(out, outlen[0])
end

