local ffi = require "ffi"
ffi.cdef [[
/*typedef struct EVP_MD_CTX {} EVP_MD_CTX;
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);*/
const EVP_MD *EVP_shake256(void);
 int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md, size_t len);
]]
local lib = ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")
return function(data, size)
  local ctx = ffi.gc(lib.EVP_MD_CTX_new(), lib.EVP_MD_CTX_free)
  lib.EVP_DigestInit_ex(ctx, lib.EVP_shake256(), nil)
  lib.EVP_DigestUpdate(ctx, data, data:len())
  local out = ffi.new("unsigned char[?]", size)
  local outlen = ffi.new("unsigned int[1]", size)
  lib.EVP_DigestFinalXOF(ctx, out, size)
  return ffi.string(out, outlen[0])
end
