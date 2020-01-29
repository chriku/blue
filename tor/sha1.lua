local ffi = require "ffi"
ffi.cdef [[
typedef struct EVP_MD_CTX {} EVP_MD_CTX;
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
const EVP_MD *EVP_sha1(void);
]]
local lib = ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")
return function()
  local ctx = ffi.gc(lib.EVP_MD_CTX_new(),lib.EVP_MD_CTX_free)
  lib.EVP_DigestInit_ex(ctx,lib.EVP_sha1(),nil)
  return function(data)
    lib.EVP_DigestUpdate(ctx,data,data:len())
    local ctx2=ffi.gc(lib.EVP_MD_CTX_new(),lib.EVP_MD_CTX_free)
    lib.EVP_MD_CTX_copy_ex(ctx2,ctx)
    local out = ffi.new("unsigned char[256]")
    local outlen = ffi.new("unsigned int[1]", 256)
    lib.EVP_DigestFinal_ex(ctx2,out,outlen)
    return ffi.string(out, outlen[0])
  end
end

