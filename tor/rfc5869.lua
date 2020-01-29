local ffi = require "ffi"
ffi.cdef [[
//typedef struct EVP_PKEY_CTX {} EVP_PKEY_CTX;
//typedef struct EVP_MD {} EVP_MD;
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                              int cmd, int p1, void *p2);
const EVP_MD *EVP_sha256(void);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
]]
local lib = ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")

return function(key, salt, info)
  -- key,salt,info=key,salt,info
  -- key,info,salt=key,salt,info
  local ctx = ffi.gc(lib.EVP_PKEY_CTX_new_id(1036, nil), lib.EVP_PKEY_CTX_free)
  lib.EVP_PKEY_derive_init(ctx)
  lib.EVP_PKEY_CTX_ctrl(ctx, -1, bit.lshift(1, 10), 0x1003, 0, ffi.cast("void*", lib.EVP_sha256()))
  lib.EVP_PKEY_CTX_ctrl(ctx, -1, bit.lshift(1, 10), 0x1004, salt:len(), ffi.cast("void*", salt))
  lib.EVP_PKEY_CTX_ctrl(ctx, -1, bit.lshift(1, 10), 0x1006, info:len(), ffi.cast("void*", info))
  lib.EVP_PKEY_CTX_ctrl(ctx, -1, bit.lshift(1, 10), 0x1005, key:len(), ffi.cast("void*", key))
  local out = ffi.new("unsigned char[256]")
  local outlen = ffi.new("size_t[1]", 256)
  lib.EVP_PKEY_derive(ctx, out, outlen)
  return ffi.string(out, outlen[0])
end
