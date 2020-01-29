local ffi = require "ffi"
ffi.cdef [[
typedef struct EVP_CIPHER {} EVP_CIPHER;
typedef struct EVP_CIPHER_CTX {} EVP_CIPHER_CTX;
const EVP_CIPHER *EVP_aes_128_ctr(void);
 EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
 void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
 int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
 int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       int *outl, const unsigned char *in, int inl);
 int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
 int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
 int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       int *outl, const unsigned char *in, int inl);
 int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *x, int padding);

]]
local lib = ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")
local aes = {}
function aes.encrypt(key)
  assert(key)
  assert(key:len() == 16)
  local ctx = ffi.gc(lib.EVP_CIPHER_CTX_new(), lib.EVP_CIPHER_CTX_free)
  local iv = ffi.new("unsigned char[128]")
  for i = 0, 127 do
    iv[i] = 0
  end
  lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_128_ctr(), nil, key, iv)
  lib.EVP_CIPHER_CTX_set_padding(ctx,0)
  return function(data)
    local ret=""
    do
      local out = ffi.new("unsigned char[1024]")
      local outlen = ffi.new("int[1]", 1024)
      assert(lib.EVP_EncryptUpdate(ctx, out, outlen, data, data:len()) == 1)
      ret=ret.. ffi.string(out, outlen[0])
    end
    return ret
  end
end
function aes.decrypt(key)
  assert(key)
  assert(key:len() == 16)
  local ctx = ffi.gc(lib.EVP_CIPHER_CTX_new(), lib.EVP_CIPHER_CTX_free)
  local iv = ffi.new("unsigned char[128]")
  for i = 0, 127 do
    iv[i] = 0
  end
  lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_128_ctr(), nil, key, iv)
  lib.EVP_CIPHER_CTX_set_padding(ctx,0)
  return function(data)
    local ret=""
    do
      local out = ffi.new("unsigned char[1024]")
      local outlen = ffi.new("int[1]", 1024)
      assert(lib.EVP_DecryptUpdate(ctx, out, outlen, data, data:len()) == 1)
      ret=ret.. ffi.string(out, outlen[0])
    end
    return ret
  end
end
return aes
