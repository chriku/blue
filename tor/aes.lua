local ffi=require"ffi"
ffi.cdef[[
typedef struct EVP_CIPHER {} EVP_CIPHER;
typedef struct EVP_CIPHER_CTX {} EVP_CIPHER_CTX;
const EVP_CIPHER *EVP_aes_128_cbc(void);
 EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
 void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
 int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
 int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       int *outl, const unsigned char *in, int inl);
 int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
]]
local lib=ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")
local aes={}
function aes.new(key)
assert(key)
assert(key:len()==16)
  local ctx=ffi.gc(lib.EVP_CIPHER_CTX_new(),lib.EVP_CIPHER_CTX_free)
  local iv=ffi.new("unsigned char[128]")
  for i=0,127 do iv[i]=0 end
  lib.EVP_EncryptInit_ex(ctx,lib.EVP_aes_128_cbc(),nil,key,iv)
  local stream={}
  function stream.encrypt(data)
    local out=ffi.new("unsigned char[1024]")
    local outlen=ffi.new("int[1]",1024)
    assert(lib.EVP_EncryptUpdate(ctx,out,outlen,data,data:len())==1)
    return ffi.string(out,outlen[0])
  end
  function stream.close()
print("CLOSE 1")
    local out=ffi.new("unsigned char[1024]")
    local outlen=ffi.new("int[1]",1024)
    assert(lib.EVP_EncryptFinal_ex(ctx,out,outlen)==1)
print("CLOSE 2")
    return ffi.string(out,outlen[0])
  end
  return stream
end
return aes
