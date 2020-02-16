local ffi = require "ffi"
ffi.cdef [[
int crypto_scalarmult_ed25519(unsigned char *q, const unsigned char *n,
                              const unsigned char *p);
int crypto_scalarmult_ed25519_noclamp(unsigned char *q, const unsigned char *n,
                                      const unsigned char *p);
]]
local lib = ffi.load("/usr/lib/x86_64-linux-gnu/libsodium.so.23")
return function(inp, param)
  local out = ffi.new("unsigned char[32]")
  assert(lib.crypto_scalarmult_ed25519(out, inp, param) == 0)
  return ffi.string(out, 32)
end
--[==[

local ffi=require"ffi"
ffi.cdef[[
typedef struct BIGNUM {} BIGNUM;
typedef struct BN_CTX {} BN_CTX;
BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
void BN_free(BIGNUM *a);
int BN_mod_mul(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
                       BN_CTX *ctx);
BIGNUM *BN_new(void);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
        BN_CTX *BN_CTX_new(void);


        void BN_CTX_free(BN_CTX *c);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_hex2bn(BIGNUM **a, const char *str);
]]
local lib=ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")
return function(b,a)
local bn_a=ffi.gc(lib.BN_lebin2bn(a,a:len(),nil),lib.BN_free)
local bn_b=ffi.gc(lib.BN_lebin2bn(b,b:len(),nil),lib.BN_free)
local ret=ffi.gc(lib.BN_new(),lib.BN_free)
local bn_m=ffi.new("BIGNUM*[1]")
--gc(lib.BN_new(),lib.BN_free)
lib.BN_hex2bn(bn_m,"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
bn_m=ffi.gc(bn_m[0],lib.BN_free)
local ctx=ffi.gc(lib.BN_CTX_new(),lib.BN_CTX_free)
assert(lib.BN_mod_mul(ret,bn_a,bn_b,bn_m,ctx)==1)
local to=ffi.new("unsigned char[32]")
local len=lib.BN_bn2lebinpad(ret,to,32)
return ffi.string(to,32)
end
]==]
