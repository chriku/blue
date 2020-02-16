local lib = require "blue.tor.openssl"
local ffi = require "ffi"
local aes = {}
function aes.encrypt(key_in, iv_in)
  assert(key_in)
  assert((key_in:len() == 16) or (key_in:len() == 32))
  local key = ffi.cast("uint8_t*", ffi.C.malloc(32))
  ffi.copy(key, key_in)
  local iv
  if iv_in then
    iv = ffi.cast("uint8_t*", ffi.C.malloc(16))
    ffi.copy(iv, iv_in)
  else
    iv = ffi.cast("uint8_t*", ffi.C.malloc(16))
    for i = 0, 15 do
      iv[i] = 0
    end
  end
  local ctx = ffi.gc(lib.EVP_CIPHER_CTX_new(), function(ctx)
    assert(lib.EVP_CIPHER_CTX_reset(ctx) == 1)
    lib.EVP_CIPHER_CTX_free(ctx)
    ffi.C.free(key)
    ffi.C.free(iv)
  end)
  local c = lib.EVP_aes_128_ctr()
  if (key_in:len() == 32) then
    c = lib.EVP_aes_256_ctr()
  end
  lib.EVP_EncryptInit_ex(ctx, c, nil, key, iv)
  lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
  return function(data)
    local ret = ""
    do
      local l = data:len() + 128
      local out = ffi.new("unsigned char[?]", l)
      local outlen = ffi.new("int[1]", l)
      assert(lib.EVP_EncryptUpdate(ctx, out, outlen, data, data:len()) == 1)
      ret = ret .. ffi.string(out, outlen[0])
    end
    return ret
  end
end
local gd = {}
function aes.decrypt(key_in, iv_in)
  assert(key_in)
  assert((key_in:len() == 16) or (key_in:len() == 32))
  local key = ffi.cast("uint8_t*", ffi.C.malloc(32))
  ffi.copy(key, key_in)
  local iv
  if iv_in then
    iv = ffi.cast("uint8_t*", ffi.C.malloc(16))
    ffi.copy(iv, iv_in)
  else
    iv = ffi.cast("uint8_t*", ffi.C.malloc(16))
    for i = 0, 15 do
      iv[i] = 0
    end
  end
  local ctx = ffi.gc(lib.EVP_CIPHER_CTX_new(), function(ctx)
    assert(lib.EVP_CIPHER_CTX_reset(ctx) == 1)
    lib.EVP_CIPHER_CTX_free(ctx)
    ffi.C.free(key)
    ffi.C.free(iv)
  end)
  local c = lib.EVP_aes_128_ctr()
  if (key_in:len() == 32) then
    c = lib.EVP_aes_256_ctr()
  end
  lib.EVP_DecryptInit_ex(ctx, c, nil, key, iv)
  lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
  return function(data)
    local ret = ""
    do
      local l = data:len() + 128
      local out = ffi.new("unsigned char[?]", l)
      local outlen = ffi.new("int[1]", l)
      assert(lib.EVP_DecryptUpdate(ctx, out, outlen, data, data:len()) == 1)
      ret = ret .. ffi.string(out, outlen[0])
    end
    return ret
  end
end
return aes
