local ffi = require "ffi"
ffi.cdef [[
typedef struct ECP_PKEY_CTX {} ECP_PKEY_CTX;

]]
local lib = ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")

return function (key, salt, info)
end
