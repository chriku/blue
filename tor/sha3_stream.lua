local ffi = require "ffi"
ffi.cdef [[
const EVP_MD *EVP_sha3_256(void);
]]
return require "blue.tor.evp_stream"("EVP_sha3_256")
