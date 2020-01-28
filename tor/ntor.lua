local struct = require "blue.struct"
local curve = require "blue.tor.curve"
local rsa = require "blue.tor.rsa"
local hmac = require "blue.tor.hmac"
local function create_ntor()
  local dig = rsa.load_cert(certs[2]):digest()
  local X, x = curve.gen_key()
  local B = require"base64".decode("A9OYkoVFLF4G/Jwd+5gJ6hyaaw+/8aR47K6X8Sojo2E=") -- TODO!!!
  local ID = dig:sub(1, 20)
  local ret = struct.pack(">c20c32c32", dig:sub(1, 20), B, X)
  return ret, function(hdata)
    local Y = hdata:sub(1, 32)
    local auth = hdata:sub(33):sub(1, 32)
    local PROTOID = "ntor-curve25519-sha256-1"
    local secret_input = curve.handshake(x, Y) .. curve.handshake(x, B) .. ID .. B .. X .. Y .. PROTOID
    local seed = hmac(secret_input, PROTOID .. ":key_extract")
    local verify = hmac(secret_input, PROTOID .. ":verify")
    local auth_input = verify .. ID .. B .. Y .. X .. PROTOID .. "Server"
    local auth_v = hmac(auth_input, PROTOID .. ":mac")
    assert(auth_v == auth, "Invalid hash")
    local long_key = rfc5869(secret_input, PROTOID .. ":key_extract", PROTOID .. ":key_expand")
    local Df = long_key:sub(1, 20)
    local Db = long_key:sub(21, 40)
    local Kf = long_key:sub(41, 56)
    local Kb = long_key:sub(57, 72)
    local KH = long_key:sub(73, 72 + 32)
    key_forward = Kf
  end
end

