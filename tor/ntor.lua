local struct = require "blue.struct"
local curve = require "blue.tor.curve"
local rsa = require "blue.tor.rsa"
local hmac = require "blue.tor.hmac"
local rfc5869=require"blue.tor.rfc5869"
local base64 = require "blue.base64"
local HANDSHAKE_TYPE_NTOR = 2
return function(node)
  local X, x = curve.gen_key()
  local B = assert(node.router.ntor_onion_key)
  local ID = assert(node.router.fingerprint)
  local ret = struct.pack(">HHc20c32c32", HANDSHAKE_TYPE_NTOR, ID:len() + B:len() + X:len(), ID, B, X)
  return ret, function(hdata)
    hdata = hdata:sub(3) -- Remove HDATA Len
    local Y = hdata:sub(1, 32)
    local auth = hdata:sub(33):sub(1, 32)
    local PROTOID = "ntor-curve25519-sha256-1"
    local secret_input = curve.handshake(x, Y) .. curve.handshake(x, B) .. ID .. B .. X .. Y .. PROTOID
print(require"blue.hex".encode(rfc5869(

require"blue.hex".decode("2C 57 3B E3 D7 FF 67 1C 43 E5 EB E1 E2 88 E3 11 52 70 35 08 BF A1 E9 49 F0 41 86 5B BF 52 DC 04 6D 7F F4 1A C3 A5 20 16 67 CF 1D 2D F9 8A 76 B7 4C 43 B8 0C 1C 34 CB B0 3C 75 A3 0A F2 EE 94 20 A9 F5 13 5A E1 8C 7E 25 C7 C7 91 17 CD 8C 76 19 BF EB 85 ED 4D 59 9F B1 A3 FC 4F 19 6D 67 9D 07 F5 82 9A 48 7E F7 A0 BF D3 88 B5 DA 86 A1 CE 6E 3F 90 66 7D 86 C6 56 86 7B 54 9C 79 4D 26 E4 AE 27 66 C6 5E D5 2E D5 2F 81 1E BD 6A 65 07 0C F6 E3 E1 28 53 BB 08 8F 7F 98 3A 51 AF 08 26 2F F8 69 12 39 B3 A8 DD E8 56 16 AF 55 C4 89 8F 82 A9 59 04 90 4C 6E 74 6F 72 2D 63 75 72 76 65 32 35 35 31 39 2D 73 68 61 32 35 36 2D 31")

, PROTOID .. ":key_extract", PROTOID .. ":key_expand")))
    local seed = hmac(secret_input, PROTOID .. ":key_extract")
    local verify = hmac(secret_input, PROTOID .. ":verify")
    local auth_input = verify .. ID .. B .. Y .. X .. PROTOID .. "Server"
    local auth_v = hmac(auth_input, PROTOID .. ":mac")
    assert(auth_v == auth, "Invalid hash")
    local long_key = rfc5869(seed, PROTOID .. ":key_extract", PROTOID .. ":key_expand")
    node.digest_forward = long_key:sub(1, 20)
    node.digest_backward = long_key:sub(21, 40)
    node.key_forward = long_key:sub(41, 56)
    node.key_backward = long_key:sub(57, 72)
    KH = long_key:sub(73, 72 + 32)
  end
end

