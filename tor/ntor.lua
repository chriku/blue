local struct = require "blue.struct"
local curve = require "blue.tor.curve"
local rsa = require "blue.tor.rsa"
local hmac = require "blue.tor.hmac"
local aes = require "blue.tor.aes"
local rfc5869 = require "blue.tor.rfc5869"
local base64 = require "blue.base64"
local tor_sha1=require"blue.tor.sha1"
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
    local seed = hmac(secret_input, PROTOID .. ":key_extract")
    local verify = hmac(secret_input, PROTOID .. ":verify")
    local auth_input = verify .. ID .. B .. Y .. X .. PROTOID .. "Server"
    local auth_v = hmac(auth_input, PROTOID .. ":mac")
    assert(auth_v == auth, "Invalid hash")
    local long_key = rfc5869(secret_input, PROTOID .. ":key_extract", PROTOID .. ":key_expand")
    node.hash_forward=tor_sha1()
    node.hash_backward=tor_sha1()
    node.digest_forward = long_key:sub(1, 20)
    node.digest_backward = long_key:sub(21, 40)
    node.hash_forward(node.digest_forward)
    node.hash_backward(node.digest_backward)
    node.key_forward = long_key:sub(41, 56)
    node.key_backward = long_key:sub(57, 72)
    node.aes_forward = aes.encrypt(node.key_forward)
    node.aes_backward = aes.decrypt(node.key_backward)
    KH = long_key:sub(73, 72 + 32)
  end
end

