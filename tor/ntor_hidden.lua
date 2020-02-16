local struct = require "blue.struct"
local curve = require "blue.tor.crypto.curve"
local aes = require "blue.tor.crypto.aes_stream"
local random = require "blue.tor.crypto.random"
local struct = require "blue.struct"
local link_specifier = require "blue.tor.link_specifier"
local sha3 = require "blue.tor.crypto.sha3"
local hmac = require "blue.tor.crypto.hmac_sha3"
local shake3 = require "blue.tor.crypto.shake3"
local sha3_stream = require "blue.tor.crypto.sha3_stream"

local PROTOID = "tor-hs-ntor-curve25519-sha3-256-1"

return function(hs, creds, cookie, rendezvous)
  local data = string.rep(string.char(0), 20) .. struct.pack(">B H c32 B", 2, 32, hs.auth_key, 0)
  local B = hs.enc_key
  local X, x = curve.gen_key()
  local intro_secret_hs_input = curve.handshake(x, B) .. hs.auth_key .. X .. B .. PROTOID
  local info = PROTOID .. ":hs_key_expand" .. creds.subcredential
  local hs_keys = shake3(intro_secret_hs_input .. PROTOID .. ":hs_key_extract" .. info, 32 + 32)
  local S_KEY_LEN = 32
  local ENC_KEY = hs_keys:sub(1, S_KEY_LEN)
  local MAC_KEY = hs_keys:sub(S_KEY_LEN + 1)

  local plaintext = cookie .. struct.pack(">B", 0) .. struct.pack(">BH", 1, 32) .. rendezvous.ntor_onion_key .. link_specifier.generate_list(rendezvous)

  local encrypted_data = aes.encrypt(ENC_KEY)(plaintext)

  data = data .. X .. encrypted_data
  data = data .. random((246 - 32) - data:len())
  data = data .. sha3(struct.pack(">L", 32) .. MAC_KEY .. data)
  return data, function(Y, auth, new_node)
    local ID = hs.auth_key
    local PROTOID = "tor-hs-ntor-curve25519-sha3-256-1"
    local secret_input = curve.handshake(x, Y) .. curve.handshake(x, B) .. ID .. B .. X .. Y .. PROTOID
    local seed = hmac(PROTOID .. ":hs_key_extract", secret_input)
    local verify = hmac(PROTOID .. ":hs_verify", secret_input)
    local auth_input = verify .. ID .. B .. Y .. X .. PROTOID .. "Server"
    local auth_v = hmac(PROTOID .. ":hs_mac", auth_input)
    assert(auth_v == auth, "Invalid MAC")
    local long_key = shake3(seed .. "tor-hs-ntor-curve25519-sha3-256-1" .. ":hs_key_expand", 32 * 2 + 32 * 2)
    new_node.hash_forward = sha3_stream()
    new_node.hash_backward = sha3_stream()
    new_node.digest_forward = long_key:sub(1, 32)
    new_node.digest_backward = long_key:sub(33, 64)
    new_node.hash_forward(new_node.digest_forward)
    new_node.hash_backward(new_node.digest_backward)
    new_node.key_forward = long_key:sub(65, 96)
    new_node.key_backward = long_key:sub(97, 128)
    new_node.aes_forward = aes.encrypt(new_node.key_forward)
    new_node.aes_backward = aes.decrypt(new_node.key_backward)
  end
end
