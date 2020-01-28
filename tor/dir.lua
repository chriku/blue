-- 128.31.0.34:9131
require "blue.util"
local dir = {}
local base64 = require "blue.base64"
local hex = require "blue.hex"
local function read_dir(str)
  local lines = {}
  local items = {}
  local in_block = nil
  local block_data
  local last_item = {}
  for line in str:gmatch("[^\n]*") do
    local object_begin = line:match("^%-%-%-%-%-BEGIN ([A-Za-z0-9%- ]+)%-%-%-%-%-$")
    local object_end = line:match("^%-%-%-%-%-END ([A-Za-z0-9%- ]+)%-%-%-%-%-$")
    local keyword_single = line:match("^([A-Za-z0-9%-]+)$")
    local keyword_multi, args = line:match("^([A-Za-z0-9%-]+)[ \t]+(.-)$")
    if object_begin and not in_block then
      in_block = object_begin
      block_data = ""
    elseif object_end then
      assert(in_block == object_end)
      in_block = nil
      if last_item then
        last_item.block_data = {key = object_end, data = block_data}
      end
    elseif keyword_single and not in_block then
      assert(keyword_single ~= "-----BEGIN")
      local key = keyword_single
      items[key] = items[key] or {}
      local item = {}
      last_item = item
      table.insert(items[key], item)
    elseif keyword_multi and not in_block then
      assert(keyword_multi ~= "-----BEGIN")
      local key = keyword_multi
      items[key] = items[key] or {}
      local item = {data = args}
      last_item = item
      table.insert(items[key], item)
    elseif in_block then
      block_data = block_data .. line
    end
  end
  assert(not in_block)
  -- items.to_sign=str:match("^.*\nrouter%-signature\n")
  return items
end
local function parse_router(items)
  local router = {}
  local readers = {}
  table.insert(readers, function()
    assert(items["router"])
    assert(#items["router"] == 1)
    assert(items["router"][1].data)
    local nickname, address, orport, _, dir_port = items["router"][1].data:match("^([^ ]*) ([0-9]*%.[0-9]*%.[0-9]*%.[0-9]*) ([0-9]*) ([0-9]*) ([0-9]*)")
    router.nickname = assert(nickname)
    router.address = assert(address)
    router.orport = assert(tonumber(orport))
    router.dir_port = assert(tonumber(dir_port))
  end)
  table.insert(readers, function()
    if items["identity-ed25519"] then
      assert(#items["identity-ed25519"] == 1)
      assert(items["identity-ed25519"][1].block_data)
      assert(items["identity-ed25519"][1].block_data.key == "ED25519 CERT")
      router.identity_ed25519 = base64.decode(items["identity-ed25519"][1].block_data.data)
    end
  end)
  table.insert(readers, function()
    if items["master-key-ed25519"] then
      assert(#items["master-key-ed25519"] == 1)
      assert(items["master-key-ed25519"][1].data)
      router.master_key_ed25519 = base64.decode(items["master-key-ed25519"][1].data)
    end
  end)
  table.insert(readers, function()
    if items["ntor-onion-key"] then
      assert(#items["ntor-onion-key"] == 1)
      assert(items["ntor-onion-key"][1].data)
      router.ntor_onion_key = base64.decode(items["ntor-onion-key"][1].data)
    end
  end)
  table.insert(readers, function()
    if items["fingerprint"] then
      assert(#items["fingerprint"] == 1)
      router.fingerprint = hex.decode(assert(items["fingerprint"][1].data))
    end
  end)
  for _, reader in ipairs(readers) do
    reader()
  end
  return router
end
function dir.parse_to_router(doc)
  return parse_router(read_dir(doc))
end
return dir
--[==[decode(parse_router(read_dir[[router moria1 128.31.0.34 9101 0 9131
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQABsDLAcNTxZiZh+xxKU3qBhH2VLOuY2iD/N/BkostwpoDKYH3AQAgBADKnR/C
2nhpr9UzJkkbPy83sqbfNh63VgFnCpkSTULAclhv2P6nRVPvh34XZ1S5+a99vTFJ
LkfrnonMMypKtZ3ct1qQGf2W1PsfXzQIkFUGs1xcLD+NwSIMBMRRNAzEMwg=
-----END ED25519 CERT-----
master-key-ed25519 yp0fwtp4aa/VMyZJGz8vN7Km3zYet1YBZwqZEk1CwHI
platform Tor 0.4.3.0-alpha-dev on Linux
proto Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2 Padding=2 FlowCtrl=1
published 2020-01-28 05:04:47
fingerprint 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31
uptime 64871
bandwidth 512000 104857600 3074048
extra-info-digest 838C67764EDD14D4962EFFD1189CCC9544CCF7C4 NobmwjuWxaIJKrKdl4CBeacj3lD8SOG8GBWAv24laFc
caches-extra-info
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALUl/2ZuvWmautGOih1XRx9/4+4zqwWc531CTKouINAuEZZM4kPgVjX7
JRbluomDqa27DLQbvryNdTJIjjNU+AsmxFY/U6Dav1jF9PwcHsJcbCuSapBng4xq
/nBb24X/+SH0BMCemQfdVbmW8f11rfzUoxwt9UVeLRfBhvH2CZ1jAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALtJ9uD7cD7iHjqNA3AgsX9prES5QN+yFQyr2uOkxzhvunnaf6SNhzWW
bkfylnMrRm/qCz/czcjZO6N6EKHcXmypehvP566B7gAQ9vDsb+l7VZVWgXvzNc2s
tl3P7qpC08rgyJh1GqmtQTCesIDqkEyWxwToympCt09ZQRq+fIttAgMBAAE=
-----END RSA PUBLIC KEY-----
onion-key-crosscert
-----BEGIN CROSSCERT-----
RI3kuh/OpgIGWuvOXUukDyzjrT922yYyvebSsyouVP5OhqBPpTvByk/ZxJK9dbeX
OZdDGuURTdKcpGR1xyK6chgt8qiCc6zXRpEfcSEzJLSLNKrQEVdQkYCpZ2v7dZHY
qkJBTukei8WxbYJopFiwDDgQi3iJyiTANXq6smx5HtA=
-----END CROSSCERT-----
ntor-onion-key-crosscert 0
-----BEGIN ED25519 CERT-----
AQoABrU+AcqdH8LaeGmv1TMmSRs/Lzeypt82HrdWAWcKmRJNQsByALgiuBiA4cjP
rxMmwbvyOgAeX1XyoJ+WTvkfD6dbSLjOSC7eRwN+y1zI0XtytfMy4jvd4XUFMZ4D
DKymJAa7fA0=
-----END ED25519 CERT-----
hidden-service-dir
contact 1024D/EB5A896A28988BF5 arma mit edu
ntor-onion-key A9OYkoVFLF4G/Jwd+5gJ6hyaaw+/8aR47K6X8Sojo2E=
reject *:*
tunnelled-dir-server
router-sig-ed25519 H2JwGRJggIuNaKu0m/jpcPqkuthaFRdoEsjpSRFFzjDeG589sg17+jHzZ2aR41hAme0cZQra/xMRB2U/ADBQBg
router-signature
-----BEGIN SIGNATURE-----
GX5BLBfReaYPdkLR/ObmDqVLDnFxolTKWCDizD8LuG4gn6GPTHmUuzh7LAIQk6MJ
wsgqKmgwlfaftwwRWiy6RFnXP1xLg116595qWxY8h/Z5NZPYZH5hAujjKX1bw7Ry
T89tRvM9Kid58bqVUIeRlBZ3qyz9Ylu4wKlooCH6Ltc=
-----END SIGNATURE-----

]]))]==]
