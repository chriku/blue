local struct=require"blue.struct"
local ed25519 = {}
function ed25519.parse_cert(str)
  local version, type, exp, cert_key_type, certified_key, n_extensions = struct.unpack(">BBIBc32B", str)
  assert(version == 1, "Invalid Version")
  assert(cert_key_type == 1, "Invalid Type")
  str = str:sub(41)
  for i = 1, n_extensions do
    local len, type, flags = struct.unpack(">HBB", str)
    str = str:sub(5)
    str = str:sub(len + 1)
  end
  local signature = str
  return certified_key
end
return ed25519
