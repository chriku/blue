local struct = require "blue.struct"
local link_specifier = {}
function link_specifier.generate_list(router)
  local ids = {}
  if router.fingerprint then
    table.insert(ids, struct.pack(">BBc20", 2, 20, router.fingerprint))
  end
  if router.address then
    local ip1, ip2, ip3, ip4 = assert(router.address):match("^([0-9]+)%.([0-9]+)%.([0-9]+)%.([0-9]+)$")
    ip1 = assert(tonumber(ip1))
    ip2 = assert(tonumber(ip2))
    ip3 = assert(tonumber(ip3))
    ip4 = assert(tonumber(ip4))
    table.insert(ids, struct.pack("BB BBBB H", 0, 6, ip1, ip2, ip3, ip4, assert(router.orport)))
  end
  if router.raw_address then
    table.insert(ids, struct.pack("BB c6", 0, 6, router.raw_address))
  end
  return struct.pack(">B ", #ids) .. table.concat(ids)
end
return link_specifier
