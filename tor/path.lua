local dir = require "blue.tor.dir"
local ntor = require "blue.tor.ntor"
local struct = require "blue.struct"
local aes=require"blue.tor.aes"
local sha1=require"blue.sha1"
return function(circuit, first_node_info)
  local first_node = {router = dir.parse_to_router(first_node_info)}
  local path = {}
  local handshake_data, handshake_cb = ntor(first_node)
  circuit:send_cell("create2", handshake_data)
  do
    local cmd, data = circuit:read_cell()
    assert(cmd == "created2")
    handshake_cb(data)
  end
  function path:extend(node_info)
    local new_node = {router = dir.parse_to_router(node_info)}
    local ip1, ip2, ip3, ip4 = assert(new_node.router.address):match("^([0-9]+)%.([0-9]+)%.([0-9]+)%.([0-9]+)$")
    ip1 = assert(tonumber(ip1))
    ip2 = assert(tonumber(ip2))
    ip3 = assert(tonumber(ip3))
    ip4 = assert(tonumber(ip4))
    local handshake_data, handshake_cb = ntor(new_node)
    local extend_content = struct.pack(">B BB BBBB H", 1, 0, 6, ip1, ip2, ip3, ip4, assert(new_node.router.orport))..handshake_data
    local relay_content_hash=struct.pack(">BHHIH",14,0,0,0,extend_content:len())..extend_content
    relay_content_hash=relay_content_hash..string.rep(string.char(0),509-relay_content_hash:len())
    local digest=sha1.binary(first_node.digest_forward..relay_content_hash):sub(1,4)
    local relay_content=struct.pack(">BHHc4H",14,0,0,digest,extend_content:len())..extend_content
    relay_content=relay_content..string.rep(string.char(0),509-relay_content:len())
    circuit:send_cell("relay",aes.encrypt(first_node.key_forward,relay_content))
    --circuit:send_cell("relay",relay_content)
    local cmd,data=circuit:read_cell()
    print("EXTEND RESPONSE",cmd,({[0] = "NONE", "PROTOCOL", "INTERNAL", "REQUESTED", "HIBERNATING", "RESOURCELIMIT", "CONNECTFAILED", "OR_IDENTITY", "OR_CONN_CLOSED", "FINISHED", "TIMEOUT", "DESTROYED", "NOSUCHSERVICE"})[string.byte(data)])
  end
  return path
end
