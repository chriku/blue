local dir = require "blue.tor.dir"
local ntor = require "blue.tor.ntor"
local struct = require "blue.struct"
local aes=require"blue.tor.aes"
local sha1=require"blue.sha1"
return function(circuit, first_node_info)
  local first_node = {router = dir.parse_to_router(first_node_info),prev_data=""}
  local path = {}
  local nodes={first_node}
  do
    local handshake_data, handshake_cb = ntor(first_node)
    circuit:send_cell("create2", handshake_data)
    local cmd, data = circuit:read_cell()
    assert(cmd == "created2")
    handshake_cb(data)
  end
  local function send_to_node(idx,cmd,stream_id,data,early)
    local node=assert(nodes[idx])
    local relay_content_hash=struct.pack(">BHHIH",cmd,0,stream_id,0,data:len())..data
    while relay_content_hash:len()<509 do
      relay_content_hash=relay_content_hash..string.char(math.random(0,255))
    end
print("PREV",idx,node.prev_data:len())
    local digest=sha1.binary(node.digest_forward..node.prev_data..relay_content_hash):sub(1,4)
    relay_content=relay_content_hash:sub(1,5)..digest..relay_content_hash:sub(10)
    node.prev_data=node.prev_data..relay_content_hash
    for i=idx,1,-1 do
      relay_content=nodes[i].aes_forward(relay_content)
    end
    if early then
      circuit:send_cell("relay_early",relay_content)
    else
      circuit:send_cell("relay",relay_content)
    end
  end
  local function read_relay_cell(cmd,data)
    assert(cmd=="relay")
    for i=1,10 do
      data=nodes[i].aes_backward(data)
      local cmd,recognized,stream_id,digest,length=struct.unpack(">BHHIH",data)
      if recognized==0 then
        data=data:sub(12,12-1+length)
        return cmd,data
      end
    end
    error("Invalid packet")
  end
  function path:extend(node_info)
    math.randomseed(os.time()*math.random())
    local new_node = {router = dir.parse_to_router(node_info),prev_data=""}
    local ip1, ip2, ip3, ip4 = assert(new_node.router.address):match("^([0-9]+)%.([0-9]+)%.([0-9]+)%.([0-9]+)$")
    ip1 = assert(tonumber(ip1))
    ip2 = assert(tonumber(ip2))
    ip3 = assert(tonumber(ip3))
    ip4 = assert(tonumber(ip4))
    local handshake_data, handshake_cb = ntor(new_node)
    local extend_content = struct.pack(">B BB BBBB H", 2, 0, 6, ip1, ip2, ip3, ip4, assert(new_node.router.orport))..struct.pack(">BBc20",2,20,new_node.router.fingerprint)..handshake_data
    send_to_node(#nodes,14,0,extend_content,true)
    local cmd,hdata=read_relay_cell(circuit:read_cell())
print("CMD",cmd,string.byte(hdata))
    assert(cmd==15)
    handshake_cb(hdata)
    table.insert(nodes,new_node)
  end
  function path:test()
    send_to_node(#nodes,1,1,struct.pack(">sI","google.de:80\0",0))
    local cmd,hdata=read_relay_cell(circuit:read_cell())
    assert(cmd==4)
    send_to_node(#nodes,2,1,"GET / HTTP/1.1\r\nHost: google.de\r\n\r\n")
while true do
    local cmd,hdata=read_relay_cell(circuit:read_cell())
    if cmd==2 then
print("READ",hdata)
end
end
  end
  return path
end
