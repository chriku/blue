local dir = require "blue.tor.dir"
local ntor = require "blue.tor.ntor"
local struct = require "blue.struct"
local aes = require "blue.tor.aes"
local tor_sha1 = require "blue.tor.sha1"
local scheduler = require "blue.scheduler"
return function(circuit, first_node_info)
  local control
  local first_node = {router = dir.parse_to_router(first_node_info)}
  local path = {}
  local nodes = {first_node}
  do
    local handshake_data, handshake_cb = ntor(first_node)
    circuit:send_cell("create2", handshake_data)
    local cmd, data = circuit:read_cell()
    assert(cmd == "created2")
    handshake_cb(data)
  end
  local function send_to_node(idx, cmd, stream_id, data, early)
    local node = assert(nodes[idx])
    local relay_content_hash = struct.pack(">BHHIH", cmd, 0, stream_id, 0, data:len()) .. data
    while relay_content_hash:len() < 509 do
      relay_content_hash = relay_content_hash .. string.char(math.random(0, 255))
    end
    local digest = node.hash_forward(relay_content_hash):sub(1, 4)
    relay_content = relay_content_hash:sub(1, 5) .. digest .. relay_content_hash:sub(10)
    for i = idx, 1, -1 do
      relay_content = nodes[i].aes_forward(relay_content)
    end
    if early then
      circuit:send_cell("relay_early", relay_content)
    else
      circuit:send_cell("relay", relay_content)
    end
  end

  local cnt = 1000
  local function read_relay_cell(cmd, data)
    assert(cmd == "relay")
    for i = 1, 10 do
      data = nodes[i].aes_backward(data)
      local cmd, recognized, stream_id, digest, length = struct.unpack(">BHHc4H", data)
      if recognized == 0 then
        local node = nodes[i]
        relay_content_hash = data:sub(1, 5) .. "\0\0\0\0" .. data:sub(10)
        assert(digest == node.hash_backward(relay_content_hash):sub(1, 4), "Inv data")
        data = data:sub(12, 12 - 1 + length)
        cnt = cnt - 1
        if cnt < 900 then
          control:send(5, struct.pack(">BH", 0, 0))
          cnt = cnt + 100
        end
        return stream_id, cmd, data
      end
    end
    error("Invalid packet")
  end
  function path:extend(node_info)
    math.randomseed(os.time() * math.random())
    local new_node = {router = dir.parse_to_router(node_info)}
    local ip1, ip2, ip3, ip4 = assert(new_node.router.address):match("^([0-9]+)%.([0-9]+)%.([0-9]+)%.([0-9]+)$")
    ip1 = assert(tonumber(ip1))
    ip2 = assert(tonumber(ip2))
    ip3 = assert(tonumber(ip3))
    ip4 = assert(tonumber(ip4))
    local handshake_data, handshake_cb = ntor(new_node)
    local extend_content = struct.pack(">B BB BBBB H", 2, 0, 6, ip1, ip2, ip3, ip4, assert(new_node.router.orport)) .. struct.pack(">BBc20", 2, 20, new_node.router.fingerprint) .. handshake_data
    send_to_node(#nodes, 14, 0, extend_content, true)
    local sid, cmd, hdata = read_relay_cell(circuit:read_cell())
    assert(cmd == 15)
    handshake_cb(hdata)
    table.insert(nodes, new_node)
  end
  local sub_buffer = {}
  local receive_running = false
  local function start_receiver()
    assert(not receive_running)
    receive_running = true
    scheduler.addthread(function()
      while true do
        local stream_id, cmd, data = read_relay_cell(circuit:read_cell())
        if sub_buffer[stream_id] then
          table.insert(sub_buffer[stream_id], {cmd = cmd, data = data})
        else
          print("Relay for unknown stream id", stream_id, cmd)
        end
      end
    end)
  end
  local function register_circuit(id)
    id = id or math.random(1, 65535)
    while sub_buffer[id] do
      id = (id + 1) % 65536
      if id == 0 then
        id = 1
      end
    end
    local sub_buf = {}
    sub_buffer[id] = sub_buf
    local sub_circuit = {}
    function sub_circuit:send(cmd, data)
      send_to_node(#nodes, cmd, id, data)
    end
    function sub_circuit:close()
      sub_buffer[id] = nil
    end
    function sub_circuit:read(cmd, data)
      while #sub_buf < 1 do
        scheduler.sleep(0.01) -- TODO
      end
      local item = table.remove(sub_buf, 1)
      return item.cmd, item.data
    end
    return sub_circuit
  end
  control = register_circuit(0)
  scheduler.addthread(function()
    while true do
      local c, d = control:read()
      print("CONTROL", c, string.byte(d))
    end
  end)
  function path:provider()
    start_receiver()
    local provider = {}
    local function do_buildup(circuit)
      local cmd, data = circuit:read()
      if cmd ~= 4 then
        print("ERROR", string.byte(data))
        return nil, "tor error"
      end
      function socket:send(data)
        while data:len() > 450 do
          circuit:send(2, data:sub(1, 450))
          data = data:sub(451)
        end
        circuit:send(2, data)
        return data
      end
      function socket:close(data)
        circuit:send(3, string.char(6))
        circuit:close()
        return data
      end
      local cnt = 490 -- 500
      function socket:receive(data)
        local cmd, data = circuit:read()
        cnt = cnt - 1
        if cnt < 450 then
          circuit:send(5, struct.pack(">BH", 0, 0))
          cnt = cnt + 50
        end
        if cmd == 2 then
          return data
        elseif cmd == 3 then
          return nil, "closed"
        else
          print("Unknown Relay CMD", cmd)
          return ""
        end
      end
      return require "blue.socket_wrapper"(socket)
    end
    function provider.connect(host, port)
      local socket = {}
      local circuit = register_circuit()
      local addr = host .. ":" .. port
      circuit:send(1, struct.pack(">sI", addr .. "\0", 0))
      return do_buildup(circuit)
    end
    function provider.connect_dir()
      local socket = {}
      local circuit = register_circuit()
      circuit:send(13, "")
      return do_buildup(circuit)
    end
    --[[
    assert(cmd == 4)
    while true do
      local cmd, hdata = read_relay_cell(circuit:read_cell())
      if cmd == 2 then
        print("READ", hdata)
      end
    end]]
    return provider
  end
  return path
end
