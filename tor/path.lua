local dir = require "blue.tor.dir"
local ntor = require "blue.tor.ntor"
local hmac = require "blue.tor.hmac2"
local struct = require "blue.struct"
local aes = require "blue.tor.aes"
local tor_sha1 = require "blue.tor.sha1"
local scheduler = require "blue.scheduler"
local curve = require "blue.tor.curve"
local sha3 = require "blue.tor.sha3"

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
    if type(data) ~= "string" then
      error("Invalid data", 2)
    end
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
    if cmd ~= "relay" then
      error("Invalid reply for relay: " .. cmd)
    end
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
  local function gen_link_spec_list(router)
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
  function path:extend(node_info)
    math.randomseed(os.time() * math.random())
    local new_node = {router = type(node_info) == "string" and dir.parse_to_router(node_info) or node_info}
    decode(new_node)
    local handshake_data, handshake_cb = ntor(new_node)
    local extend_content = gen_link_spec_list(new_node.router) .. handshake_data
    send_to_node(#nodes, 14, 0, extend_content, true)
    local sid, cmd, hdata = read_relay_cell(circuit:read_cell())
    assert(cmd == 15)
    handshake_cb(hdata)
    table.insert(nodes, new_node)
  end
  function path:rendezvous(cookie)
    send_to_node(#nodes, 33, 0, cookie, false)
    local sid, cmd, hdata = read_relay_cell(circuit:read_cell())
    assert(cmd == 39)
  end
  function path:rendezvous2(i1d)
    local x, B, X = i1d.x, i1d.B, i1d.X

    local ID = i1d.auth_key
    local sid, cmd, hdata = read_relay_cell(circuit:read_cell())
    assert(cmd == 37)
    local Y = hdata:sub(1, 32)
    local auth = hdata:sub(33):sub(1, 32)
    local PROTOID = "tor-hs-ntor-curve25519-sha3-256-1"
    local secret_input = curve.handshake(x, Y) .. curve.handshake(x, B) .. ID .. B .. X .. Y .. PROTOID
    local seed = hmac(PROTOID .. ":hs_key_extract", secret_input)
    local verify = hmac(PROTOID .. ":hs_verify", secret_input)
    local auth_input = verify .. ID .. B .. Y .. X .. PROTOID .. "Server"
    local auth_v = hmac(PROTOID .. ":hs_mac", auth_input)
    assert(auth_v == auth, "Invalid MAC")
    local long_key = require "blue.tor.shake3"(seed .. "tor-hs-ntor-curve25519-sha3-256-1" .. ":hs_key_expand", 32 * 2 + 32 * 2)
    print("KEYS", require"blue.hex".encode(long_key))
    local new_node = {}
    new_node.hash_forward = require "blue.tor.sha3_stream"()
    new_node.hash_backward = require "blue.tor.sha3_stream"()
    new_node.digest_forward = long_key:sub(1, 32)
    new_node.digest_backward = long_key:sub(33, 64)
    new_node.hash_forward(new_node.digest_forward)
    new_node.hash_backward(new_node.digest_backward)
    new_node.key_forward = long_key:sub(65, 96)
    new_node.key_backward = long_key:sub(97, 128)
    new_node.aes_forward = aes.encrypt(new_node.key_forward)
    new_node.aes_backward = aes.decrypt(new_node.key_backward)
    table.insert(nodes, new_node)
  end
  function path:introduce1(hs, creds, rendezvous, cookie)
    math.randomseed(os.time() * math.random())
    local data = string.rep(string.char(0), 20) .. struct.pack(">B H c32 B", 2, 32, hs.auth_key, 0)
    local PROTOID = "tor-hs-ntor-curve25519-sha3-256-1"
    local B = hs.enc_key
    local X, x = curve.gen_key()
    local intro_secret_hs_input = curve.handshake(x, B) .. hs.auth_key .. X .. B .. PROTOID
    local info = PROTOID .. ":hs_key_expand" .. creds.subcredential
    local hs_keys = require "blue.tor.shake3"(intro_secret_hs_input .. PROTOID .. ":hs_key_extract" .. info, 32 + 32)
    local S_KEY_LEN = 32
    local ENC_KEY = hs_keys:sub(1, S_KEY_LEN)
    local MAC_KEY = hs_keys:sub(S_KEY_LEN + 1)

    local plaintext = cookie .. struct.pack(">B", 0) .. struct.pack(">BH", 1, 32) .. rendezvous.ntor_onion_key .. gen_link_spec_list(rendezvous)
    print("DECRYPTED " .. require"blue.hex".encode(plaintext))

    local encrypted_data = aes.encrypt(ENC_KEY)(plaintext)

    data = data .. X .. encrypted_data
    while data:len() < (246 - 32) do
      data = data .. string.char(math.random(0, 255))
    end
    data = data .. sha3(struct.pack(">L", 32) .. MAC_KEY .. data)

    print("DATA LEN", data:len())

    send_to_node(#nodes, 34, 0, data, false)
    local sid, cmd, hdata = read_relay_cell(circuit:read_cell())
    assert(cmd == 40)
    assert(hdata == "\0\0\0", "Error creating circuit")
    return {x = x, X = X, B = B, auth_key = hs.auth_key}
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
  function path:sendme()
    control:send(5, struct.pack(">BH", 0, 0))
  end
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
      local socket = {}
      local cmd, data = circuit:read()
      if cmd ~= 4 then
        if cmd==3 then
          if data:byte()==6 then
            return nil,"closed"
          end
        end
        print("ERROR", cmd,string.byte(data))
        return nil, "tor error"
      end
      function socket:sendme()
        circuit:send(5, struct.pack(">BH", 0, 0))
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
