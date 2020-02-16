local tor = {}
local PAYLOAD_LEN = 509
local PK_PAD_LEN = 42
local PK_ENC_LEN = 128
local HASH_LEN = 20
local ID_LENGTH = 20
local ssl = require "blue.ssl"
local struct = require "blue.struct"
local curve = require "blue.tor.curve"
local sha1 = require "blue.sha1"
local rsa = require "blue.tor.rsa"
local hmac = require "blue.tor.hmac"
local aes = require "blue.tor.aes"
local ed25519 = require "blue.tor.ed25519"
local util = require "blue.util"
local scheduler = require "blue.scheduler"
local create_path = require "blue.tor.path"
local matrix = require "blue.matrix.init"
local http_client = require "blue.http_client"
local base32 = require "blue.base32"
local dir = require "blue.tor.dir"
local sha3 = require "blue.tor.sha3"
local tor_cmds = {}
do
  local function add_cmd(id, name)
    local cmd = {id = id, name = name}
    tor_cmds[id] = cmd
    tor_cmds[name] = cmd
  end
  add_cmd(0, "padding")
  add_cmd(1, "create")
  add_cmd(2, "created")
  add_cmd(3, "relay")
  add_cmd(4, "destroy")
  add_cmd(5, "create_fast")
  add_cmd(6, "created_fast")
  add_cmd(8, "netinfo")
  add_cmd(9, "relay_early")
  add_cmd(10, "create2")
  add_cmd(11, "created2")
  add_cmd(12, "padding_negotiate")
  add_cmd(7, "versions")
  add_cmd(128, "vpadding")
  add_cmd(129, "certs")
  add_cmd(130, "auth_challenge")
  add_cmd(131, "authenticate")
  add_cmd(132, "authorize")
end
function tor.create(args)
  assert(args.first_relay)
  assert(args.first_relay.ip)
  assert(args.first_relay.port)
  assert(args.first_relay.port)
  local socket_provider = ssl.create(args.socket_provider)
  print("CONN TO", args.first_relay.ip, args.first_relay.port)
  local conn = socket_provider.connect(args.first_relay.ip, args.first_relay.port)

  local socket_mutex = util.mutex()
  local recv_buf = ""
  local circ_id_len = "H"

  local circuits = {}
  local function register_circuit(id)
    local circuit = {}
    local buffer = {}
    local cb
    circuits[id] = function(cmd, data)
      local rcb = cb
      cb = nil
      table.insert(buffer, {cmd = cmd, data = data})
      if rcb then
        scheduler.addthread(function()
          scheduler.sleep(0)
          rcb()
        end)
      end
    end
    function circuit:read_cell()
      while #buffer == 0 do
        assert(not cb, "Attempt to multithread on single circuit")
        cb = scheduler.getresume()
        scheduler.yield()
      end
      local item = table.remove(buffer, 1)
      return tor_cmds[item.cmd].name, item.data
    end
    function circuit:send_raw_cell(cmd, data)
      socket_mutex:lock()
      -- print("Send Cell", tor_cmds[cmd].name)
      local sd = struct.pack(">" .. circ_id_len .. "B", id, cmd) .. data
      assert(conn:send(sd))
      socket_mutex:unlock()
    end
    function circuit:send_cell(cmd, data)
      assert(cmd ~= "versions")
      local cmd_id = assert(tor_cmds[cmd]).id
      if cmd_id >= 128 then
        data = struct.pack(">H", data:len()) .. data
      else
        data = data .. string.rep(string.char(0), PAYLOAD_LEN - data:len())
      end
      circuit:send_raw_cell(cmd_id, data)
    end
    function circuit:erase()
      circuits[id] = nil
    end
    return circuit
  end

  local function ensure_buf(len)
    while recv_buf:len() < len do
      recv_buf = recv_buf .. assert(conn:receive())
    end
  end

  local function read_version_cell(cmd, data)
    assert(cmd == "versions")
    while data:len() >= 2 do
      local vnum = struct.unpack(">H", data)
      if vnum == 3 then
        return true
      end
      data = data:sub(3)
    end
    error("Protocol 3 Missing")
  end

  local function read_certs_cell(cmd, data)
    assert(cmd == "certs")
    local N = struct.unpack(">B", data)
    local pos = 2
    for i = 1, N do
      local type, len = struct.unpack(">BH", data:sub(pos))
      local cert = data:sub(pos + 3, pos + 3 + len - 1)
      pos = pos + 3 + len
      -- print("CERT", type, cert:len())
      -- assert(not certs[type])
      -- certs[type] = cert
    end
  end

  local function read_challenge_cell(cmd, data)
    assert(cmd == "auth_challenge")
    local challenge = data:sub(1, 32)
    local method_count = struct.unpack(">H", data:sub(33))
    for i = 1, method_count do
      local method = struct.unpack(">H", data:sub(35 + (i - 1) * 2))
    end
  end
  local function read_addr(data)
    local type, len = struct.unpack(">BB", data)
    local addr = data:sub(3, 3 + len - 1)
    return data:sub(3 + len)
  end
  local function read_netinfo_cell(cmd, data)
    assert(cmd == "netinfo")
    local time = struct.unpack(">I", data)
    data = read_addr(data:sub(5))
    local my_addr_cnt = struct.unpack(">B", data)
    data = data:sub(2)
    for i = 1, my_addr_cnt do
      data = read_addr(data)
    end
  end

  scheduler.addthread(function()
    scheduler.sleep(0.001)
    while next(circuits) do
      ensure_buf(3)
      local CircID, cmd = struct.unpack(">" .. circ_id_len .. "B", recv_buf)
      local len = PAYLOAD_LEN
      local start = 4
      if cmd == 7 or cmd >= 128 then
        ensure_buf(5)
        len = struct.unpack(">H", recv_buf:sub(start))
        start = 6
      end
      ensure_buf(start + len - 1)
      local data = recv_buf:sub(start, start + len - 1)
      recv_buf = recv_buf:sub(start + len)
      -- print("Receive Cell", tor_cmds[cmd].name)
      if circuits[CircID] then
        circuits[CircID](cmd, data)
      else
        print("Package for unregistered circuit", CircID, cmd)
      end
    end
  end)

  local control = register_circuit(0)

  control:send_raw_cell(7, struct.pack(">HH", 2, 3))

  assert(read_version_cell(util.call_timeout_cb_noreturn(control.read_cell, 5, function()
    error("First Handshake timeout")
  end, control)))
  read_certs_cell(util.call_timeout_cb_noreturn(control.read_cell, 5, function()
    error("First Handshake timeout")
  end, control))
  read_challenge_cell(util.call_timeout_cb_noreturn(control.read_cell, 5, function()
    error("First Handshake timeout")
  end, control))
  read_netinfo_cell(util.call_timeout_cb_noreturn(control.read_cell, 5, function()
    error("First Handshake timeout")
  end, control))

  control:send_cell("netinfo", struct.pack(">I BB BBBB B", os.time(), 4, 4, 0, 0, 0, 0, 0))

  local code, moria1
  repeat
    code, moria1 = http_client.request("http://moria.csail.mit.edu:9131/tor/server/authority", nil, nil, args.socket_provider)
    -- print(code, moria1)
  until code == 200

  local test_circuit = create_path(register_circuit(1), moria1)
  -- Target: http://xb2grobibwfzs3whjdqs6djk2lns3mkusdxsgz5nknb3honbvxacjaid.onion/
  -- test_circuit:extend(require"blue.tests.tor_node_infos"["gabelmoo"])
  -- test_circuit:extend(require"blue.tests.tor_node_infos"["dannenberg"])
  -- test_circuit:extend(require"blue.tests.tor_node_infos"["ExitNinja"])
  local dir_circuit = create_path(register_circuit(2), moria1)
  -- dir_circuit:extend(require"blue.tests.tor_node_infos"["gabelmoo"])
  -- dir_circuit:extend(require"blue.tests.tor_node_infos"["dannenberg"])
  -- dir_circuit:extend(require"blue.tests.tor_node_infos"["BexleyRecipes"])
  local dir_provider = require "blue.socket_wrapper"({connect = dir_circuit:provider().connect_dir})
  -- print(http_client.request("http://node/tor/rendezvous2/zfb5772vpm4i5ioutjq5ehw2beaau7qk", nil, nil, dir_provider))
  -- os.exit(0)
  local function require_file(fn, url)
    local e, consensus_data
    local file = io.open(fn)
    if file then
      consensus_data = file:read("*a")
      file:close()
    end
    if not consensus_data then
      print("MISSING " .. fn)
      e, consensus_data = http_client.request(url, nil, nil, dir_provider)
      local file = io.open(fn, "w")
      file:write(consensus_data)
      file:close()
    end
    return consensus_data
  end
  local consensus_data = require_file("consensus", "http://node/tor/status-vote/current/consensus")
  print("LOADED CONSENSUS")
  local consensus = dir.parse_consensus(consensus_data)
  print("PARSED CONSENSUS")
  local router_data = require_file("router", "http://node/tor/server/all")
  print("LOADED ROUTER")
  local routers = dir.parse_all_router(router_data)
  print("PARSED ROUTER")

  local ffi = require "ffi"
  local tor = ffi.load("tor/tor.so")
  ffi.cdef [[
void init_logging(int disable_startup_queue);

void
hs_build_blinded_pubkey(const void*pk,const uint8_t *secret, size_t secret_len,
                        uint64_t time_period_num,void*out);

int ed25519_public_blind(uint8_t *out,
                         const uint8_t *inp,
                         const uint8_t *param);
                         int tor_memcmp(const void *a, const void *b, size_t sz);
]]
  tor.init_logging(0)

  local function lookup_onion(addr)
    local current = true
    local addr_bin = base32.decode(addr)
    local mins = consensus.valid_after / 60
    local blk = math.floor(mins / 1440)
    if not current then
      blk = blk - 1
    end
    print("Current time", blk)
    local nonce = "key-blind" .. struct.pack(">LL", blk, 1440)
    local basepoint = "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
    local h = sha3("Derive temporary signing key\0" .. addr_bin:sub(1, 32) .. basepoint .. nonce)
    -- h=string.char(bit.band(h:byte(1),248))..h:sub(2,31)..string.char(bit.bor(64,bit.band(63,h:byte(32))))
    local out = ffi.new("char[32]")
    local pubkey = ffi.new("char[32]", addr_bin:sub(1, 32))
    print(require"blue.hex".encode(ffi.string(pubkey, 32)))
    tor.ed25519_public_blind(out, ffi.new("char[32]", addr_bin:sub(1, 32)), ffi.new("char[?]", h:len(), h))
    local blinded_pubkey = ffi.string(out, 32)
    print(require"blue.base64".encode(blinded_pubkey))
    local hsdir_n_replicas = 2
    local hsdir_spread_fetch = 3
    local hsdir_spread_store = 4
    local repica_indices = {}
    local search = {}
    search[require"blue.hex".decode("8B 64 F5 93 CA C2 ED 05 C0 FA 70 3A EF 50 FF 71 92 5B 56 9C")] = true
    search[require"blue.hex".decode("4F 9B E3 A5 49 73 0D 4B 57 05 E1 B8 9D 63 7C A8 24 A5 7D A1")] = true
    search[require"blue.hex".decode("A4 CC 39 18 4A D2 87 D7 2C 22 47 73 88 35 81 1C 7A 7E CB 8E")] = true
    search[require"blue.hex".decode("82 5A D5 D3 3B 2A 5C 41 BC 64 70 47 D6 B6 3A C4 1C 4C 50 21")] = true
    search[require"blue.hex".decode("BF 73 5F 66 94 81 EE 1C CC 34 8F 07 31 55 1C 93 3D 1E 22 78")] = true
    search[require"blue.hex".decode("FF 30 59 E7 7E 5D 22 F1 C3 B2 0C CB E1 25 69 1A D2 75 88 DD")] = true
    for _, dir in ipairs(consensus.hidden_service_dirs) do
      local router = routers[dir.identity]
      if router then
        -- decode(router)
        dir.hsdir_index = sha3("node-idx" .. router.master_key_ed25519 .. (current and consensus.shared_current_value or consensus.shared_prev_value) .. struct.pack(">LL", blk, 1440))
        if router.master_key_ed25519 == require"blue.hex".decode("0F 05 79 43 19 24 52 0E 9A 48 8A C2 1E 03 81 84 E0 27 4C DD 83 15 FA 70 6F 8C 07 1B 56 BB A4 4F") then
          print(require"blue.hex".encode(dir.hsdir_index))
        end
        -- print(require"blue.hex".encode(dir.identity),require"blue.hex".encode(dir.hsdir_index))
      end
      --[[for k, v in pairs(dir) do
      end]]
      -- assert(dir.identity~=require"blue.hex".decode("A4 CC 39 18 4A D2 87 D7 2C 22 47 73 88 35 81 1C 7A 7E CB 8E"))
    end
    print("All routers")
    -- os.exit(0)
    local nl = {unpack(consensus.hidden_service_dirs)}
    local function cmp(a, b)
      if a and b then
        assert(a:len() == b:len())
        return tor.tor_memcmp(a, b, a:len()) < 0
      elseif b and not a then
        return true
      else
        return false
      end
    end
    local ret = {}
    for replicanum = 1, hsdir_n_replicas do
      local index = sha3("store-at-idx" .. blinded_pubkey .. struct.pack(">LLL", replicanum, 1440, blk))
      print("HS INDEX", require"blue.hex".encode(index))
      table.insert(nl, {is_mark = true, hsdir_index = index})
    end
    table.sort(nl, function(a, b)
      return cmp(a.hsdir_index, b.hsdir_index)
    end)
    for i, node in ipairs(nl) do
      if search[node.identity] then
        print("SORTED", require"blue.hex".encode(node.identity), require"blue.hex".encode(node.hsdir_index))
      end
    end
    local valid = {}
    for i, node in ipairs(nl) do
      if node.is_mark then
        table.insert(valid, nl[((i + 1) % (#nl)) + 1])
      end
    end
    for i, dir in ipairs(valid) do
      local dir_circuit = create_path(register_circuit(3 + i), moria1)
      dir_circuit:extend(routers[dir.identity])
      local dir_provider = require "blue.socket_wrapper"({connect = dir_circuit:provider().connect_dir})
      local status, content = http_client.request("http://node/tor/hs/3/" .. require"blue.base64".encode(blinded_pubkey), nil, nil, dir_provider)
      if status==200 then
        return content
      end
    end
    return nil,"error"
  end
  local descriptor=assert(lookup_onion("aupfgzsrk52tj4bp7debhwvdfl5u4g6lsdxro5gxbemn4r3cazutqbad"))
  dir.parse_hidden(descriptor)

  os.exit()
  local cnt = 0
  scheduler.addthread(function()
    while true do
      scheduler.sleep(1)
      -- print("CNT", cnt)
    end
  end)
  for i, dir in ipairs(consensus.hidden_service_dirs) do
    if i % 100 == 0 then
      print(i, "of", #consensus.hidden_service_dirs, "current(", cnt, ")")
    end
    local function f()
      cnt = cnt + 1
      -- print("REQ",dir.ip,dir.dirport)
      local e, m = pcall(function()
        local dir_provider = require "blue.socket_wrapper"({connect = dir_circuit:provider().connect_dir})
        local dir_circuit = create_path(register_circuit(3 + i), moria1)
        local status, content = http_client.request("http://" .. dir.ip .. ":" .. dir.dirport .. "/tor/rendezvous/3g2upl4pq6kufc4m", nil, nil, dir_provider)
        if status and status < 300 then
          decode(dir)
          print(content)
        end
      end)
      cnt = cnt - 1
      -- assert(e, m)
    end
    while cnt > 512 do
      scheduler.sleep(0.001)
    end
    scheduler.addthread(f)
  end

  --[[local nodes = {}
  for i = 1, 3 do
    table.insert(nodes, consensus.relays[math.random(1, #consensus.relays)])
  end
  table.insert(nodes, consensus.exits[math.random(1, #consensus.exits)])
  for i = 1, #nodes do
    local node = nodes[i]
    local _, h
    _, nodes[i], h = http_client.request("http://node/tor/server/d/" .. require"blue.hex".encode(node.digest):gsub(" ", ""), nil, nil, dir_provider)
  end
  for i = 1, #nodes do
    test_circuit:extend(nodes[i])
  end]]
  -- local provider = test_circuit:provider()
  -- print(http_client.request("http://3g2upl4pq6kufc4m.onion/", nil, nil, provider))
  -- print("EXTENDED")

  --[[  local provider = test_circuit:provider()
  local conn = matrix.connect("", "", "", provider)
  function conn.on_invite(room)
    print("JOINING", room.name)
    room:join()
  end
  function conn.on_room_joined(room)
    local first = true
    function room.on_sync_finished()
      if first then
        first = false
        if not room.name then
          for i = 1, 5 do
            print("SI", i)
            -- room:send_text_message("MSG "..i)
          end
        end
      end
    end
    function room.on_text_message(message, sender)
      print("MESSAGE", message, sender.name, sender.self)
      decode(message)
      if not sender.self then
        print("SEND", room:send_text_message("Answer: " .. message), true)
      end
    end
  end
  conn:start()
  print("DONE")]]

  --[[




  local rfc
  local function read_created2_cell(cmd, CircID, data)
    assert(cmd == 11)
    local hlen = struct.unpack(">H", data)
    local hdata = data:sub(3, 3 + hlen - 1)
    rfc(hdata)
  end
  local function read_destroy_cell(cmd, CircID, data)
    assert(cmd == 4)
    print(
        ({[0] = "NONE", "PROTOCOL", "INTERNAL", "REQUESTED", "HIBERNATING", "RESOURCELIMIT", "CONNECTFAILED", "OR_IDENTITY", "OR_CONN_CLOSED", "FINISHED", "TIMEOUT", "DESTROYED", "NOSUCHSERVICE"})[string.byte(
            data)])
    error("Destroy")
  end


  local key_forward

  local function send_create_cell()
    local ud
    ud, rfc = create_ntor()
    local pkg = struct.pack(">HB HH", 1, 10, 2, ud:len()) .. ud
    pkg = pkg .. string.rep(string.char(0), (PAYLOAD_LEN + 3) - pkg:len())
    -- print(pkg:gsub(".",function(a)return string.format("%02X ",string.byte(a))end))
    assert(conn:send(pkg))
  end

  local pkg = struct.pack(">HB I BB BBBB B", 0, 8, os.time(), 4, 4, 0, 0, 0, 0, 0)
  pkg = pkg .. string.rep(string.char(0), (PAYLOAD_LEN + 3) - pkg:len())
  -- print(pkg:gsub(".",function(a)return string.format("%02X ",string.byte(a))end))
  assert(conn:send(pkg))

  local function send_relay_cell()
    local ud = struct.pack(">sI", "78.42.208.205:80", 0x7)
    ud = ""
    -- local pkg=struct.pack(">HB BHHIH",0,3,13,0,1,0,ud:len())..ud
    local stream = aes.new(key_forward)
    local encd = stream.encrypt(struct.pack(">BHHIH", 13, 0, 1, 0, ud:len()) .. ud .. string.rep(string.char(0), PAYLOAD_LEN - 11 - ud:len()))
    encd = encd .. stream.close()
    local pkg = struct.pack(">HB", 1, 3) .. encd
    print("PACKAGE LEMNGTH", pkg:len(), (PAYLOAD_LEN + 3))
    pkg = pkg .. string.rep(string.char(0), (PAYLOAD_LEN + 3) - pkg:len())
    print(pkg:gsub(".", function(a)
      return string.format("%02X ", string.byte(a))
    end))
    assert(conn:send(pkg))
  end

  send_create_cell()
  read_created2_cell(read_cell())
  send_relay_cell()
  -- send_create_fast_cell()

  read_destroy_cell(read_cell())

  print("RECV", read_cell())
  print("RECV", read_cell())
  print("RECV", read_cell())]]
end
return tor
