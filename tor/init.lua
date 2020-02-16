local tor = {}
local ssl = require "blue.ssl"
local struct = require "blue.struct"
local sha1 = require "blue.sha1"
local rsa = require "blue.tor.rsa"
local aes = require "blue.tor.aes_stream"
local ed25519 = require "blue.tor.ed25519"
local util = require "blue.util"
local scheduler = require "blue.scheduler"
local matrix = require "blue.matrix.init"
local http_client = require "blue.http_client"
local dir = require "blue.tor.dir"
local sha3 = require "blue.tor.sha3"
local circ = require "blue.tor.circuit"
local param = require "blue.tor.param"
local hsc = require "blue.tor.hidden_service_client"
function tor.create(args)
  assert(args.first_relay)
  assert(args.first_relay.ip)
  assert(args.first_relay.port)
  assert(args.first_relay.port)
  local tor = {}
  local socket_provider = ssl.create(args.socket_provider)
  local code, moria1
  repeat
    code, moria1 = http_client.request("http://moria.csail.mit.edu:9131/tor/server/authority", nil, nil, args.socket_provider)
  until code == 200
  local circuit = circ(socket_provider.connect(args.first_relay.ip, args.first_relay.port), moria1)
  tor.circuit = circuit
  local hidden_service_client = hsc(tor)

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

  local control = circuit.control

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

  local test_circuit = circuit.create_path()
  local test_circuit2 = circuit.create_path()
  -- Target: http://xb2grobibwfzs3whjdqs6djk2lns3mkusdxsgz5nknb3honbvxacjaid.onion/
  -- test_circuit:extend(require"blue.tests.tor_node_infos"["gabelmoo"])
  -- test_circuit:extend(require"blue.tests.tor_node_infos"["dannenberg"])
  -- test_circuit:extend(require"blue.tests.tor_node_infos"["ExitNinja"])
  local dir_circuit = circuit.create_path()
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
  tor.consensus = dir.parse_consensus(consensus_data)
  print("PARSED CONSENSUS")
  local router_data = require_file("router", "http://node/tor/server/all")
  print("LOADED ROUTER")
  tor.routers = dir.parse_all_router(router_data)
  print("PARSED ROUTER")
  -- local descriptor, creds = assert(lookup_onion("aupfgzsrk52tj4bp7debhwvdfl5u4g6lsdxro5gxbemn4r3cazutqbad"))
  local descriptor, creds = assert(hidden_service_client.lookup_onion("aupfgzsrk52tj4bp7debhwvdfl5u4g6lsdxro5gxbemn4r3cazutqbad"))
  descriptor = dir.parse_hidden(descriptor)

  local function crypt(SECRET_DATA, STRING_CONSTANT, data)
    assert(type(SECRET_DATA) == "string")
    assert(type(STRING_CONSTANT) == "string")
    assert(type(data) == "string")
    local encrypted = require"blue.base64".decode(data)
    local salt, mac
    salt, encrypted, mac = encrypted:sub(1, 16), encrypted:sub(17, -33), encrypted:sub(-32, -1)
    local secret_input = SECRET_DATA .. creds.subcredential .. struct.pack(">L", tonumber(assert(descriptor["revision-counter"][1]).data))
    local S_KEY_LEN = 32
    local S_IV_LEN = 16
    local MAC_KEY_LEN = 32
    local keys = require "blue.tor.shake3"(secret_input .. salt .. STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
    assert(keys:len() == (S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN))
    local SECRET_KEY = keys:sub(1, S_KEY_LEN)
    local SECRET_IV = keys:sub(1 + S_KEY_LEN, S_IV_LEN + S_KEY_LEN)
    local MAC_KEY = keys:sub(S_IV_LEN + S_KEY_LEN + 1)
    local aes_ctx = aes.decrypt(SECRET_KEY, SECRET_IV)
    local ret = aes_ctx(encrypted)
    aes_ctx = nil

    assert(sha3(struct.pack(">L", MAC_KEY_LEN) .. MAC_KEY .. struct.pack(">L", salt:len()) .. salt .. encrypted) == mac, "Bad MAC")
    return ret
  end
  local superdecrypted = crypt(creds.blinded_pubkey, "hsdir-superencrypted-data", descriptor["superencrypted"][1].block_data.data)
  local inner = dir.parse_hidden_inner(superdecrypted)
  local authorization_cookie = ""
  local decrypted = crypt(creds.blinded_pubkey .. authorization_cookie, "hsdir-encrypted-data", inner["encrypted"][1].block_data.data)
  local cookie = require "blue.tor.random"(20)

  local rdp = tor.routers["gabelmoo"]

  test_circuit2:extend(rdp)
  test_circuit2:rendezvous(cookie)

  local plain = dir.parse_hidden_plain(decrypted)
  local ip = plain.intoduction_points[math.random(1, #plain.intoduction_points)]
  test_circuit:extend(ip.link_specifier)

  local idata = test_circuit:introduce1(ip, creds, rdp, cookie)

  test_circuit2:rendezvous2(idata)
  local test_provider = test_circuit2:provider()
  print("STARTING REQUEST")
  print(http_client.request("http://(rendezvous)/", nil, nil, test_provider))

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
