local util = require "blue.util"
local scheduler = require "blue.scheduler"
local struct = require "blue.struct"
local param = require "blue.tor.param"
local create_path = require "blue.tor.path"
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
return function(conn, first_node_info)
  local socket_mutex = util.mutex()

  local recv_buf = ""
  local circ_id_len = "H"

  local circ = {}
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
        data = data .. string.rep(string.char(0), param.PAYLOAD_LEN - data:len())
      end
      circuit:send_raw_cell(cmd_id, data)
    end
    function circuit:erase()
      circuits[id] = nil
    end
    return circuit
  end
  circ.control = register_circuit(0)
  local count = 0
  function circ.create_circuit()
    count = count + 1
    return register_circuit(count) -- TODO!!!
  end
  function circ.create_path()
    return create_path(circ.create_circuit(), first_node_info)
  end

  local function ensure_buf(len)
    while recv_buf:len() < len do
      recv_buf = recv_buf .. assert(conn:receive())
    end
  end

  scheduler.addthread(function()
    scheduler.sleep(0.001)
    while next(circuits) do
      ensure_buf(3)
      local CircID, cmd = struct.unpack(">" .. circ_id_len .. "B", recv_buf)
      local len = param.PAYLOAD_LEN
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

  return circ
end
