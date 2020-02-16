local sha3 = require "blue.tor.crypto.sha3"
local base32 = require "blue.base32"
local base64 = require "blue.base64"
local struct = require "blue.struct"
local scheduler = require "blue.scheduler"
local http_client = require "blue.http_client"
local key_blinding = require "blue.tor.key_blinding"
local socket_wrapper = require "blue.socket_wrapper"

return function(tor)
  local hidden_service_client = {}
  function hidden_service_client.lookup_onion(addr)
    local current = os.time() > tor.consensus.valid_after
    local addr_bin = base32.decode(addr)
    local mins = tor.consensus.valid_after / 60
    local blk = math.floor(mins / 1440)
    if not current then
      blk = blk - 1
    end
    local nonce = "key-blind" .. struct.pack(">LL", blk, 1440)
    local basepoint = "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
    local h = sha3("Derive temporary signing key\0" .. addr_bin:sub(1, 32) .. basepoint .. nonce)
    local blinded_pubkey = key_blinding.blind_public_key(addr_bin:sub(1, 32), h)
    local credential = sha3("credential" .. addr_bin:sub(1, 32))
    local subcredential = sha3("subcredential" .. credential .. blinded_pubkey)
    local hsdir_n_replicas = 2
    local hsdir_spread_fetch = 3
    local hsdir_spread_store = 4
    local repica_indices = {}
    for _, dir in ipairs(tor.consensus.hidden_service_dirs) do
      local router = tor.routers[dir.identity]
      if router then
        dir.hsdir_index = sha3("node-idx" .. router.master_key_ed25519 .. (current and tor.consensus.shared_current_value or tor.consensus.shared_prev_value) .. struct.pack(">LL", blk, 1440))
      end
    end
    local nl = {unpack(tor.consensus.hidden_service_dirs)}
    local function memcmp(a, b)
      for i = 1, a:len() do
        local ba = a:byte(i)
        local bb = b:byte(i)
        if ba ~= bb then
          return ba - bb
        end
      end
      return 0
    end
    local function cmp(a, b)
      if a and b then
        assert(a:len() == b:len())
        local lv = memcmp(a, b)
        return lv < 0
      elseif b and not a then
        return true
      else
        return false
      end
    end
    local ret = {}
    for replicanum = 1, hsdir_n_replicas do
      local index = sha3("store-at-idx" .. blinded_pubkey .. struct.pack(">LLL", replicanum, 1440, blk))
      table.insert(nl, {is_mark = true, hsdir_index = index})
    end
    table.sort(nl, function(a, b)
      return cmp(a.hsdir_index, b.hsdir_index)
    end)
    local valid = {}
    for i, node in ipairs(nl) do
      if node.is_mark then
        table.insert(valid, nl[((i + 1) % (#nl)) + 1])
      end
    end
    if #valid == 0 then
      return nil, "no valid dirs found"
    end
    local ret, ret2
    for i, dir in ipairs(valid) do
      scheduler.addthread(function()
        local ok, data, data2 = pcall(function()
          local dir_circuit = tor.circuit.create_path()
          dir_circuit:extend(tor.routers[dir.identity])
          local dir_provider = socket_wrapper({connect = dir_circuit:provider().connect_dir})
          local status, content = http_client.request("http://node/tor/hs/3/" .. base64.encode(blinded_pubkey), nil, nil, dir_provider)
          if status == 200 then
            return content, {blinded_pubkey = blinded_pubkey, pubkey = addr_bin:sub(1, 32), credential = credential, subcredential = subcredential}
          end
          assert(status == 404)
          return nil
        end)
        if ok and data then
          ret, ret2 = data, data2
        elseif not ok then
          print(data)
        else
          print("no data here")
        end
      end)
    end
    for i = 1, 5000 do
      scheduler.sleep(0.001)
      if ret then
        return ret, ret2
      end
    end
    return nil, "error"
  end
  return hidden_service_client
end
