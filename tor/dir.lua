require "blue.util"
local dir = {}
local base64 = require "blue.base64"
local hex = require "blue.hex"
local function read_dir(str)
  if not str then
    error("Invalid directory string", 2)
  end
  local lines = {}
  local items = {}
  local in_block = nil
  local block_data
  local last_item = {}
  str = str:sub(1, (str:find("\0", nil, true) or 0) - 1)
  for line in str:gmatch("[^\n\r]+") do
    local object_begin = line:match("^%-%-%-%-%-BEGIN ([A-Za-z0-9%- ]+)%-%-%-%-%-$")
    local object_end = line:match("^%-%-%-%-%-END ([A-Za-z0-9%- ]+)%-%-%-%-%-$")
    local keyword_single = line:match("^([A-Za-z0-9%-]+)$")
    local keyword_multi, args = line:match("^([A-Za-z0-9%-]+)[ \t]+(.-)$")
    if object_begin and not in_block then
      in_block = object_begin
      block_data = ""
    elseif object_end then
      assert(in_block == object_end)
      in_block = nil
      if last_item then
        last_item.block_data = {key = object_end, data = block_data}
      end
    elseif keyword_single and not in_block then
      assert(keyword_single ~= "-----BEGIN")
      local key = keyword_single
      items[key] = items[key] or {}
      local item = {key = key}
      last_item = item
      table.insert(items[key], item)
      table.insert(items, item)
    elseif keyword_multi and not in_block then
      assert(keyword_multi ~= "-----BEGIN")
      local key = keyword_multi
      items[key] = items[key] or {}
      local item = {data = args, key = key}
      last_item = item
      table.insert(items[key], item)
      table.insert(items, item)
    elseif in_block then
      block_data = block_data .. line
    end
  end
  assert(not in_block, "Still in block")
  -- items.to_sign=str:match("^.*\nrouter%-signature\n")
  return items
end
local function parse_router(items)
  local router = {}
  local readers = {}
  table.insert(readers, function()
    assert(items["router"])
    assert(#items["router"] == 1)
    assert(items["router"][1].data)
    local nickname, address, orport, _, dir_port = items["router"][1].data:match("^([^ ]*) ([0-9]*%.[0-9]*%.[0-9]*%.[0-9]*) ([0-9]*) ([0-9]*) ([0-9]*)")
    router.nickname = assert(nickname)
    router.address = assert(address)
    router.orport = assert(tonumber(orport))
    router.dir_port = assert(tonumber(dir_port))
  end)
  table.insert(readers, function()
    if items["identity-ed25519"] then
      assert(#items["identity-ed25519"] == 1)
      assert(items["identity-ed25519"][1].block_data)
      assert(items["identity-ed25519"][1].block_data.key == "ED25519 CERT")
      router.identity_ed25519 = base64.decode(items["identity-ed25519"][1].block_data.data)
    end
  end)
  table.insert(readers, function()
    if items["master-key-ed25519"] then
      assert(#items["master-key-ed25519"] == 1)
      assert(items["master-key-ed25519"][1].data)
      router.master_key_ed25519 = base64.decode(items["master-key-ed25519"][1].data)
    end
  end)
  table.insert(readers, function()
    if items["ntor-onion-key"] then
      assert(#items["ntor-onion-key"] == 1)
      assert(items["ntor-onion-key"][1].data)
      router.ntor_onion_key = base64.decode(items["ntor-onion-key"][1].data)
    end
  end)
  table.insert(readers, function()
    if items["fingerprint"] then
      assert(#items["fingerprint"] == 1)
      router.fingerprint = hex.decode(assert(items["fingerprint"][1].data))
    end
  end)
  for _, reader in ipairs(readers) do
    reader()
  end
  return router
end
function dir.parse_to_router(doc)
  if not doc then
    error("invalid router string", 2)
  end
  return parse_router(read_dir(doc))
end
function dir.parse_hidden(doc)
  return read_dir(doc)
end
function dir.parse_hidden_inner(doc)
  return read_dir(doc)
end
function dir.parse_hidden_plain(doc)
  local ips = {}
  local cur = {}
  for _, line in ipairs(read_dir(doc)) do
    if line.key == "introduction-point" then
      table.insert(ips, cur)
      cur = {}
    end
    table.insert(cur, line)
  end
  local hidden_service = {intoduction_points = {}}
  table.insert(ips, cur)
  local meta = table.remove(ips, 1)
  for _, ip in ipairs(ips) do
    local intp = {}
    for _, d in ipairs(ip) do
      local key = d.key
      if key == "introduction-point" then
        local ls = require"blue.base64".decode(d.data)
        intp.link_specifier = {}
        local count = ls:byte(1)
        ls = ls:sub(2)
        for i = 1, count do
          local type = ls:byte(1)
          local len = ls:byte(2)
          ls = ls:sub(3)
          local data = ls:sub(1, len)
          if type == 0 then
            intp.link_specifier.raw_address = data
          elseif type == 2 then
            intp.link_specifier.fingerprint = data
          end
          ls = ls:sub(len + 1)
        end
      elseif key == "onion-key" then
        local key = d.data:match("^ntor (.*)$")
        intp.link_specifier.ntor_onion_key = require"blue.base64".decode(key)
      elseif key == "auth-key" then
        intp.auth_key = require"blue.tor.ed25519".parse_cert(require"blue.base64".decode(d.block_data.data))
      elseif key == "enc-key" then
        local key = d.data:match("^ntor (.*)$")
        intp.enc_key = require"blue.base64".decode(key)
      elseif key == "enc-key-cert" then
        intp.enc_key_cert = require"blue.base64".decode(d.block_data.data)
      else
        print("Unknown key in hidden service: " .. key)
      end
    end
    table.insert(hidden_service.intoduction_points, intp)
  end
  return hidden_service
end
local function do_router(routers, rt)
  for _, pair in ipairs(rt) do
    local key = pair.key
    rt[key] = rt[key] or {}
    table.insert(rt[key], pair)
  end
  local data = parse_router(rt)
  routers[data.fingerprint] = data
  routers[data.nickname] = data
end
function dir.parse_all_router(doc)
  local routers = {}
  local dir = read_dir(doc)
  local cur
  for _, rt in ipairs(dir) do
    if rt.key == "router" then
      if cur then
        do_router(routers, cur)
      end
      cur = {}
    end
    table.insert(cur, rt)
  end
  do_router(routers, cur)
  return routers
end
function dir.parse_consensus(data)
  local consensus = read_dir(data)
  local relay = {protos = {}}
  local relays = {}
  local network = {relays = relays, exits = {}, hidden_service_dirs = {}}
  local function parse_date(str)
    local year, month, day, hour, min, sec = str:match("^([0-9]+)%-([0-9]+)%-([0-9]+)% ([0-9]+)%:([0-9]+)%:([0-9]+)$")
    return (os.time {year = year, month = month, day = day, hour = hour, min = min, sec = sec, isdst = false} - os.time {year = 1970, month = 01, day = 1, hour = 0, min = 0, sec = 0, isdst = false})
  end
  network.valid_after = parse_date(consensus["valid-after"][1].data)
  network.shared_current_value = require"blue.base64".decode(consensus["shared-rand-current-value"][1].data:match("^[0-9]* (.-)$"))
  network.shared_prev_value = require"blue.base64".decode(consensus["shared-rand-previous-value"][1].data:match("^[0-9]* (.-)$"))
  for _, pair in ipairs(consensus) do
    if pair.key == "r" then
      relay = {protos = {}}
      table.insert(relays, relay)
      local name, identity, digest, publication, ip, orport, dirport = pair.data:match(
                                                                           "^([^ \n\t]*)[ \n\t]*([^ \n\t]*)[ \n\t]*([^ \n\t]*)[ \n\t]*([^ \n\t]*[ \n\t]*[^ \n\t]*)[ \n\t]*([^ \n\t]*)[ \n\t]*([^ \n\t]*)[ \n\t]*([^ \n\t]*)[ \n\t]*")
      relay.name = name
      relay.identity = assert(require"blue.base64".decode(identity))
      relay.digest = assert(require"blue.base64".decode(digest))
      -- print(require"blue.hex".encode(relay.digest):gsub(" ",""))
      relay.ip = ip
      relay.orport = tonumber(orport)
      relay.dirport = tonumber(dirport)
    end
    if pair.key == "s" then
      for flag in pair.data:gmatch("[^ \n\t]*") do
        if flag == "Exit" then
          relay.exit = true
        end
        if flag:find("HSDir") then
          relay.hsdir = true
        end
      end
    end
    if pair.key == "pr" then
      for proto, versions in pair.data:gmatch("([a-zA-Z0-9]+)=([^ ]+)") do
        local p = {}
        relay.protos[proto] = p
        for version in versions:gmatch("[^,]+") do
          local from, to = version:match("^([0-9]+)%-([0-9]+)$")
          local single = version:match("^([0-9]+)$")
          if from and to then
            for i = tonumber(from), tonumber(to) do
              p[i] = true
            end
          elseif single then
            p[tonumber(single)] = true
          else
            error("Invalid protocol versions: " .. versions)
          end
        end
      end
    end
  end
  for _, relay in ipairs(relays) do
    if relay.exit then
      table.insert(network.exits, relay)
    end
  end
  for _, relay in ipairs(relays) do
    if relay.protos["HSDir"] and relay.protos["HSDir"][2] then
      table.insert(network.hidden_service_dirs, relay)
    end
  end
  return network
end
return dir
