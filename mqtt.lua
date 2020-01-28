-- Copyright (c) 2019 Christian Georg Kurz [chrikuvellberg@gmail.com]
-- 
-- This file is part of the Blue-Scheduler. 
-- 
-- The Blue-Scheduler is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Lesser General Public License as
-- published by the Free Software Foundation, either version 3 of
-- the License, or (at your option) any later version.
-- 
-- The Blue-Scheduler is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
-- 
-- You should have received a copy of the GNU Lesser General Public License
-- along with the Blue-Scheduler. If not, see <http://www.gnu.org/licenses/>.
--- MQTT v3.1.1 Client
local scheduler = require "blue.scheduler"
local util = require "blue.util"
local mqtt = {}
local function decode_mqtt_int(str, pos)
  pos = pos or 1
  local v = 0
  v = v + (string.byte(str:sub(pos, pos)) * 256)
  v = v + (string.byte(str:sub(pos + 1, pos + 1)) * 1)
  return v, pos + 2
end
local function encode_mqtt_int(int)
  local ret = {}
  ret[1] = string.char((int / 256) % 256)
  ret[2] = string.char((int / 1) % 256)
  return table.concat(ret)
end
local function decode_mqtt_utf8(str, pos)
  pos = pos or 1
  local len
  len, pos = decode_mqtt_int(str, pos)
  local data = str:sub(pos, pos + len - 1)
  return data, pos + len
end
local function encode_mqtt_utf8(str)
  return encode_mqtt_int(str:len()) .. str
end
local function decode_mqtt_varint(str, pos)
  pos = pos or 1
  local v = 0
  local mul = 1
  repeat
    local cur = string.byte(str, pos)
    if not cur then
      return nil
    end
    pos = pos + 1
    v = v + (mul * (cur % 128))
    mul = mul * 128
  until cur < 128
  return v, pos
end
local function encode_mqtt_varint(val)
  local ret = {}
  repeat
    local b = val % 128
    val = math.floor(math.abs(val / 128))
    if val ~= 0 then
      b = b + 128
    end
    table.insert(ret, string.char(b))
  until val == 0
  return table.concat(ret)
end
local packages = {
  CONNECT = {id = 1},
  CONNACK = {id = 2},
  PUBLISH = {id = 3},
  PUBACK = {id = 4},
  PUBREC = {id = 5},
  PUBREL = {id = 6, flags = 2},
  PUBCOMP = {id = 7},
  SUBSCRIBE = {id = 8, flags = 2},
  SUBACK = {id = 9},
  UNSUBSCRIBE = {id = 10, flags = 2},
  UNSUBACK = {id = 11},
  PINGREQ = {id = 12},
  PINGRESP = {id = 13},
  DISCONNECT = {id = 14}
}
local typemap = {}
for k, v in pairs(packages) do
  v.name = k
  typemap[v.id] = v
end
local function do_fixed_header(type, rest, flags)
  local type_info = packages[type]
  if not type_info then
    error("Invalid Package Type", 2)
  end
  flags = flags or type_info.flags or 0
  local b1 = (type_info.id * 16) + (flags % 16)
  local b2 = encode_mqtt_varint(rest:len())
  return string.char(b1) .. b2 .. rest
end
function mqtt.connect(host, port, username, password, settings, socket_provider) -- TODO: timeout if error
  settings = settings or {}
  local keep_alive = settings.keep_alive or 0
  local socket = assert((socket_provider or require "blue.bsocket").connect(host, port))
  local function send_packet(type, content, flags)
    return socket:send(do_fixed_header(type, table.concat(content), flags))
  end
  local mqtt_ctx = {}
  local handlers = {}
  local publish_handlers = {}
  local function decode_packet(data, pos)
    local b1 = string.byte(data, 1)
    local type = typemap[math.floor(b1 / 16)]
    local flags = math.floor(b1 % 16)
    local x = {}
    if not type then
      error("Invalid Type received")
    end
    -- print("Received",type.name)
    if not handlers[type] then
      error("Missing handle function")
    end
    handlers[type](flags, data:sub(pos))
  end
  local packet_id_client = {} -- started by me
  local packet_id_server = {} -- started by server
  local function new_packet_id()
    for i = 1, 65535 do
      if not packet_id_client[i] then
        return i
      end
    end
  end
  local function id_handler(flags, data)
    local id, pos = decode_mqtt_int(data, 1)
    data = data:sub(pos)
    if packet_id_client[id] then
      scheduler.addthread(packet_id_client[id], data)
      packet_id_client[id] = nil
    else
      return
    end
  end
  local resume
  handlers[packages["CONNECT"]] = function()
    error("INV")
  end
  handlers[packages["CONNACK"]] = function(flags, data)
    local status = string.byte(data, 2)
    if status == 0 then
      scheduler.addthread(resume)
    elseif status == 1 then
      error("unacceptable protocol version")
    elseif status == 2 then
      error("identifier rejected")
    elseif status == 3 then
      error("Server unavailable")
    elseif status == 4 then
      error("bad user name or password")
    elseif status == 5 then
      error("not authorized")
    else
      error("Invalid Error")
    end
  end
  function mqtt_ctx.publish(topic, qos, data)
    local content = {}
    table.insert(content, encode_mqtt_utf8(topic))
    local flags = 0
    flags = flags + ((qos % 4) * 2)
    local id
    local resume
    local handler
    if qos == 0 then
    elseif qos == 1 or qos == 2 then
      id = new_packet_id()
      table.insert(content, encode_mqtt_int(id))
      packet_id_client[id] = function()
        resume()
      end
    else
      error("Invalid QoS", 2)
    end
    table.insert(content, data)
    send_packet("PUBLISH", content, flags)
    if qos == 1 or qos == 2 then
      resume = scheduler.getresume()
      scheduler.yield()
    end
  end
  handlers[packages["PUBLISH"]] = function(flags, data)
    local qos = (math.floor(flags / 2) % 4)
    local topic, pos = decode_mqtt_utf8(data)
    local id
    local do_cb
    if qos == 1 then
      id = decode_mqtt_int(data, pos)
      local content = {}
      table.insert(content, encode_mqtt_int(id))
      send_packet("PUBACK", content)
    elseif qos == 2 then
      id = decode_mqtt_int(data, pos)
      local content = {}
      table.insert(content, encode_mqtt_int(id))
      send_packet("PUBREC", content)
      packet_id_client[id] = function()
        do_cb()
      end
    elseif qos ~= 0 then
      error("Invalid QoS", 2)
    end
    data = data:sub(pos)
    function do_cb()
      for k, v in pairs(publish_handlers) do
        k = k:gsub("[^a-z0-9/%+%#]", "%%%1")
        k = k:gsub("%+", "[^/]*")
        k = k:gsub("%#", ".*")
        if topic:find("^" .. k .. "$") then
          scheduler.addthread(v, data)
        end
      end
    end
    if qos ~= 2 then
      do_cb()
    end
  end
  handlers[packages["PUBACK"]] = id_handler
  handlers[packages["PUBREC"]] = function(flags, data)
    local id, pos = decode_mqtt_int(data, 1)
    data = data:sub(pos)
    if packet_id_client[id] then
      local h = packet_id_client[id]
      packet_id_client[id] = h2
      send_packet("PUBREL", {encode_mqtt_int(id)})
    else
      return
    end
  end
  handlers[packages["PUBREL"]] = function(flags, data)
    local id, pos = decode_mqtt_int(data, 1)
    data = data:sub(pos)
    send_packet("PUBCOMP", {encode_mqtt_int(id)})
    if packet_id_client[id] then
      scheduler.addthread(packet_id_client[id], data)
      packet_id_client[id] = nil
    else
      return
    end
  end
  handlers[packages["PUBCOMP"]] = id_handler
  function mqtt_ctx.subscribe(topic, qos, cb)
    local id = new_packet_id()
    local content = {}
    table.insert(content, encode_mqtt_int(id))
    assert(topic)
    assert(qos)
    assert(cb)
    table.insert(content, encode_mqtt_utf8(topic))
    table.insert(content, string.char(qos))
    publish_handlers[topic] = cb
    local resume
    packet_id_client[id] = function(data)
      packet_id_client[id] = nil
      local ret = string.byte(data)
      if ret <= 2 then
        resume(true, ret)
      else
        resume(nil, "server didn't want it")
      end
    end
    send_packet("SUBSCRIBE", content)
    resume = scheduler.getresume()
    return scheduler.yield()
  end
  handlers[packages["SUBSCRIBE"]] = function()
    error("INV")
  end
  handlers[packages["SUBACK"]] = id_handler
  function mqtt_ctx.unsubscribe(topic)
    local id = new_packet_id()
    local content = {}
    table.insert(content, encode_mqtt_int(id))
    assert(topic)
    table.insert(content, encode_mqtt_utf8(topic))
    local resume
    packet_id_client[id] = function(data)
      packet_id_client[id] = nil
      local ret = string.byte(data)
      resume(true)
    end
    send_packet("UNSUBSCRIBE", content)
    resume = scheduler.getresume()
    return scheduler.yield()
  end
  handlers[packages["UNSUBSCRIBE"]] = function()
    error("INV")
  end
  handlers[packages["UNSUBACK"]] = id_handler
  local last_resp = {}
  handlers[packages["PINGREQ"]] = function()
    error("INV")
  end
  handlers[packages["PINGRESP"]] = function()
    last_resp = {}
  end
  handlers[packages["DISCONNECT"]] = function()
    error("INV")
  end
  function mqtt_ctx.close()
    send_packet("DISCONNECT", {})
    socket:close()
  end
  local open = true
  scheduler.addthread(function()
    while open and keep_alive > 0 do
      scheduler.sleep(keep_alive)
      if not open then
        return
      end
      local this_resp = last_resp
      local sent = send_packet("PINGREQ", {})
      if not sent then
        return
      end
      scheduler.sleep(keep_alive * 0.5)
      if this_resp == last_resp then
        mqtt_ctx.close()
      end
    end
  end)
  scheduler.addthread(function()
    local buf = ""
    while true do
      local something = socket:receive()
      if not something then
        open = false
        break
      end
      buf = buf .. something
      while true do
        local len, pos = decode_mqtt_varint(buf, 2)
        if len and buf:len() >= (pos + len - 1) then
          local p2 = pos
          local data = buf:sub(1, pos + len - 1)
          buf = buf:sub(pos + len)
          scheduler.addthread(decode_packet, data, p2)
        else
          break
        end
      end
    end
  end)
  do
    local content = {}
    table.insert(content, encode_mqtt_utf8("MQTT"))
    table.insert(content, string.char(4))
    local flags = 2
    if password then
      flags = flags + 64
    end
    if username then
      flags = flags + 128
    end
    table.insert(content, string.char(flags))
    table.insert(content, encode_mqtt_int(keep_alive or 0))
    table.insert(content, encode_mqtt_utf8("")) -- Session ID
    if username then
      table.insert(content, encode_mqtt_utf8(username))
    end
    if password then
      table.insert(content, encode_mqtt_utf8(password))
    end
    send_packet("CONNECT", content)
  end
  resume = scheduler.getresume()
  scheduler.yield()
  return mqtt_ctx
end
return mqtt
