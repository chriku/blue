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
--- Blue socket abstraction
-- @classmod bsocket
--- Connect to remote host
-- @function connect
-- @tparam string host Destination Hostname
-- @tparam integer port Destination Port
-- @treturn[1] socket Resulting socket
-- @treturn[2] nil
-- @treturn[2] string Error message
--- Listen for connections
-- @function bind
-- @tparam string host Hostanme to listen on
-- @tparam integer port Port
-- @tparam function cb The callback to be called with the new socket
-- @treturn[1] socket Resulting server
-- @treturn[2] nil
-- @treturn[2] string Error message
--- Socket Object
-- @section socket
--- Send data
-- @function socket:send
-- @tparam string data Data to send
-- @treturn[1] non-nil Success
-- @treturn[2] nil
-- @treturn[2] string Error message
--- Receive data
-- @function socket:receive
-- @treturn[1] string Received data
-- @treturn[2] nil
-- @treturn[2] string Error message
--- Close socket
-- @function socket:close
--- Server object
-- @section server Server
--- Receive data
-- @function server:local_port
-- @treturn[1] integer Resulting port
--- Stop listening
-- @function server:close
-- @nyi a b c
if package.loaded.copas then
  local lsocket = require "socket"
  do
    local sel = lsocket.select
    function lsocket.select(rd, wr, to)
      for _, fd in ipairs(rd) do
        if not (fd:getfd() >= 0) then
          return {fd}, {}
        end
      end
      return sel(rd, wr, to)
    end
  end
  local copas = require "copas"
  copas.autoclose = false
  local socket = {}
  local function wrap(s)
    local client = {}
    function client:send(data)
      return copas.send(s, data)
    end
    function client:receive()
      local d, e = copas.receive(s, 1)
      return d, e
    end
    function client:handshake()
      local err
      s, err = copas.dohandshake(s, {mode = "client", protocol = "any", verify = "none", options = {"all", "no_sslv3"}})
      return (not not s), err
    end
    function client:close()
      return s:close()
    end
    return require "blue.socket_wrapper"(client)
  end
  local sl = {}
  socket.connect = function(host, port)
    local s = lsocket.tcp()
    local cs, err
    cs, err = assert(copas.connect(s, host, port))
    if not cs then
      return nil, err
    end
    return wrap(s)
  end
  socket.bind = function(host, port, cb)
    local server, err = lsocket.bind(host, port)
    if not server then
      return nil, err
    end
    copas.addserver(server, function(s)
      cb(wrap(s))
    end)
    return {
      local_port = function()
        local _, port = server:getsockname()
        return tonumber(port)
      end
    }
  end
  local udp = lsocket.udp()
  function socket.sendto(ip, port, data)
    udp:setsockname("255.255.255.255", port)
    udp:setoption("broadcast", true)
    udp:settimeout(0, "t")
    assert(udp:sendto(data, ip, port))
  end
  function socket.receivefrom(port, kf)
    kf = kf or {}
    local udp = lsocket.udp4()
    function kf.kf() -- Stop listening
      udp:close()
    end
    assert(udp:setoption("reuseaddr", true))
    assert(udp:setsockname("255.255.255.255", port))
    udp:settimeout(0, "t")
    local data, ip, port = copas.receivefrom(udp, 4096)
    -- print(ip,port)
    udp:close()
    return ip, data
  end
  return socket
elseif package.loaded.lgi then
  local scheduler = require "blue.scheduler"
  local bytes = require 'bytes'
  local lgi = require 'lgi'
  local Gio = lgi.Gio
  local GLib = lgi.GLib
  local socket = {}
  function socket.sendto(ip, port, data)
    local socket = Gio.Socket.new("IPV4", "DATAGRAM", "UDP")
    socket:set_broadcast(true)
    local sa = Gio.InetSocketAddress.new(Gio.InetAddress.new_from_string(ip), port)
    socket:send_to(sa, data, nil, nil)
    socket:close()
  end
  function socket.receivefrom(port, kf)
    kf = kf or {}
    local socket = Gio.Socket.new("IPV4", "DATAGRAM", "UDP")
    socket:set_broadcast(true)
    local sa = Gio.InetSocketAddress.new(Gio.InetAddress.new_from_string("255.255.255.255"), port)
    socket:bind(sa, true)
    socket:set_blocking(false)
    local buf = bytes.new(4096)
    local len, err
    local addr = ""
    local function dr()
      len, err = socket:receive_from(buf)
      if len >= 0 then
        addr = err:get_address():to_string()
      elseif err.code ~= "WOULD_BLOCK" then
        -- print(len,err,err.code,err.code~="WOULD_BLOCK")
        error(tostring(err), 2)
      end
      return len
    end
    local good = true
    while dr() < 0 do
      local ok = true
      local me = assert(coroutine.running(), "MT")
      local src = socket:create_source("IN")
      function kf.kf()
        if ok then
          ok = false
          good = false
          scheduler.resume(me, src)
        end
      end
      src:set_callback(function()
        if ok then
          ok = false
          scheduler.resume(me, src)
        end
      end, function()
        print("X")
      end)
      src:attach(nil)
      coroutine.yield()
      src:destroy()
    end
    socket:close()
    if not good then
      return "", ""
    end
    return addr, tostring(buf):sub(1, len)
  end
  local function wrap(conn)
    local client = {}
    function client:send(data)
      if not conn then
        return nil, "closed"
      end
      local os = conn:get_output_stream()
      if (os:is_closed()) then
        return nil, "closed"
      end
      -- print("SEND",data:len())
      -- if os:is_closed() then return nil,"closed" end
      local bw, err = os:write(data)
      -- print("SENT",bw,err)
      if bw < 0 then
        print("SERR", err)
        return nil, err.message
      end
      local ok, err = os:flush()
      if not ok then
        return nil, err.message
      end
      return data:len()
    end
    local rresume = {}
    function client:receive()
      if not conn then
        return nil, "closed"
      end
      local is = conn:get_input_stream()
      if (is:is_closed() and not is:has_pending()) then
        return nil, "closed"
      end
      local me = assert(coroutine.running(), "MT")
      local err, data
      rresume[me] = true
      is:read_bytes_async(4096, GLib.PRIORITY_DEFAULT, nil, function(self, b)
        data, err = is:read_bytes_finish(b)
        rresume[me] = nil
        scheduler.resume(me)
      end)
      coroutine.yield()
      if not data then
        return nil, "closed"
      end
      local len = data:get_size()
      -- print("RECV",len,err)
      -- if len<=0 then print("RERR",err) end
      if len == 0 then
        return nil, "closed"
      end
      if err then
        return nil, err.message
      end
      return tostring(data:get_data()):sub(1, len)
    end
    function client:close()
      if not conn then
        return nil, "closed"
      end
      conn:close()
      for k, v in pairs(rresume) do
        scheduler.resume(k)
        rresume[k] = nil
      end
    end
    return require "blue.socket_wrapper"(client)
  end
  socket.connect = function(host, port)
    local s = Gio.SocketClient.new()
    local me = assert(coroutine.running(), "MT")
    local conn, err
    s:connect_to_host_async(host, tonumber(port) .. "", nil, function(self, res)
      conn, err = s:connect_to_host_finish(res)
      scheduler.resume(me)
    end)
    coroutine.yield()
    if not conn then
      -- print("CE", err, err.message)
      return nil, err.message
    end
    return wrap(conn)
  end
  socket.bind = function(host, port, cb)
    local server = Gio.SocketListener()
    local ok, e
    if math.floor(port) > 0 then
      ok, e = server:add_inet_port(port, nil)
    else
      port, e = server:add_any_inet_port(nil, nil)
      ok = (port > 0)
    end
    if not ok then
      return nil, tostring(e)
    end
    local function asy()
      server:accept_async(nil, function(self, task)
        local socket, a, b, c = server:accept_finish(task, nil, nil)
        asy()
        scheduler.addthread(cb, wrap(socket))
      end)
    end
    asy()
    -- server:start()
    return {
      local_port = function()
        return port
      end
    }
  end
  return socket
else
  error("Invalid Scheduler System (2)", 2)
end
