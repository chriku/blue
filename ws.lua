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
local sha1 = require "blue.sha1"
local base64 = require "blue.base64"
local scheduler = require "blue.scheduler"
return function(pfunc, request, headers)
  local struct = require "blue.struct"
  local raw = false
  local ws = {}
  local swk = request["X-sec-websocket-key"]
  local swa = base64.encode(sha1.binary(swk .. "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
  headers.upgrade = "websocket"
  headers.connection = "upgrade"
  headers["Sec-WebSocket-Accept"] = swa
  return function(socket)
    scheduler.addthread(function()
      scheduler.sleep(0.1)
      local open = true
      ws.close = function(sd)
        socket:close()
      end
      ws.send = function(sd)
        if not open then
          return nil, "closed"
        end
        if raw then
          socket:send(sd)
          return
        end
        local len = sd:len()
        local data = ""
        if len > 65535 then
          data = struct.pack(">L", len)
          len = 127
        elseif len > 125 then
          data = struct.pack(">H", len)
          len = 126
        end
        data = struct.pack(">BB", 128 + 1, len) .. data
        data = data .. sd
        -- print(string.byte(data:sub(1,1)))
        socket:send(data)
      end
      local buf = ""
      local function read()
        if not open then
          return string.char(0)
        end
        while buf:len() == 0 do
          local d = socket:receive()
          if not d then
            open = false
            return string.char(0)
          end
          buf = buf .. d
        end
        local c = buf:sub(1, 1)
        buf = buf:sub(2)
        return c
      end
      local receive
      local cb
      function ws.set_cb(ncb)
        if not cb then
          scheduler.addthread(function()
            scheduler.sleep(0.000001)
            while open do
              local ret, err = receive()
              if ret then
                scheduler.addthread(cb, "data", ret)
              elseif err ~= "closed" then
                scheduler.addthread(cb, "error", err)
              end
            end
            cb("closed")
          end)
        end
        cb = ncb
      end
      function receive()
        if not open then
          return nil, "closed"
        end
        if raw then
          return read()
        end
        local type, len = struct.unpack(">BB", read() .. read())
        if not open then
          return nil, "closed"
        end
        if len < 128 then
          error("NEED MASKING")
        end
        len = len - 128
        if len == 126 then
          len = assert(struct.unpack(">H", read() .. read()))
        elseif len == 127 then
          len = assert(struct.unpack(">L", read() .. read() .. read() .. read() .. read() .. read() .. read() .. read()))
        end
        local mask = {string.byte(read()), string.byte(read()), string.byte(read()), string.byte(read())}
        local ret = ""
        for i = 1, len do
          ret = ret .. string.char(bit.bxor(string.byte(read()), mask[((i - 1) % 4) + 1]))
        end
        if not open then
          return nil, "closed"
        end
        return ret
      end
      pfunc(ws, request)
    end)
  end
end
