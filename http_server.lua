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
local socket = require "blue.bsocket"
local scheduler = require "blue.scheduler"
local util = require "blue.util"
local ws = require "blue.ws"
local getpage
local function answer(socket)
  local buf = ""
  local fdata = ""
  local function getline()
    local start = os.time()
    while (not buf:find("\r\n")) do
      local s = socket:receive()
      if not s then
        return
      end
      buf = buf .. s
    end
    local l
    l, buf = buf:match("^([^\n]*)\n(.-)$")
    fdata = fdata .. l .. "\n"
    l = l:gsub("\r$", "")
    return l
  end
  local fline = getline()
  if not fline then
    return
  end
  local method, page = fline:match("^([A-Z]*) (.-) HTTP/1.1$")
  local invalid = function(n)
    local data = "You sent a Bad Request\r\n" .. (n or 0) .. "\r\n"
    socket:send("HTTP/1.1 400 Bad Request\r\n")
    socket:send("Connection: Close\r\n")
    socket:send("Content-type: text/plain\r\n")
    socket:send("Content-length: " .. data:len() .. "\r\n")
    socket:send("\r\n")
    socket:send(data)
    socket:close()
  end
  if not (method and page) then
    return invalid(1)
  end
  local headers = {}
  repeat
    local line = getline()
    if not line then
      return invalid(2)
    end
    local k, v = line:match("^(.-):[\n\t\r ]*(.-)$")
    if k and v then
      k = k:lower()
      if headers[k] then
        if type(headers[k]) == "string" then
          headers[k] = {v, headers[k]}
        else
          table.insert(headers[k], v)
        end
      else
        headers[k] = v
      end
    end
  until line == ""
  local d = ""
  if headers["content-length"] then
    local len = tonumber(headers["content-length"])
    local start = os.time()
    while d:len() < len do
      if (os.time() - start) > 3 then
        return invalid(3)
      end
      if buf:len() > 0 then
        local len = len - d:len()
        d = d .. buf:sub(1, len)
        buf = buf:sub(len + 1)
      else
        buf = buf .. socket:receive()
      end
    end
  end
  -- print("D",d)
  -- decode(headers)
  -- local data=[[<html><body><img src="/test.png"/></body></html>]]
  local args = {}
  for k, v in pairs(headers) do
    args["X-" .. k] = v
  end
  args.method = method
  args.page = page:match("^[^%?]*")
  args.url = page
  args.content = d
  args.fdata = fdata
  args.rest = buf
  local mode, code, content, ns = getpage(args)
  local headers = {}
  for k, v in pairs(ns) do
    headers[k:lower()] = v
  end
  content = content or ""
  code = code or 500
  headers["connection"] = headers["connection"] or "keep-alive"
  if type(content) == "string" then
    headers["content-length"] = headers["content-length"] or content:len() .. ""
    headers["content-length"] = content:len() .. ""
  elseif mode == "normal" and not headers["content-length"] then
    error("Missing content-length")
  end
  if mode == "proxy" then
    content(socket)
    return
  end
  socket:send("HTTP/1.1 " .. code .. "\r\n")
  socket:send("X-Clacks-Overhead: GNU Terry Pratchett\r\n")
  -- decode(headers)
  for k, v in pairs(headers) do
    assert(type(k) == "string" or type(k) == "table", "Headerkey must be string")
    k = k:gsub("%-.", function(a)
      return a:upper()
    end)
    k = k:gsub("^.", function(a)
      return a:upper()
    end)
    if type(v) == "string" or type(v) == "number" then
      socket:send(k .. ": " .. v .. "\r\n")
    elseif type(v) == "table" then
      for i, v in ipairs(v) do
        socket:send(k .. ": " .. v .. "\r\n")
      end
    end
  end
  socket:send("\r\n")
  if type(content) == "string" then
    socket:send(content)
    -- socket:send("\r\n")
    -- socket:close()
    -- return
  elseif mode == "normal" then
    while true do
      local cur = content()
      -- print("SEND",cur:len())
      if not cur then
        socket:close()
        return
      end
      if cur:len() == 0 then
        break
      end
      socket:send(cur)
    end
  elseif mode == "switch" then
    return content(socket)
  else
    error("Unknown Mode: " .. mode)
  end
  scheduler.addthread(answer, socket)
end
local server, err = socket.bind("*", 80, function(socket)
  answer(socket)
end)
if not server then
  server, err = socket.bind("*", 8080, function(socket)
    answer(socket)
  end)
end
assert(server, err)
local pages = {}
function getpage(args)
  if pages[args.page] then
    local status, content, mime = pages[args.page].func(args)
    mime = mime or {["content-type"] = "text/plain"}
    if pages[args.page].single then
      pages[args.page] = nil
    end
    if type(status) == "string" then
      return "switch", 101, ws(content, args, mime), mime
    end
    return "normal", status, content, mime
  end
  return "normal", 404, "Not Found", {["content-type"] = "text/plain"}
end
local http = {}
function http.add(url, func)
  pages[url] = {func = func}
end
function http.remove(url)
  pages[url] = nil
end
return http
