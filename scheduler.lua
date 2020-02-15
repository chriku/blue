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
--- Scheduler system
-- @module scheduler
--- Suspend coroutine
--
-- This function always yields and enters the schedulig main loop, even if time=0
-- @function scheduler.sleep
-- @tparam time number seconds
--- New Thread
-- @function scheduler.addthread
-- @tparam function func
-- @param ... Arguments to be passed through
-- @noyield
--- Get Function to resume thread
-- @function scheduler.getresume
-- @treturn function Callback to resume this thread
-- @noyield
--- Yield thread
--
-- Yields a thread, allowing resume only via previous getresume
--
-- Important: Do not yield between scheduler.getresume and scheduler.yield
-- @function scheduler.yield
local function compat_copas()
  local copas = require "copas"
  -- local socket=require"socket"
  local scheduler = {}
  local data = setmetatable({}, {__mode = "k"})
  local function resume(co, ...)
    data[co] = {...}
    copas.wakeup(co)
  end
  debug.getregistry().scheduler = scheduler
  local threads = {}
  function scheduler.addthread(func, ...)
    if not func then
      error("Invalid Function", 2)
    end
    local args = {...}
    local L = copas.addthread(function()
      func(unpack(args))
    end)
  end
  function scheduler.sleep(time)
    local t = {}
    copas.sleep(time)
  end
  local calls = setmetatable({}, {__mode = "k"})
  function scheduler.getresume()
    local me = assert(coroutine.running(), "MT")
    return function(...)
      resume(me, ...)
    end
  end
  function scheduler.yield()
    local me = assert(coroutine.running(), "MT")
    copas.sleep(-1)
    if data[me] then
      return unpack(data[me])
    else
      print("MISSING!!!")
    end
  end
  return scheduler
end
local function compat_love()
  local copas = require "copas"
  function love.run()
    if love.load then
      love.load(love.arg.parseGameArguments(arg), arg)
    end
    if love.timer then
      love.timer.step()
    end
    local dt = 0
    return function()
      if love.event then
        love.event.pump()
        for name, a, b, c, d, e, f in love.event.poll() do
          if name == "quit" then
            if not love.quit or not love.quit() then
              return a or 0
            end
          end
          love.handlers[name](a, b, c, d, e, f)
        end
      end
      if love.timer then
        dt = love.timer.step()
      end
      if love.update then
        love.update(dt)
      end -- will pass 0 if love.timer is disabled
      if love.graphics and love.graphics.isActive() then
        love.graphics.origin()
        love.graphics.clear(love.graphics.getBackgroundColor())
        if love.draw then
          love.draw()
        end
        love.graphics.present()
      end
      local ok, err = copas.step(0.001)
      assert(ok ~= nil, err)
      -- if love.timer then love.timer.sleep(0.001) end
    end
  end
  return compat_copas()
end
local function compat_glib()
  local bytes = require 'bytes'
  local lgi = require 'lgi'
  local Gio = lgi.Gio
  local GLib = lgi.GLib
  local times = {}
  local function resume(co, ...)
    local where = debug.traceback(co)
    local ret = {coroutine.resume(co, ...)}
    local start = os.clock()
    collectgarbage()
    local time = os.clock()
    -- collectgarbage("step",10)
    time = time - start
    local t = where
    times[t] = (times[t] or 0) + time
    local ok = table.remove(ret, 1)
    if not ok then
      print("ERR", ret[1])
      return nil
    end
    return unpack(ret)
  end
  local scheduler = {resume = resume}
  local threads = {}
  function scheduler.addthread(func, ...)
    if not func then
      error("Func Missing", 2)
    end
    local co = coroutine.create(func)
    resume(co, ...)
    return co
  end
  function scheduler.sleep(time)
    assert(time >= 0)
    local me = assert(coroutine.running(), "MT")
    GLib.timeout_add(GLib.PRIORITY_DEFAULT, time * 1000, function()
      if me then
        local cme = me
        me = nil
        resume(cme)
      else
        -- print("DBL")
      end
      return false
    end)
    coroutine.yield()
  end
  local calls = setmetatable({}, {__mode = "k"})
  function scheduler.getresume()
    local me = assert(coroutine.running(), "MT")
    return function(...)
      resume(me, ...)
    end
  end
  function scheduler.yield()
    return coroutine.yield()
  end
  if false then
    scheduler.addthread(function()
      while true do
        scheduler.sleep(10)
        local r = next(times)
        for k, v in pairs(times) do
          if v > times[r] then
            r = k
          end
        end
        -- print(times[r],debug.traceback(r))
        print(times[r], r)
      end
    end)
  end
  return scheduler
end
if rawget(_G,"love") then
  return compat_love()
elseif package.loaded.copas then
  return compat_copas()
elseif package.loaded.lgi then
  return compat_glib()
elseif package.loaded.copas then
  return compat_copas()
else
  error("Invalid Scheduler System", 2)
end
