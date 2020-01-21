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

--- Utils
local scheduler=require"blue.scheduler"
if false then
  jit.off()
  local last=os.time()
  scheduler.addthread(function()
    while true do
      scheduler.sleep(0.1)
      last=os.time()
    end
  end)
  debug.sethook(function(a,b,c)
    if last-os.time()>2 then
      print(debug.traceback())
    end
    --print(coroutine.running())
  end,"",1)
end
local util={}
local has_ffi,ffi = pcall(require,"ffi")
if has_ffi then
ffi.cdef[[

typedef long int __time_t;
typedef long int __suseconds_t;
struct timezone
          {
            int tz_minuteswest;
            int tz_dsttime;
};
typedef struct timezone *__timezone_ptr_t;
struct timeval
{
  __time_t tv_sec;
  __suseconds_t tv_usec;
};

int gettimeofday (struct timeval *__tv,
__timezone_ptr_t __tz);
]]
--- Monotonic time
-- @treturn number time in secods
function util.time()
  local tv = ffi.new("struct timeval")
  local rc = ffi.C.gettimeofday (tv, nil)
  local returnValue64_c = (tonumber(tv.tv_sec) * 1000) + tonumber(tv.tv_usec)/1000
  returnValue64_c=returnValue64_c/1000.0
  return returnValue64_c
end
end
--- Create a killable thread
function util.kill_task()
  local kt={}
  local cb
  --- Kills killable thread
  -- Returns from anywhere within a killable thread, even in subfunctions
  -- @param ... are returned from kt:run()
  function kt:ret(...)--quits task immediately and returns ...
    if cb then
      local ocb=cb
      cb=nil
      ocb(...)
    end
    scheduler.yield()
  end
  --- Runs a killable thread
  -- @tparam function f Function to be executed
  -- @return[1] return values after function has finished executing
  -- @return[2] arguments of kt:ret()
  function kt:run(f)--runs task
    scheduler.addthread(function()
      scheduler.sleep(0)
      local ret={pcall(f)}
      if not ret[1] then print("ERROR: "..ret[2]) end
      table.remove(ret,1)
      local ocb=cb
      cb=nil
      ocb(unpack(ret))
    end)
    cb=scheduler.getresume()
    return scheduler.yield()
  end
  return kt
end
local function rdecode(data,int,hd)
  if type(data)~="table" then
    print(type(data),":",data)
    --print(debug.traceback())
  else
    for k,v in pairs(data) do
      for i=1,int do io.write"  " end
      if type(v)=="table" and int<10 and not hd[v] then
        hd[v]=true
        print(k)
        rdecode(v,int+1,hd)
      else
        print(k,v)
      end
    end
  end
end
--- Print data to stdout
function decode(data)
  print("===== BEGIN =====")
  rdecode(data,0,{})
  print("===== END =====")
end
--debug.setmetatable(_G,{__index=function(self,k) error("NOPEI: "..tostring(k),2) end,__newindex=function(self,k) print("NOPEN: "..tostring(k),2) error("NOPEN: "..tostring(k),2) end})
do
  local todel=setmetatable({},{__mode="k"})
  local running=false
  local function make_run()
    if not running then
      scheduler.addthread(function()
        running=true
        while next(todel) do
          local diff=nil
          local cur=util.time()
          for t,v in pairs(todel) do
            for k,time in pairs(v) do
              if cur>=time then
                t[k]=nil
                todel[t][k]=nil
              else
                local ad=time-cur
                ad=1
                diff=math.min(diff or ad,ad)
              end
            end
          end
          if not diff then break end
          scheduler.sleep(diff)
        end
        running=false
      end)
    end
  end
  --- Deletes an item from a table
  -- @tparam table t Table to index
  -- @param f Field
  -- @tparam number time Time to wait
  function util.delete_later(t,f,time)
    if not todel[t] then
      todel[t]={}
    end
    todel[t][f]=util.time()+time
    make_run()
  end
end
--- Wait for cb or timeout
--
-- Yields coroutine until t[k] is calles or timeout
-- @return[1] arguments from t[k]
-- @treturn[2] nil error
-- @tparam number timeout timeout in seconds
-- @tparam table t
-- @param k
function util.wait_cb(timeout,t,k)
  local ret
  local cb=scheduler.getresume()
  scheduler.addthread(function()
    scheduler.sleep(math.max(timeout,0))
    local ocb=cb
    cb=nil
    if ocb then ocb() end
  end)
  t[k]=function(...)
    local ocb=cb
    cb=nil
    if ocb then ocb(...) end
  end
  return scheduler.yield()
end
--- GC Table
function util.gc_table(gcf)
  local map1=setmetatable({},{__mode="v"})
  local map2={}
  local ret={}
  local running=false
  local function er()
    if not running then
      scheduler.addthread(function()
        running=true
        while next(map2) do
          scheduler.sleep(1)
          for k,v in pairs(map2) do
            if not map1[k] then
              scheduler.addthread(gcf,map2[k])
              map2[k]=nil
            end
          end
        end
        running=false
      end)
    end
  end
  function ret.add(k,v)
    local rk={}
    map2[rk]=v
    map1[rk]=k
    er()
  end
  return ret
end
--- Limit function time
function util.time_task(timeout,f,args)
  local cb=scheduler.getresume()
  scheduler.addthread(function()
    scheduler.sleep(math.max(0,timeout))
    local ocb=cb cb=nil if ocb then ocb() end
  end)
  scheduler.addthread(function()
    scheduler.sleep(0)
    local ret={pcall(f,unpack(args))}
    local ocb=cb cb=nil if ocb then ocb(ret) end
  end)
  local ret=scheduler.yield()
  if ret then
    local ok=table.remove(ret,1)
    return ok,ret
  end
  return nil
end
rawset(_G,"console",{log=function(...) print("LOG",...) end,warn=function(...) print("WARN",...) end})
--- Create Mutex
function util.mutex()
  local mutex={}
  local waiting
  --- lock mutex
  function mutex:lock()
    if waiting then
      table.insert(waiting,scheduler.getresume())
      scheduler.yield()
    else
      waiting={}
    end
  end
  --- unlock mutex
  function mutex:unlock()
    if not waiting then error("Double unlock",2) end
    local cur=table.remove(waiting,1)
    if cur then
      scheduler.addthread(cur)
    else
      waiting=nil
    end
  end
  return mutex
end
--- Create pair of @{socket} pipe
-- @treturn socket first end
-- @treturn socket second end
function util.pair()
  local s1={}
  local s2={}
  local function conn(a,b)
    local cbs={}
    local buf={}
    function a:receive()
      while #buf==0 do
        table.insert(cbs,scheduler.getresume())
        scheduler.yield()
      end
      local data=table.concat(buf)
      buf={}
      return data
    end
    function b:send(d)
      table.insert(buf,d)
      while #cbs>0 do table.remove(cbs,1)() end
      return true
    end
  end
  conn(s1,s2)
  conn(s2,s1)
  return s1,s2
end
function util.urlencode(str)
  str=str:gsub(".",function(a)return "%"..string.format("%02X",string.byte(a)) end)
  return str
end
return util
