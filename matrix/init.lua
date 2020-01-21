-- Copyright (c) 2020 Christian Georg Kurz [chrikuvellberg@gmail.com]
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

require"blue.util"
local do_request=require"blue.matrix.request"
local scheduler=require"blue.scheduler"
local util=require"blue.util"
local matrix={}
local events=require"blue.matrix.events"
local room_functions=require"blue.matrix.room"
local user_functions=require"blue.matrix.user"
function matrix.connect(host,user,pass)
  local open=true
  local txcnt=0
  local request=do_request(host)
  do --Check for r0.5.0
    local code,data=request.get("/_matrix/client/versions")
    if not data.versions then return nil,data.errcode end
    local good_version
    for _,version in ipairs(data.versions) do
      if version=="r0.5.0" then good_version=true end
    end
    if not good_version then return nil,"Server doesn't support Version r.0.5.0" end
  end

  do --Check for password feature
    if not open then return false end
    local code,data=request.get("/_matrix/client/r0/login")
    if not data.flows then return nil,data.errcode end
    local has_password=true
    for _,flow in ipairs(data.flows) do
      if flow.type=="m.login.password" then has_password=true end
    end
    if not has_password then return nil,"Server doesn't support Password" end
  end

  local home_server
  local device_id
  local user_id

  do--Do Login
    if not open then return false end
    local code,data=request.get("/_matrix/client/r0/login",{type="m.login.password",user=user,password=pass})
    if not data.access_token then return nil,data.errcode end
    request.set_access_token(data.access_token)
    home_server=data.home_server
    device_id=data.device_id
    user_id=data.user_id
  end
  do
    if not open then return false end
    local code,capa=request.get("/_matrix/client/r0/capabilities")
    assert(capa,"Invalid Capabilities Response")
    assert(capa.capabilities,"Invalid Capabilities Response")
  end
  local M={}
  M.__index=M
  local handle=setmetatable({
    on_invite=false,
    on_room_joined=false,
  },M)
  local conn={request=request,M=M,user_id=user_id}
  user_functions(conn)
  local function do_join(room_id)
    if not open then return nil,"closed" end
    local code,join=request.get("/_matrix/client/r0/join/"..util.urlencode(room_id),{})
    if join.room_id then return true end
    return nil,"join error"
  end
  local parse_room_events,create_room_handle
  do
    local room_handles={}
    local metas={}
    function parse_room_events(room_handle,events)
      local meta=assert(metas[room_handle],"Invalid Room Handle")
      for _,event in ipairs(events) do
        meta.push_event(event)
      end
    end
    function create_room_handle(id,state,is_first)
      if room_handles[id] then return room_handles[id] end
      local room_handle={}
      room_handles[id]=room_handle
      local index={id=id}
      local M={__index=index,index=index,handle=handle,conn=conn}
      metas[room_handle]=M
      function M.send_message_event(type,content)
        local tid=txcnt
        txcnt=txcnt+1
        repeat
          if not open then return false end
          local code,msg=conn.request.get("/_matrix/client/r0/rooms/"..util.urlencode(id).."/send/"..type.."/"..tid,content,{[":method"]="PUT"})
          if msg.retry_after_ms then scheduler.sleep(msg.retry_after_ms/1000) end
          if msg.event_id then return true end
        until not msg.retry_after_ms
        return false
      end
      setmetatable(room_handle,M)
      local done={}
      function M.push_event(event)
        if event.event_id then
          if done[event.event_id] then return end
          done[event.event_id]=true
        end
        local type=event.type
        if events[type] then
          scheduler.addthread(function()
            events[type](event,M,room_handle)
          end)
        else
          print("Unhandled Event: ",type)
        end
      end
      room_functions(M,room_handle,handle,conn)
      if state=="invite" then
        function index:join()
          return do_join(id)
        end
      elseif state=="join" then
        if handle.on_room_joined then
          scheduler.addthread(function()
            handle.on_room_joined(room_handle)
          end)
        end
      else
        error("TODO")
      end
      return room_handle
    end
  end
  local function process_joined_room(joined_rooms,is_first)
    for room_name,room in pairs(joined_rooms) do
      --if room.state.events[1] and room.state.events[1] then decode(room.state) os.exit(0) end
      local room_handle=create_room_handle(room_name,"join",is_first)
      parse_room_events(room_handle,room.state.events)
      parse_room_events(room_handle,room.timeline.events)
      if room_handle.on_sync_finished then
        scheduler.addthread(function()
          room_handle.on_sync_finished()
        end)
      end
    end
  end
  local function process_rooms(rooms,is_first)
    if handle.on_invite then
      for id,invite_state in pairs(rooms.invite) do
        local invite_room=create_room_handle(id,"invite")
        parse_room_events(invite_room,invite_state.invite_state.events)
        scheduler.addthread(function()
          handle.on_invite(invite_room)
        end)
      end
    end
    process_joined_room(rooms.join,is_first)
  end
  local since
  local function sync()
    local code,sync=request.get("/_matrix/client/r0/sync?timeout=1500&"..(since and "since="..util.urlencode(since) or ""))
    sync.presence=nil
    sync.account_data=nil
    local is_first=not since
    since=sync.next_batch
    process_rooms(sync.rooms,is_first)
  end
  function M:start()
    scheduler.addthread(function()
      while open do
        sync()
      end
    end)
  end
  function M:close()
    open=false
  end
  return handle
end
return matrix
