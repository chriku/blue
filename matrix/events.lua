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

local events={}
events["m.room.name"]=function(event,meta,handle)
  meta.index.name=event.content.name
end
events["m.room.join_rules"]=function(event,meta,handle)end
events["m.room.member"]=function(event,meta,handle)
  meta.conn.user.create_user(event)
end
events["m.room.power_levels"]=function(event,meta,handle)end
events["m.room.history_visibility"]=function(event,meta,handle)end
events["m.room.guest_access"]=function(event,meta,handle)end
events["m.room.message"]=function(event,meta,handle)
  local sender=meta.conn.user.find_user(event.sender)
  local time
  if event.content.msgtype=="m.text" and handle.on_text_message then
    handle.on_text_message(event.content.body,sender,time)
  end
  if handle.on_message then
    handle.on_message(event.content,sender,time)
  end
end
events["m.room.create"]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
events[""]=function(event,meta,handle)end
return events
