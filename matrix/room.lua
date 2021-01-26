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
return function(meta, room_handle, handle, conn)
  function meta.index:send_text_message(msg)
    meta.send_message_event("m.room.message", {msgtype = "m.text", body = msg})
  end
  function meta.index:send_message(msg)
    meta.send_message_event("m.room.message", msg)
  end
  function meta.index:send_state_event(type, key, content)
    meta.send_state_event(type, key, content)
  end
end
