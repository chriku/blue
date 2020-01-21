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

local json=require"blue.matrix.json"
return function(base_host)
  local do_request={}
  local header={}
  function do_request.get(rest,info,put)
    --print("REQ1",rest)
    local http_client=require"blue.http_client"
    local data
    local head={}
    if info then data=json.encode(info) head["Content-Type"]="application/json" if put then head[":method"]="PUT" end end
    for k,v in pairs(header) do head[k]=v end
    local code,ret=http_client.request(base_host..rest,data,head)
    local ret2=json.decode(ret)
    if not ret2 then print(base_host..rest) decode(ret) decode(data) decode(head) os.exit(0) end
    --print("REQ2",rest)
    return code,ret2 or {}
  end
  function do_request.set_access_token(token)
    header["Authorization"]="Bearer "..token
  end
  return do_request
end
