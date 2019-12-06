local socket=require"blue.bsocket"
local scheduler=require"blue.scheduler"
local http={}
function http.request(url,data,req)
  req=req or {}
  local proto,host,port,page=url:match("^http(s*)://([^/:]*):*([^/:]-)/(.-)$")
  local secure=proto=="s"
  local conn
  conn=assert(socket.connect(host,tonumber(port.."") or (secure and 443 or 80)))
  if secure then
    if not conn.handshake then error("Scheduler system doesn't support TLS",2) end
    assert(conn:handshake())
  end
  local npage="/"..page
  local method="GET"
  if data then method= req[":method"] or "POST" req["content-length"]=data:len() end
  conn:send(method.." "..npage.." HTTP/1.1\r\n")
  req["connection"]="close"
  req["host"]=host
  for k,v in pairs(req) do
    if k:find("^[a-zA-Z]") then
      conn:send(k..": "..v.."\r\n")
    end
  end
  conn:send("\r\n")
  conn:send(data or "")
  local cb
  scheduler.addthread(function()
    scheduler.sleep(0)
    local buf=""
    local function getline()
      while not buf:find("\r\n") do
        local cd,err=conn:receive()
        if cd then
          buf=buf..cd
        else
          local c=buf
          buf=""
          if c:len()==0 then c=nil end
          return c,err
        end
      end
      local d=buf:sub(1,buf:find("\r\n")-1)
      buf=buf:sub(buf:find("\n")+1)
      return d
    end
    local l,err=getline()
    if not l then
      if not cb then return end
      cb(nil,err)
      cb=nil
      return
    end
    local code=l:match("HTTP/1.1 ([0-9]+)")
    local content=""
    local headers={}
    repeat
        local line,err=getline()
        if not line then
          if not cb then return end
          cb(nil,err)
          cb=nil
          return
        end
        local k,v=line:match("^(.-):[ \n\t]*(.-)$")
        if k and v then
          headers[k:lower()]=v
        end
      until line==""
      local content=""
      local len=tonumber(headers["content-length"] or "0")
      if headers["transfer-encoding"]=="chunked" then
        error("TODO: Catch errors")
        repeat
          local c=""
          local l=getline()
          len=tonumber(l,16)
          print("LEN",len,l)
          --headers["transfer-encoding"]=nil
          while c:len()<len do
            c=c..buf:sub(1,1)
            buf=buf:sub(2)
            if buf:len()==0 then
              buf=assert(conn:receive())
            end
          end
          if headers["transfer-encoding"]=="chunked" then
            getline()
            c=string.format("%X",len).."\r\n"..c.."\r\n"
          end
          content=content..c
        until headers["transfer-encoding"]~="chunked" or len==0
      else
        content=buf
        while content:len()<len do
          content=content..conn:receive()
        end
      end
      if not cb then return end
      cb(tonumber(code),content,headers)
      cb=nil
    end)
    scheduler.addthread(function()
      scheduler.sleep(20)
      if not cb then return end
      cb(200,"timeout")
      cb=nil
    end)
    cb=scheduler.getresume()
    local code,msg=scheduler.yield()
    if conn then conn:close() end
    return code,msg
end
return http
