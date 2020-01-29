local scheduler = require "blue.scheduler"
local http = {}
function http.request(url, data, req, socket_provider)
  req = req or {}
  local socket = socket_provider or require "blue.bsocket"
  local proto, host, port, page = url:match("^http(s*)://([^/:]*):*([^/:]*)(.-)$")
  if page == "" then
    page = "/"
  end
  if not page then
    error("Invalid Page", 2)
  end
  assert(page:find("^/"))
  local secure = proto == "s"
  local conn
  if secure then
    socket = require"blue.ssl".create(socket_provider)
  end
  conn = assert(socket.connect(host, tonumber(port .. "") or (secure and 443 or 80)))
  local npage = page
  local method = "GET"
  if data then
    method = req[":method"] or "POST"
    req["content-length"] = data:len()
  end
  conn:send(method .. " " .. npage .. " HTTP/1.1\r\n")
  req["connection"] = "close"
  req["connection"] = "keep-alive"
  req["host"] = host
  for k, v in pairs(req) do
    if k:find("^[a-zA-Z]") then
      conn:send(k .. ": " .. v .. "\r\n")
    end
  end
  conn:send("\r\n")
  conn:send(data or "")
  local buf = ""
  local function getline()
    while not buf:find("\r\n") do
      local cd, err = conn:receive_timeout(60)
      if cd then
        buf = buf .. cd
      else
        local c = buf
        buf = ""
        if c:len() == 0 then
          c = nil
        end
        return c, err
      end
    end
    local d = buf:sub(1, buf:find("\r\n") - 1)
    buf = buf:sub(buf:find("\n") + 1)
    return d
  end
  local l, err = getline()
  if not l then
    if conn then
      conn:close()
    end
    return nil, err
  end
  local code = l:match("HTTP/1.1 ([0-9]+)")
  local content = ""
  local headers = {}
  repeat
    local line, err = getline()
    if not line then
      if conn then
        conn:close()
      end
      return nil, err
    end
    local k, v = line:match("^(.-):[ \n\t]*(.-)$")
    if k and v then
      headers[k:lower()] = v
    end
  until line == ""
  local content = ""
  local len = tonumber(headers["content-length"] or "0")
  if headers["transfer-encoding"] == "chunked" then
    -- error("TODO: Catch errors")
    repeat
      local c = ""
      local l = getline()
      len = tonumber(l, 16)
      print("LEN", len, l)
      -- headers["transfer-encoding"]=nil
      while c:len() < len do
        c = c .. buf:sub(1, 1)
        buf = buf:sub(2)
        if buf:len() == 0 then
          buf = assert(conn:receive())
        end
      end
      if headers["transfer-encoding"] == "chunked" then
        getline()
        c = string.format("%X", len) .. "\r\n" .. c .. "\r\n"
      end
      content = content .. c
    until headers["transfer-encoding"] ~= "chunked" or len == 0
  else
    content = buf
    while content:len() < len do
      -- print(content)
      content = content .. assert(conn:receive())
    end
  end
  if conn then
    conn:close()
  end
  return tonumber(code), content, headers
end
return http
