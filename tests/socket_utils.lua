package.path = package.path .. ";../?.lua"
local copas=require"copas"
local socket=require"bsocket"
copas.addthread(function()
  local conn=socket.connect("google.de",80)
  conn:send("GET / HTTP/1.1\r\nHost: google.de\r\nConnection: keep-alive\r\n\r\n")
  for i=1,1000 do
    print(assert(conn:receive_timeout(1)))
  end
end)
copas.loop()
