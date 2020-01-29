package.path = package.path .. ";../?.lua"
local copas = require "copas"
local http_client = require "blue.http_client"
local socket = require "blue.bsocket"
copas.addthread(function()
  assert(not pcall(function()
    local conn = socket.connect("google.de", 80)
    conn:send("GET / HTTP/1.1\r\nHost: google.de\r\nConnection: keep-alive\r\n\r\n")
    for i = 1, 1000 do
      assert(conn:receive_timeout(1))
    end
  end))
  print("REQUEST", http_client.request("https://google.de/"))
end)
copas.loop()
