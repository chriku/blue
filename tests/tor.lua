package.path = package.path .. ";../?.lua"
-- local copas = require "copas"
local lgi = require "lgi"
local Gtk = lgi.require("Gtk", "3.0")
lgi.require("GLib", "2.0")
local GLib = lgi.GLib
local scheduler = require "blue.scheduler"
scheduler.addthread(function()
  local tor = require "blue.tor"
  local conn = tor.create {
    first_relay = {ip = "128.31.0.34", port = 9101} -- moria1
    -- first_relay={ip="164.132.226.30",port=22}
  }
  print("CONN OPEN", conn)
end)
-- copas.loop()
GLib.MainLoop.run(GLib.MainLoop.new(GLib.MainContext.default()))
