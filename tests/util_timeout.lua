package.path = package.path .. ";../?.lua"
local copas = require "copas"
local util = require "blue.util"
local scheduler = require "blue.scheduler"
copas.addthread(function()
  assert(not pcall(function()
    util.call_timeout_error(scheduler.sleep, 1, 2)
  end))
  assert(pcall(function()
    util.call_timeout_error(scheduler.sleep, 1, 0.5)
  end))
end)
copas.loop()
