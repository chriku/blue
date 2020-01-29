local scheduler=require"blue.scheduler"
return function(socket)
  function socket:receive_timeout(seconds)
    local cb
    scheduler.addthread(function()
      scheduler.sleep(0)
      local a,b=socket:receive()
      if cb then
        local rcb=cb
        cb=nil
        rcb(a,b)
      end
    end)
    scheduler.addthread(function()
      scheduler.sleep(seconds)--TODO: abort earlier
      if cb then
        local rcb=cb
        cb=nil
        rcb(nil,"timeout")
      end
    end)
    cb=scheduler.getresume()
    return scheduler.yield()
  end
  return socket
end
