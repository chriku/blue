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
local ffi = require "ffi"
local scheduler = require "blue.scheduler"
local libssh2 = require "blue.ssh_init"
assert(libssh2.init(0) == 0)
ffi.cdef [[
  int socketpair(int domain, int type, int protocol, int sv[2]);
  ssize_t write(int fd, const void *buf, size_t count);
  ssize_t read(int fd, void *buf, size_t count);
  int close(int fd);
]]
ffi.metatype("struct _LIBSSH2_SESSION", {__index = libssh2})
local ssh = {}
function ssh.connect(host, port, username, socket_provider)
  local skts = ffi.new("int[2]")
  assert(ffi.C.socketpair(1, 2048 + 1, 0, skts) == 0)
  local session = ffi.gc(libssh2.session_init_ex(nil, nil, nil, nil), function(o)
    ffi.C.close(skts[0])
    assert(ffi.C.close(skts[1]) == 0)
    libssh2.session_free(o)
  end)
  session:session_set_blocking(0)
  local my_socket = skts[0]
  -- local rem_socket=assert(socket.connect("localhost",22))
  local rem_socket = assert((socket_provider or require "blue.bsocket").connect(host, port))
  local function exec(func, ...)
    while true do
      local ret = func(...)
      if ret ~= -37 then
        if type(ret) == "number" and ret < 0 then
          local msg = ffi.new("char*[1]")
          local len = ffi.new("int[1]")
          libssh2.session_last_error(session, msg, len, false)
          return nil, (ffi.string(msg[0], len[0]))
        end
        return ret
      end
      local s = ffi.new("char[1024]")
      local len = ffi.C.read(my_socket, s, 1024)
      if len > 0 then
        rem_socket:send(ffi.string(s, len))
      else
        local str = assert(rem_socket:receive())
        assert(ffi.C.write(my_socket, str, str:len()) == str:len())
      end
    end
  end
  local function execp(func, ...)
    return exec(function(...)
      local ptr = func(...)
      local err = session:session_last_errno()
      if ptr == nil then
        return err
      end
      return ptr
    end, ...)
  end
  assert(exec(session.session_handshake, session, skts[1]))
  local uname = username
  assert(exec(session.userauth_publickey_fromfile_ex, session, uname, uname:len(), "/home/christian/.ssh/id_rsa.pub", "/home/christian/.ssh/id_rsa", nil))
  local prov = {}
  function prov:close()
    local ret = {exec(libssh2.session_disconnect_ex, session, 11, "close", "")}
    session = nil
    return unpack(ret)
  end
  function prov.connect(host, port)
    local session = session
    local channel = ffi.gc(assert(execp(libssh2.channel_direct_tcpip_ex, session, host, port, "127.0.0.1", 22)), libssh2.channel_free)
    local skt = {}
    function skt:send(str)
      return exec(libssh2.channel_write_ex, channel, 0, ffi.new("char[?]", str:len(), str), str:len())
    end
    local str = ffi.new("char[1024]")
    function skt:receive()
      if exec(libssh2.channel_eof, channel) ~= 0 then
        return nil, "closed"
      end
      local len, err = exec(libssh2.channel_read_ex, channel, 0, str, 1024)
      if not len then
        return nil, err
      end
      local data = ffi.string(str, len)
      return data
    end
    function skt:close()
      local ret = {exec(libssh2.channel_close, channel)}
      channel = nil
      return unpack(ret)
    end
    return require "blue.socket_wrapper"(skt)
  end
  return prov
end
return ssh
