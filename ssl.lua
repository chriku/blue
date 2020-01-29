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
ffi.cdef [[
typedef struct SSL_METHOD {} SSL_METHOD;
typedef struct SSL_CTX {} SSL_CTX;
typedef struct BIO {} BIO;
typedef struct SSL {} SSL;
typedef struct X509_STORE_CTX {} X509_STORE_CTX;

typedef int (*SSL_verify_cb)(int preverify_ok, X509_STORE_CTX *x509_ctx);
typedef long (*BIO_callback_fn_ex)(BIO *b, int oper, const char *argp,size_t len, int argi,long argl, int ret, size_t *processed);

void SSL_free(SSL *ssl);
int    BIO_free(BIO *a);
int BIO_write(BIO *b, const void *data, int dlen);
void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio);
void SSL_set_connect_state(SSL *s);
int SSL_get_error(const SSL *s, int ret_code);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
int OPENSSL_init_ssl(uint64_t opts, const void *settings);
const SSL_METHOD *TLS_method(void);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb callback);
unsigned long SSL_CTX_set_options(SSL_CTX *ctx, unsigned long op);
BIO *BIO_new_ssl_connect(SSL_CTX *ctx);
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
int SSL_set_cipher_list(SSL *s, const char *str);
int BIO_puts(BIO *bp, const char *buf);
int BIO_read(BIO *b, void *data, int dlen);
int BIO_test_flags(const BIO *b, int flags);
void BIO_set_callback_ex(BIO *b, BIO_callback_fn_ex callback);
int BIO_new_bio_pair(BIO **bio1, size_t writebuf1,BIO **bio2, size_t writebuf2);
SSL *SSL_new(SSL_CTX *ctx);
int SSL_do_handshake(SSL *ssl);
void SSL_CTX_free(SSL_CTX *ctx);
int SSL_write(SSL *ssl, const void *buf, int num);
int SSL_read(SSL *ssl, void *buf, int num);
char *SSL_state_string_long(const SSL *ssl);
int SSL_has_pending(const SSL *s);
int    BIO_up_ref(BIO *a);
]]
local lib = ffi.load("/usr/lib/x86_64-linux-gnu/libssl.so.1.1")
lib.OPENSSL_init_ssl(0, nil)
lib.OPENSSL_init_ssl(0x00200000 + 0x00000002, nil)

--[[print(len,lib.BIO_test_flags(o,8))
print("RTR",lib.BIO_test_flags(web,8))
lib.BIO_puts(web,"GET / HTTP/1.0\r\n\r\n")
for i=1,1000 do
end
os.exit(0)]]

local mutex = require"blue.util".mutex
local ssl = {}
function ssl.create(socket_provider)
  local prov = {}
  function prov.connect(host, port)
    local rem_socket = assert((socket_provider or require "blue.bsocket").connect(host, port))
    local open = true

    local send_mutex = mutex()

    local web, o = ffi.new("BIO*[1]"), ffi.new("BIO*[1]")
    local buffer_size = 16384
    lib.BIO_new_bio_pair(web, buffer_size, o, buffer_size)
    web, o = web[0], ffi.gc(o[0], lib.BIO_free)
    if web == nil then
      error("TODO")
    end
    local waiting_sockets = {}
    local rec_buf = ""
    local function do_close()
      open = false
      rem_socket:close()
      local w = {unpack(waiting_sockets)}
      waiting_sockets = {}
      for _, w in ipairs(w) do
        w()
      end
    end
    local function flush()
      if rec_buf:len() > 0 then
        local allowed = tonumber(lib.BIO_ctrl(o, 140, 0, nil)) - 1
        if not (allowed > 0) then
          allowed = 0
        end
        local data = rec_buf:sub(1, allowed)
        rec_buf = rec_buf:sub(allowed + 1)
        lib.BIO_write(o, data, data:len())
        local w = {unpack(waiting_sockets)}
        waiting_sockets = {}
        for _, w in ipairs(w) do
          w()
        end
        if allowed > 0 then
          return true
        end
      end
    end
    scheduler.addthread(function()
      while true do
        local data = rem_socket:receive()
        if data then
          rec_buf = rec_buf .. data
        else
          do_close()
          lib.BIO_ctrl(o, 142, 0, nil)
          break
        end
        flush()
      end
    end)
    local function sync(wait)
      if flush() then
        return
      end
      if not open then
        return
      end
      local have = false
      repeat
        local buf = ffi.new("char[1024]")
        local len = lib.BIO_read(o, buf, 1024)
        if len > 0 then
          have = true
          local d = assert(ffi.string(buf, len))
          if not rem_socket:send(d) then
            do_close()
            return
          end
        end
        if not open then
          break
        end
      until not (len > 0)
      if wait and not have then
        table.insert(waiting_sockets, scheduler.getresume())
        scheduler.yield()
      end
    end

    local method = lib.TLS_method()
    if method == nil then
      error("TODO")
    end
    local ctx = ffi.gc(lib.SSL_CTX_new(method), lib.SSL_CTX_free)
    if ctx == nil then
      error("TODO")
    end
    lib.SSL_CTX_set_verify(ctx, 0x0, nil)
    lib.SSL_CTX_set_options(ctx, 0x02000000 + 0x00020000)
    local ssl = ffi.gc(lib.SSL_new(ctx), lib.SSL_free)
    lib.SSL_set_connect_state(ssl)
    lib.SSL_set_bio(ssl, web, web)
    lib.SSL_set_cipher_list(ssl, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")

    local conn = {}

    repeat
      local stat = lib.SSL_do_handshake(ssl)
      -- print("HANDSHAKE",stat,lib.SSL_get_error(ssl,stat))
      if stat ~= 1 and lib.SSL_get_error(ssl, stat) == 2 or lib.SSL_get_error(ssl, stat) == 3 then
        sync(true)
      end
    until stat == 1

    function conn:send(data)
      assert(data:len() < buffer_size)
      lib.SSL_write(ssl, data, data:len())
      sync(false)
      if open then
        return data
      else
        return nil, "closed"
      end
    end
    function conn:receive(data)
      local first = true
      local rblc = 0
      while true do
        sync(not first)
        first = false
        local ibuf_len = 8192
        local buf = ffi.new("char[?]", ibuf_len)
        local len = lib.SSL_read(ssl, buf, ibuf_len)
        if len > 0 then
          rblc = 0
          return ffi.string(buf, len)
        elseif rec_buf:len() > 0 then
          rblc = rblc + 1
          if rblc > 100 then
            error("Buffer not shrinking", 2)
          end
          -- print("RBL",rec_buf:len())
        else
          rblc = 0
          -- print(open,len,ffi.string(lib.SSL_state_string_long(ssl)),lib.SSL_has_pending(ssl),rec_buf:len(),"LAST")
          if not open then
            break
          end
        end
      end
      print("RECVEE")
      return nil, "closed"
    end
    function conn:close()
      do_close()
      return
    end

    return require "blue.socket_wrapper"(conn)
  end
  return prov
end
return ssl
